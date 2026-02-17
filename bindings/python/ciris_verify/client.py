"""CIRISVerify client - Python FFI wrapper for the verification binary.

This module provides a high-level Python interface to the CIRISVerify
Rust binary via C FFI. It handles JSON encoding/decoding and type conversion.
"""

import os
import json
import ctypes
import asyncio
import hashlib
import platform
import socket
from pathlib import Path
from typing import Optional, Set
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from .types import (
    LicenseStatus,
    LicenseTier,
    LicenseDetails,
    MandatoryDisclosure,
    DisclosureSeverity,
    LicenseStatusResponse,
    CapabilityCheckResult,
    HardwareType,
    ValidationStatus,
    SourceDetails,
    AttestationData,
)
from .exceptions import (
    BinaryNotFoundError,
    BinaryTamperedError,
    VerificationFailedError,
    TimeoutError as CIRISTimeoutError,
    CommunicationError,
)


# Default paths for the CIRISVerify binary by platform
DEFAULT_BINARY_PATHS = {
    "Linux": [
        "/usr/lib/ciris/libciris_verify.so",
        "/usr/local/lib/ciris/libciris_verify.so",
        "./target/release/libciris_verify_ffi.so",
    ],
    "Darwin": [
        "/usr/local/lib/ciris/libciris_verify.dylib",
        "./target/release/libciris_verify_ffi.dylib",
    ],
    "Windows": [
        "C:\\Program Files\\CIRIS\\ciris_verify.dll",
        ".\\target\\release\\ciris_verify_ffi.dll",
    ],
}

# Map Rust LicenseStatus enum variants (serde string serialization) to Python IntEnum
_RUST_STATUS_MAP = {
    "LicensedProfessional": LicenseStatus.LICENSED_PROFESSIONAL,
    "LicensedCommunityPlus": LicenseStatus.LICENSED_PROFESSIONAL_GRACE,
    "UnlicensedCommunity": LicenseStatus.UNLICENSED_COMMUNITY,
    "UnlicensedUnverified": LicenseStatus.RESTRICTED_VERIFICATION_FAILED,
    "ErrorBinaryTampered": LicenseStatus.LOCKDOWN_INTEGRITY_FAILURE,
    "ErrorSourcesDisagree": LicenseStatus.LOCKDOWN_ATTACK_DETECTED,
    "ErrorVerificationFailed": LicenseStatus.ERROR_VERIFICATION_FAILED,
    "ErrorLicenseRevoked": LicenseStatus.ERROR_REVOKED,
    "ErrorLicenseExpired": LicenseStatus.ERROR_EXPIRED,
}

# Map Rust DisclosureSeverity variants to Python enum
_RUST_SEVERITY_MAP = {
    "Info": DisclosureSeverity.INFO,
    "Warning": DisclosureSeverity.WARNING,
    "Critical": DisclosureSeverity.CRITICAL,
}

# Map Rust HardwareType to Python enum (from PlatformAttestation variant)
_RUST_HARDWARE_MAP = {
    "AndroidKeystore": HardwareType.ANDROID_KEYSTORE,
    "AndroidStrongbox": HardwareType.ANDROID_STRONGBOX,
    "IosSecureEnclave": HardwareType.IOS_SECURE_ENCLAVE,
    "Tpm20": HardwareType.TPM_DISCRETE,
    "IntelSgx": HardwareType.INTEL_SGX,
    "SoftwareOnly": HardwareType.SOFTWARE_ONLY,
    "Software": HardwareType.SOFTWARE_ONLY,
}

# Map Rust ValidationStatus variants to Python enum
_RUST_VALIDATION_MAP = {
    "AllSourcesAgree": ValidationStatus.ALL_SOURCES_AGREE,
    "PartialAgreement": ValidationStatus.PARTIAL_AGREEMENT,
    "SourcesDisagree": ValidationStatus.SOURCES_DISAGREE,
    "NoSourcesReachable": ValidationStatus.NO_SOURCES_REACHABLE,
    "ValidationError": ValidationStatus.VALIDATION_ERROR,
}


class CIRISVerify:
    """High-level client for CIRISVerify license verification.

    This class wraps the CIRISVerify Rust binary via C FFI, providing
    a Pythonic interface for license verification operations.

    Usage:
        verifier = CIRISVerify()
        status = await verifier.get_license_status(challenge_nonce=os.urandom(32))

        if status.allows_licensed_operation():
            # Professional capabilities available
            pass

    Thread Safety:
        The client is thread-safe. Multiple threads can call methods
        concurrently. Async methods use a thread pool for FFI calls.
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        deployment_id: Optional[str] = None,
        skip_integrity_check: bool = False,
        timeout_seconds: float = 10.0,
    ):
        """Initialize CIRISVerify client.

        Args:
            binary_path: Path to CIRISVerify binary. If None, searches
                         default system paths.
            deployment_id: Unique deployment identifier. If None, generated
                          from hostname.
            skip_integrity_check: Skip binary integrity verification.
                                  WARNING: Only for development/testing.
            timeout_seconds: Default timeout for verification operations.

        Raises:
            BinaryNotFoundError: If binary cannot be found.
            BinaryTamperedError: If binary integrity check fails.
        """
        self._timeout = timeout_seconds
        self._deployment_id = deployment_id or self._generate_deployment_id()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ciris_verify")
        self._lib: Optional[ctypes.CDLL] = None
        self._handle = None

        # Find and load binary
        self._binary_path = self._find_binary(binary_path)

        if not skip_integrity_check:
            self._verify_binary_integrity()

        self._load_library()

    @staticmethod
    def _generate_deployment_id() -> str:
        """Generate a deployment ID from the hostname."""
        hostname = socket.gethostname()
        return f"deploy-{hashlib.sha256(hostname.encode()).hexdigest()[:16]}"

    def _find_binary(self, explicit_path: Optional[str]) -> Path:
        """Find CIRISVerify binary."""
        if explicit_path:
            path = Path(explicit_path)
            if path.exists():
                return path
            raise BinaryNotFoundError(explicit_path)

        # Search default paths
        system = platform.system()
        paths = DEFAULT_BINARY_PATHS.get(system, [])

        for path_str in paths:
            path = Path(path_str)
            if path.exists():
                return path

        # Also check relative to this module
        module_dir = Path(__file__).parent
        for suffix in [".so", ".dylib", ".dll"]:
            candidate = module_dir / f"libciris_verify_ffi{suffix}"
            if candidate.exists():
                return candidate

        raise BinaryNotFoundError(f"Searched: {paths}")

    def _verify_binary_integrity(self) -> None:
        """Verify binary hasn't been tampered with."""
        try:
            with open(self._binary_path, "rb") as f:
                magic = f.read(4)
                if not magic:
                    raise BinaryTamperedError("Empty binary file")

                valid_magic = [
                    b"\x7fELF",           # ELF
                    b"\xfe\xed\xfa\xce",  # Mach-O 32
                    b"\xfe\xed\xfa\xcf",  # Mach-O 64
                    b"\xcf\xfa\xed\xfe",  # Mach-O 64 LE
                    b"\xca\xfe\xba\xbe",  # Mach-O Universal
                    b"MZ\x90\x00",        # PE
                    b"MZ\x00\x00",        # PE variant
                ]

                if not any(magic.startswith(m[:len(magic)]) for m in valid_magic):
                    raise BinaryTamperedError(f"Invalid binary magic: {magic.hex()}")

        except (OSError, IOError) as e:
            raise BinaryTamperedError(f"Cannot read binary: {e}")

    def _load_library(self) -> None:
        """Load the shared library and set up FFI bindings."""
        try:
            self._lib = ctypes.CDLL(str(self._binary_path))
        except OSError as e:
            raise CommunicationError(f"Failed to load library: {e}", e)

        # ciris_verify_init() -> *mut CirisVerifyHandle
        self._lib.ciris_verify_init.argtypes = []
        self._lib.ciris_verify_init.restype = ctypes.c_void_p

        # ciris_verify_get_status(handle, request_data, request_len, response_data, response_len) -> i32
        self._lib.ciris_verify_get_status.argtypes = [
            ctypes.c_void_p,                    # handle
            ctypes.c_char_p,                    # request_data (JSON bytes)
            ctypes.c_size_t,                    # request_len
            ctypes.POINTER(ctypes.c_char_p),    # response_data (out)
            ctypes.POINTER(ctypes.c_size_t),    # response_len (out)
        ]
        self._lib.ciris_verify_get_status.restype = ctypes.c_int

        # ciris_verify_check_capability(handle, capability, action, required_tier, allowed) -> i32
        self._lib.ciris_verify_check_capability.argtypes = [
            ctypes.c_void_p,                    # handle
            ctypes.c_char_p,                    # capability
            ctypes.c_char_p,                    # action
            ctypes.c_int,                       # required_tier
            ctypes.POINTER(ctypes.c_int),       # allowed (out)
        ]
        self._lib.ciris_verify_check_capability.restype = ctypes.c_int

        # ciris_verify_free(data)
        self._lib.ciris_verify_free.argtypes = [ctypes.c_char_p]
        self._lib.ciris_verify_free.restype = None

        # ciris_verify_destroy(handle)
        self._lib.ciris_verify_destroy.argtypes = [ctypes.c_void_p]
        self._lib.ciris_verify_destroy.restype = None

        # Initialize handle
        self._handle = self._lib.ciris_verify_init()
        if not self._handle:
            raise CommunicationError("Failed to initialize CIRISVerify handle")

    def __del__(self):
        """Clean up resources."""
        if self._handle and self._lib:
            try:
                self._lib.ciris_verify_destroy(self._handle)
            except Exception:
                pass
        if self._executor:
            self._executor.shutdown(wait=False)

    def _sync_get_license_status(
        self,
        challenge_nonce: bytes,
        device_fingerprint: Optional[bytes] = None,
    ) -> LicenseStatusResponse:
        """Synchronous license status check (internal).

        Sends a JSON-encoded LicenseStatusRequest to the Rust FFI and
        parses the JSON-encoded LicenseStatusResponse.
        """
        if len(challenge_nonce) < 32:
            raise ValueError("challenge_nonce must be at least 32 bytes")

        # Build JSON request matching Rust LicenseStatusRequest
        request_obj = {
            "deployment_id": self._deployment_id,
            "challenge_nonce": list(challenge_nonce),
            "force_refresh": False,
        }
        request_bytes = json.dumps(request_obj).encode("utf-8")

        # Call FFI
        response_data = ctypes.c_char_p()
        response_len = ctypes.c_size_t()

        result = self._lib.ciris_verify_get_status(
            self._handle,
            request_bytes,
            len(request_bytes),
            ctypes.byref(response_data),
            ctypes.byref(response_len),
        )

        if result != 0:
            raise VerificationFailedError(result, f"FFI call failed with code {result}")

        try:
            response_bytes = ctypes.string_at(response_data, response_len.value)
            return self._parse_response(response_bytes)
        finally:
            if response_data:
                self._lib.ciris_verify_free(response_data)

    def _parse_response(self, data: bytes) -> LicenseStatusResponse:
        """Parse JSON response from Rust FFI into LicenseStatusResponse."""
        try:
            resp = json.loads(data)
        except json.JSONDecodeError as e:
            raise CommunicationError(f"Invalid JSON response: {e}")

        # Map Rust status string to Python IntEnum
        rust_status = resp.get("status", "ErrorVerificationFailed")
        status = _RUST_STATUS_MAP.get(rust_status, LicenseStatus.ERROR_VERIFICATION_FAILED)

        # Parse mandatory_disclosure
        md = resp.get("mandatory_disclosure", {})
        severity_str = md.get("severity", "Warning")
        severity = _RUST_SEVERITY_MAP.get(severity_str, DisclosureSeverity.WARNING)
        disclosure = MandatoryDisclosure(
            text=md.get("text", self._default_disclosure(status)),
            severity=severity,
            locale=md.get("locale", "en"),
        )

        # Parse hardware type from attestation.platform
        attestation_data = resp.get("attestation", {})
        platform_info = attestation_data.get("platform", {})
        hardware_type = self._parse_hardware_type(platform_info)

        # Parse validation results
        validation = resp.get("validation", {})
        overall_str = validation.get("overall", "ValidationError")
        dns_us = validation.get("dns_us", {})
        dns_eu = validation.get("dns_eu", {})
        https_src = validation.get("https", {})

        source_details = SourceDetails(
            dns_us_reachable=dns_us.get("reachable", False),
            dns_eu_reachable=dns_eu.get("reachable", False),
            https_reachable=https_src.get("reachable", False),
            validation_status=_RUST_VALIDATION_MAP.get(
                overall_str, ValidationStatus.VALIDATION_ERROR
            ),
            sources_agreeing=sum([
                dns_us.get("valid", False),
                dns_eu.get("valid", False),
                https_src.get("valid", False),
            ]),
        )

        # Parse license details if present
        license_details = None
        lic = resp.get("license")
        if lic:
            license_details = self._parse_license_details(lic)

        # Parse metadata for cache info
        metadata = resp.get("metadata", {})

        return LicenseStatusResponse(
            status=status,
            license=license_details,
            mandatory_disclosure=disclosure,
            hardware_type=hardware_type,
            source_details=source_details,
            cached=False,
            verification_timestamp=datetime.now(timezone.utc),
        )

    def _parse_hardware_type(self, platform_info: dict) -> HardwareType:
        """Parse hardware type from Rust PlatformAttestation."""
        if not platform_info:
            return HardwareType.SOFTWARE_ONLY

        # PlatformAttestation is a tagged enum in Rust serde
        # It serializes as {"Software": {...}} or {"Android": {...}} etc.
        for key in platform_info:
            mapped = _RUST_HARDWARE_MAP.get(key)
            if mapped:
                return mapped

        return HardwareType.SOFTWARE_ONLY

    def _parse_license_details(self, lic: dict) -> Optional[LicenseDetails]:
        """Parse license details from Rust JSON."""
        try:
            return LicenseDetails(
                license_id=lic.get("license_id", "unknown"),
                tier=LicenseTier(lic.get("max_autonomy_tier", 0)),
                capabilities=set(lic.get("capabilities", [])),
                prohibited_capabilities=set(lic.get("capabilities_denied", [])),
                issued_at=datetime.fromtimestamp(lic.get("not_before", 0), tz=timezone.utc),
                expires_at=datetime.fromtimestamp(lic.get("expires_at", 0), tz=timezone.utc),
                issuer=lic.get("issuer", "unknown"),
                holder_name=lic.get("holder_name"),
                holder_organization=lic.get("organization_name"),
            )
        except Exception:
            return None

    def _default_disclosure(self, status: LicenseStatus) -> str:
        """Generate default disclosure text based on status."""
        if status.allows_licensed_operation():
            return "This agent is professionally licensed and verified."
        elif status.is_community_mode():
            return (
                "NOTICE: This is an unlicensed community agent. "
                "Professional capabilities (medical, legal, financial advice) "
                "are NOT available. Outputs are for informational purposes only."
            )
        elif status.requires_restricted():
            return (
                "WARNING: License verification encountered issues. "
                "Operating in restricted mode with limited capabilities."
            )
        else:
            return (
                "CRITICAL: License verification failed. "
                "Agent capabilities are severely restricted."
            )

    async def get_license_status(
        self,
        challenge_nonce: bytes,
        device_fingerprint: Optional[bytes] = None,
        timeout: Optional[float] = None,
    ) -> LicenseStatusResponse:
        """Get current license status with cryptographic attestation.

        Args:
            challenge_nonce: Random 32+ byte nonce to prevent replay attacks.
            device_fingerprint: Optional device identifier for binding.
            timeout: Operation timeout in seconds.

        Returns:
            LicenseStatusResponse with complete verification results.

        Raises:
            ValueError: If challenge_nonce is too short.
            TimeoutError: If operation times out.
            VerificationFailedError: If verification fails.
        """
        timeout = timeout or self._timeout

        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    self._executor,
                    self._sync_get_license_status,
                    challenge_nonce,
                    device_fingerprint,
                ),
                timeout=timeout,
            )
            return result
        except asyncio.TimeoutError:
            raise CIRISTimeoutError("get_license_status", timeout)

    async def check_capability(
        self,
        capability: str,
        timeout: Optional[float] = None,
    ) -> CapabilityCheckResult:
        """Check if a specific capability is allowed.

        Args:
            capability: Capability string to check (e.g., "medical:diagnosis").
            timeout: Operation timeout in seconds.

        Returns:
            CapabilityCheckResult with allow/deny decision and reason.
        """
        timeout = timeout or self._timeout

        def _check() -> CapabilityCheckResult:
            result = ctypes.c_int()
            ret = self._lib.ciris_verify_check_capability(
                self._handle,
                capability.encode("utf-8"),
                b"",  # action (default empty)
                0,    # required_tier (default 0)
                ctypes.byref(result),
            )

            if ret != 0:
                return CapabilityCheckResult(
                    capability=capability,
                    allowed=False,
                    reason=f"Check failed with code {ret}",
                )

            allowed = result.value == 1
            reason = "Capability granted" if allowed else "Capability denied by license"

            return CapabilityCheckResult(
                capability=capability,
                allowed=allowed,
                reason=reason,
            )

        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(self._executor, _check),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise CIRISTimeoutError("check_capability", timeout)

    def get_mandatory_disclosure(self, status: LicenseStatus) -> MandatoryDisclosure:
        """Get mandatory disclosure for a given status.

        Args:
            status: License status to get disclosure for.

        Returns:
            MandatoryDisclosure with text and severity.
        """
        if status.requires_lockdown():
            severity = DisclosureSeverity.CRITICAL
        elif status.requires_restricted():
            severity = DisclosureSeverity.WARNING
        else:
            severity = DisclosureSeverity.INFO

        return MandatoryDisclosure(
            text=self._default_disclosure(status),
            severity=severity,
        )


class MockCIRISVerify(CIRISVerify):
    """Mock CIRISVerify client for testing without the actual binary.

    Usage:
        verifier = MockCIRISVerify(
            mock_status=LicenseStatus.UNLICENSED_COMMUNITY
        )
        status = await verifier.get_license_status(os.urandom(32))
        assert status.status == LicenseStatus.UNLICENSED_COMMUNITY
    """

    def __init__(
        self,
        mock_status: LicenseStatus = LicenseStatus.UNLICENSED_COMMUNITY,
        mock_hardware: HardwareType = HardwareType.SOFTWARE_ONLY,
        mock_capabilities: Optional[Set[str]] = None,
    ):
        """Initialize mock client.

        Args:
            mock_status: Status to return from get_license_status().
            mock_hardware: Hardware type to report.
            mock_capabilities: Set of allowed capabilities.
        """
        self._mock_status = mock_status
        self._mock_hardware = mock_hardware
        self._mock_capabilities = mock_capabilities
        self._timeout = 10.0
        # Don't call parent __init__ - no binary needed

    def _find_binary(self, path):
        return None

    def _verify_binary_integrity(self):
        pass

    def _load_library(self):
        pass

    def __del__(self):
        pass

    async def get_license_status(
        self,
        challenge_nonce: bytes,
        device_fingerprint: Optional[bytes] = None,
        timeout: Optional[float] = None,
    ) -> LicenseStatusResponse:
        """Return mock license status."""
        if len(challenge_nonce) < 32:
            raise ValueError("challenge_nonce must be at least 32 bytes")

        severity = DisclosureSeverity.INFO
        if self._mock_status.requires_lockdown():
            severity = DisclosureSeverity.CRITICAL
        elif self._mock_status.requires_restricted():
            severity = DisclosureSeverity.WARNING

        license_details = None
        if self._mock_status.allows_licensed_operation():
            license_details = LicenseDetails(
                license_id="mock-license-001",
                tier=LicenseTier.PROFESSIONAL_FULL,
                capabilities=self._mock_capabilities or {"*"},
                prohibited_capabilities=set(),
                issued_at=datetime.now(timezone.utc),
                expires_at=datetime(2099, 12, 31, tzinfo=timezone.utc),
                issuer="mock-issuer",
            )

        return LicenseStatusResponse(
            status=self._mock_status,
            license=license_details,
            mandatory_disclosure=MandatoryDisclosure(
                text="[MOCK] " + self._default_disclosure(self._mock_status),
                severity=severity,
            ),
            hardware_type=self._mock_hardware,
            source_details=SourceDetails(
                dns_us_reachable=True,
                dns_eu_reachable=True,
                https_reachable=True,
                validation_status=ValidationStatus.ALL_SOURCES_AGREE,
                sources_agreeing=3,
            ),
            cached=False,
            verification_timestamp=datetime.now(timezone.utc),
        )

    async def check_capability(
        self,
        capability: str,
        timeout: Optional[float] = None,
    ) -> CapabilityCheckResult:
        """Return mock capability check.

        In community mode, standard operations (standard:*, tool:*) are
        allowed. Professional domain capabilities (medical, legal, financial,
        etc.) are blocked.
        """
        # Standard operations are always allowed, even in community mode
        cap_lower = capability.lower()
        is_standard = (
            cap_lower.startswith("standard:")
            or cap_lower.startswith("tool:")
        )

        if not self._mock_status.allows_licensed_operation():
            if is_standard:
                return CapabilityCheckResult(
                    capability=capability,
                    allowed=True,
                    reason="Standard operation allowed",
                )
            return CapabilityCheckResult(
                capability=capability,
                allowed=False,
                reason="Community mode - professional capabilities not available",
            )

        if self._mock_capabilities is None:
            allowed = True
        else:
            allowed = capability in self._mock_capabilities or "*" in self._mock_capabilities

        return CapabilityCheckResult(
            capability=capability,
            allowed=allowed,
            reason="Allowed by mock" if allowed else "Not in mock capabilities",
        )

    def _default_disclosure(self, status: LicenseStatus) -> str:
        """Generate default disclosure for mock."""
        return super()._default_disclosure(status)
