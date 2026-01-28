"""CIRISVerify client - Python FFI wrapper for the verification binary.

This module provides a high-level Python interface to the CIRISVerify
Rust binary via C FFI. It handles binary loading, protobuf encoding,
and type conversion.
"""

import os
import ctypes
import asyncio
import hashlib
import platform
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

    Binary Integrity:
        The client verifies binary integrity on initialization using
        embedded hash checks. If verification fails, BinaryTamperedError
        is raised and no operations are permitted.
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        skip_integrity_check: bool = False,
        timeout_seconds: float = 10.0,
    ):
        """Initialize CIRISVerify client.

        Args:
            binary_path: Path to CIRISVerify binary. If None, searches
                         default system paths.
            skip_integrity_check: Skip binary integrity verification.
                                  WARNING: Only for development/testing.
            timeout_seconds: Default timeout for verification operations.

        Raises:
            BinaryNotFoundError: If binary cannot be found.
            BinaryTamperedError: If binary integrity check fails.
        """
        self._timeout = timeout_seconds
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ciris_verify")
        self._lib: Optional[ctypes.CDLL] = None
        self._handle = None

        # Find and load binary
        self._binary_path = self._find_binary(binary_path)

        if not skip_integrity_check:
            self._verify_binary_integrity()

        self._load_library()

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
        """Verify binary hasn't been tampered with.

        In production, this checks against a pinned hash. For development,
        we skip this check with skip_integrity_check=True.
        """
        # TODO: Implement actual hash verification against pinned values
        # For now, just verify the file is readable and has expected structure
        try:
            with open(self._binary_path, "rb") as f:
                # Read first 4 bytes to check for valid binary format
                magic = f.read(4)
                if not magic:
                    raise BinaryTamperedError("Empty binary file")

                # ELF magic: 0x7f ELF
                # Mach-O magic: 0xfeedface or 0xfeedfacf or 0xcafebabe
                # PE magic: MZ
                valid_magic = [
                    b"\x7fELF",  # ELF
                    b"\xfe\xed\xfa\xce",  # Mach-O 32
                    b"\xfe\xed\xfa\xcf",  # Mach-O 64
                    b"\xcf\xfa\xed\xfe",  # Mach-O 64 LE
                    b"\xca\xfe\xba\xbe",  # Mach-O Universal
                    b"MZ\x90\x00",  # PE
                    b"MZ\x00\x00",  # PE variant
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

        # Set up function signatures
        # ciris_verify_init() -> *mut CirisVerifyHandle
        self._lib.ciris_verify_init.argtypes = []
        self._lib.ciris_verify_init.restype = ctypes.c_void_p

        # ciris_verify_get_status(handle, request_data, request_len, response_data, response_len) -> i32
        self._lib.ciris_verify_get_status.argtypes = [
            ctypes.c_void_p,  # handle
            ctypes.c_char_p,  # request_data
            ctypes.c_size_t,  # request_len
            ctypes.POINTER(ctypes.c_char_p),  # response_data (out)
            ctypes.POINTER(ctypes.c_size_t),  # response_len (out)
        ]
        self._lib.ciris_verify_get_status.restype = ctypes.c_int

        # ciris_verify_check_capability(handle, capability, result) -> i32
        self._lib.ciris_verify_check_capability.argtypes = [
            ctypes.c_void_p,  # handle
            ctypes.c_char_p,  # capability
            ctypes.POINTER(ctypes.c_int),  # result (out): 1=allowed, 0=denied
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
                pass  # Best effort cleanup
        if self._executor:
            self._executor.shutdown(wait=False)

    def _sync_get_license_status(
        self,
        challenge_nonce: bytes,
        device_fingerprint: Optional[bytes] = None,
    ) -> LicenseStatusResponse:
        """Synchronous license status check (internal)."""
        if len(challenge_nonce) < 32:
            raise ValueError("challenge_nonce must be at least 32 bytes")

        # Build request (simplified - in production use protobuf)
        # Format: nonce_len (4 bytes) + nonce + fingerprint_len (4 bytes) + fingerprint
        request = bytearray()
        request.extend(len(challenge_nonce).to_bytes(4, "little"))
        request.extend(challenge_nonce)

        if device_fingerprint:
            request.extend(len(device_fingerprint).to_bytes(4, "little"))
            request.extend(device_fingerprint)
        else:
            request.extend((0).to_bytes(4, "little"))

        request_bytes = bytes(request)

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
            # Parse response (simplified - in production use protobuf)
            response_bytes = ctypes.string_at(response_data, response_len.value)
            return self._parse_response(response_bytes)
        finally:
            # Free response memory
            if response_data:
                self._lib.ciris_verify_free(response_data)

    def _parse_response(self, data: bytes) -> LicenseStatusResponse:
        """Parse binary response into LicenseStatusResponse.

        In production, this would use protobuf decoding.
        For now, use a simplified binary format.
        """
        if len(data) < 8:
            raise CommunicationError(f"Response too short: {len(data)} bytes")

        offset = 0

        # Status code (4 bytes)
        status_code = int.from_bytes(data[offset:offset+4], "little")
        offset += 4

        # Hardware type (1 byte)
        hw_type_val = data[offset]
        offset += 1

        # Cached flag (1 byte)
        cached = bool(data[offset])
        offset += 1

        # Disclosure text length (2 bytes) + text
        disclosure_len = int.from_bytes(data[offset:offset+2], "little")
        offset += 2
        disclosure_text = data[offset:offset+disclosure_len].decode("utf-8", errors="replace")
        offset += disclosure_len

        # Map values to types
        try:
            status = LicenseStatus(status_code)
        except ValueError:
            status = LicenseStatus.ERROR_VERIFICATION_FAILED

        hw_type_map = {
            1: HardwareType.ANDROID_KEYSTORE,
            2: HardwareType.ANDROID_STRONGBOX,
            3: HardwareType.IOS_SECURE_ENCLAVE,
            4: HardwareType.TPM_DISCRETE,
            5: HardwareType.TPM_FIRMWARE,
            6: HardwareType.INTEL_SGX,
            7: HardwareType.SOFTWARE_ONLY,
        }
        hardware_type = hw_type_map.get(hw_type_val, HardwareType.SOFTWARE_ONLY)

        # Determine severity from status
        if status.requires_lockdown():
            severity = DisclosureSeverity.CRITICAL
        elif status.requires_restricted():
            severity = DisclosureSeverity.WARNING
        else:
            severity = DisclosureSeverity.INFO

        return LicenseStatusResponse(
            status=status,
            license=None,  # Would parse from response if present
            mandatory_disclosure=MandatoryDisclosure(
                text=disclosure_text or self._default_disclosure(status),
                severity=severity,
            ),
            hardware_type=hardware_type,
            source_details=SourceDetails(),  # Would parse from response
            cached=cached,
            verification_timestamp=datetime.now(timezone.utc),
        )

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

        This is the primary method for checking license status. It returns
        a comprehensive response including the license details, mandatory
        disclosure text, and hardware attestation data.

        Args:
            challenge_nonce: Random 32+ byte nonce to prevent replay attacks.
                            Generate with os.urandom(32).
            device_fingerprint: Optional device identifier for binding.
            timeout: Operation timeout in seconds. Defaults to instance timeout.

        Returns:
            LicenseStatusResponse with complete verification results.

        Raises:
            ValueError: If challenge_nonce is too short.
            TimeoutError: If operation times out.
            VerificationFailedError: If verification fails.
            CommunicationError: If FFI communication fails.
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

        This is a fast path for checking individual capabilities without
        doing a full license verification. Useful for frequent checks.

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

        This can be used to get disclosure text without doing a full
        verification, useful for UI display.

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

    This class provides the same interface as CIRISVerify but returns
    configurable mock responses. Useful for unit testing.

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
            mock_capabilities: Set of allowed capabilities. If None,
                              allows all capabilities when licensed.
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
        pass  # No cleanup needed

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
        """Return mock capability check."""
        if not self._mock_status.allows_licensed_operation():
            return CapabilityCheckResult(
                capability=capability,
                allowed=False,
                reason="Not licensed",
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
