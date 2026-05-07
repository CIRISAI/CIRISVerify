"""Tests for CIRISVerify client."""

import os
import pytest
from unittest.mock import Mock, patch, MagicMock

from ciris_verify.client import CIRISVerify, MockCIRISVerify
from ciris_verify.types import (
    LicenseStatus,
    LicenseTier,
    HardwareType,
    ValidationStatus,
)
from ciris_verify.exceptions import (
    BinaryNotFoundError,
    BinaryTamperedError,
    CommunicationError,
)


class TestMockCIRISVerify:
    """Tests for MockCIRISVerify client."""

    @pytest.fixture
    def mock_client(self):
        return MockCIRISVerify(
            mock_status=LicenseStatus.UNLICENSED_COMMUNITY,
            mock_hardware=HardwareType.SOFTWARE_ONLY,
        )

    @pytest.fixture
    def licensed_mock_client(self):
        return MockCIRISVerify(
            mock_status=LicenseStatus.LICENSED_PROFESSIONAL,
            mock_hardware=HardwareType.TPM_DISCRETE,
            mock_capabilities={"medical:*", "legal:consultation"},
        )

    @pytest.mark.asyncio
    async def test_community_status(self, mock_client):
        nonce = os.urandom(32)
        status = await mock_client.get_license_status(nonce)

        assert status.status == LicenseStatus.UNLICENSED_COMMUNITY
        assert status.hardware_type == HardwareType.SOFTWARE_ONLY
        assert not status.allows_licensed_operation()

    @pytest.mark.asyncio
    async def test_licensed_status(self, licensed_mock_client):
        nonce = os.urandom(32)
        status = await licensed_mock_client.get_license_status(nonce)

        assert status.status == LicenseStatus.LICENSED_PROFESSIONAL
        assert status.hardware_type == HardwareType.TPM_DISCRETE
        assert status.allows_licensed_operation()
        assert status.license is not None
        assert status.license.tier == LicenseTier.PROFESSIONAL_FULL

    @pytest.mark.asyncio
    async def test_nonce_validation(self, mock_client):
        with pytest.raises(ValueError, match="at least 32 bytes"):
            await mock_client.get_license_status(b"short")

    @pytest.mark.asyncio
    async def test_capability_check_community(self, mock_client):
        result = await mock_client.check_capability("medical:diagnosis")
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_capability_check_licensed(self, licensed_mock_client):
        result = await licensed_mock_client.check_capability("medical:diagnosis")
        assert result.allowed

        result = await licensed_mock_client.check_capability("financial:trading")
        assert not result.allowed  # Not in mock_capabilities

    @pytest.mark.asyncio
    async def test_mandatory_disclosure(self, mock_client):
        nonce = os.urandom(32)
        status = await mock_client.get_license_status(nonce)

        assert status.mandatory_disclosure is not None
        assert "[MOCK]" in status.mandatory_disclosure.text

    @pytest.mark.asyncio
    async def test_source_details(self, mock_client):
        nonce = os.urandom(32)
        status = await mock_client.get_license_status(nonce)

        # Mock always returns all sources agreeing
        assert status.source_details.dns_us_reachable
        assert status.source_details.dns_eu_reachable
        assert status.source_details.https_reachable
        assert status.source_details.validation_status == ValidationStatus.ALL_SOURCES_AGREE


class TestCIRISVerify:
    """Tests for real CIRISVerify client (when binary available)."""

    def test_binary_not_found(self):
        with pytest.raises(BinaryNotFoundError):
            CIRISVerify(binary_path="/nonexistent/path/libciris_verify.so")

    def test_skip_integrity_check(self, tmp_path):
        # Create a fake binary file
        fake_binary = tmp_path / "libciris_verify.so"
        fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 100)  # ELF header

        # Should not raise even though it's not a real binary
        # when skip_integrity_check=True
        with pytest.raises((OSError, CommunicationError)):
            # Will fail at load_library since it's not a real .so
            CIRISVerify(
                binary_path=str(fake_binary),
                skip_integrity_check=True,
            )

    def test_invalid_binary_format(self, tmp_path):
        # Create a file with invalid binary format
        fake_binary = tmp_path / "libciris_verify.so"
        fake_binary.write_bytes(b"not a binary")

        with pytest.raises(BinaryTamperedError):
            CIRISVerify(binary_path=str(fake_binary))


class TestFindBinaryDefenses:
    """Tests for CIRISVerify#13 defensive _find_binary enhancements:
    platform-preferred suffix order + site-packages fallback. Both must
    be no-ops on the wheel-internal happy path; both must activate for
    downstream consumers that load CIRISVerify from a directory other
    than the wheel's own.
    """

    def test_platform_suffix_order_darwin(self):
        """Darwin must return .dylib first so a stray Linux .so doesn't
        win the iteration on a mixed-bundle dev host."""
        order = CIRISVerify._get_platform_binary_suffixes("Darwin")
        assert order[0] == ".dylib"
        assert ".so" in order
        assert order.index(".dylib") < order.index(".so")

    def test_platform_suffix_order_linux(self):
        order = CIRISVerify._get_platform_binary_suffixes("Linux")
        assert order[0] == ".so"

    def test_platform_suffix_order_windows(self):
        order = CIRISVerify._get_platform_binary_suffixes("Windows")
        assert order == [".dll"]

    def test_mixed_bundle_dir_picks_correct_platform_binary(self, tmp_path, monkeypatch):
        """Mixed-bundle search dir on Darwin: the .dylib must be returned,
        not the .so that happens to also be present (the CIRISVerify#13
        ordering bug)."""
        import platform as _platform
        import ciris_verify as _ciris_verify_pkg
        import ciris_verify.client as _ciris_verify_client

        # Both extensions present in the same dir.
        (tmp_path / "libciris_verify_ffi.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (tmp_path / "libciris_verify_ffi.dylib").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        # Patch both __file__ attrs to point at tmp_path so that
        # module_dir == pkg_dir == tmp_path. The first iteration (over
        # module_dir) must hit on the platform-correct suffix order.
        monkeypatch.setattr(
            _ciris_verify_client, "__file__", str(tmp_path / "client.py")
        )
        monkeypatch.setattr(
            _ciris_verify_pkg, "__file__", str(tmp_path / "__init__.py")
        )
        monkeypatch.setattr(_platform, "system", lambda: "Darwin")

        # Build a stub instance that exposes _find_binary without running __init__.
        client = CIRISVerify.__new__(CIRISVerify)

        found = client._find_binary(None)
        assert found.suffix == ".dylib", f"expected .dylib first on Darwin, got {found}"

    def test_site_packages_fallback_when_module_dir_empty(self, tmp_path, monkeypatch):
        """When module_dir has no binary but the importable ciris_verify
        package has one in site-packages, the fallback must find it.
        This is the agent-fork case from CIRISVerify#13."""
        import platform as _platform
        import ciris_verify as _ciris_verify_pkg
        import ciris_verify.client as _ciris_verify_client

        # Fake site-packages dir with the binary present.
        fake_site_pkg = tmp_path / "site-packages-ciris_verify"
        fake_site_pkg.mkdir()
        binary = fake_site_pkg / "libciris_verify_ffi.so"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        # Empty module_dir — what an agent's embedded ffi_bindings/ looks
        # like after the in-repo desktop binary is deleted to single-source
        # via the pip wheel.
        empty_module_dir = tmp_path / "empty-module-dir"
        empty_module_dir.mkdir()

        # client.__file__ → empty_module_dir/client.py → module_dir is empty.
        monkeypatch.setattr(
            _ciris_verify_client,
            "__file__",
            str(empty_module_dir / "client.py"),
        )
        # ciris_verify.__file__ → fake_site_pkg/__init__.py → fallback finds binary.
        monkeypatch.setattr(
            _ciris_verify_pkg,
            "__file__",
            str(fake_site_pkg / "__init__.py"),
        )
        monkeypatch.setattr(_platform, "system", lambda: "Linux")

        client = CIRISVerify.__new__(CIRISVerify)
        found = client._find_binary(None)
        assert found == binary, f"site-packages fallback missed: got {found}"

    def test_site_packages_fallback_skipped_when_module_is_loader(
        self, tmp_path, monkeypatch
    ):
        """When the wheel IS the loader (pkg_dir == module_dir), the
        fallback's `pkg_dir != module_dir` guard must short-circuit and
        the function falls through to BinaryNotFoundError. Proves the
        new branch is a no-op for wheel-internal use when the primary
        lookup misses."""
        import platform as _platform
        import ciris_verify as _ciris_verify_pkg
        import ciris_verify.client as _ciris_verify_client

        empty = tmp_path / "wheel-internal-empty"
        empty.mkdir()

        # Both __file__'s point at the SAME directory: that's the
        # wheel-internal case (module_dir == pkg_dir).
        monkeypatch.setattr(
            _ciris_verify_client, "__file__", str(empty / "client.py")
        )
        monkeypatch.setattr(
            _ciris_verify_pkg, "__file__", str(empty / "__init__.py")
        )
        monkeypatch.setattr(_platform, "system", lambda: "Linux")

        client = CIRISVerify.__new__(CIRISVerify)
        with pytest.raises(BinaryNotFoundError):
            client._find_binary(None)


class TestDefaultDisclosure:
    """Tests for default disclosure text generation."""

    def test_licensed_disclosure(self):
        client = MockCIRISVerify()
        disclosure = client.get_mandatory_disclosure(LicenseStatus.LICENSED_PROFESSIONAL)
        assert "professionally licensed" in disclosure.text.lower()

    def test_community_disclosure(self):
        client = MockCIRISVerify()
        disclosure = client.get_mandatory_disclosure(LicenseStatus.UNLICENSED_COMMUNITY)
        assert "unlicensed" in disclosure.text.lower() or "community" in disclosure.text.lower()

    def test_restricted_disclosure(self):
        client = MockCIRISVerify()
        disclosure = client.get_mandatory_disclosure(LicenseStatus.RESTRICTED_VERIFICATION_FAILED)
        assert "restricted" in disclosure.text.lower()

    def test_lockdown_disclosure(self):
        client = MockCIRISVerify()
        disclosure = client.get_mandatory_disclosure(LicenseStatus.LOCKDOWN_INTEGRITY_FAILURE)
        assert "critical" in disclosure.text.lower() or "failed" in disclosure.text.lower()
