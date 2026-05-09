"""Tests for CIRISVerify client."""

import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from ciris_verify.client import CIRISVerify, MockCIRISVerify, verify_tree
from ciris_verify.types import (
    LicenseStatus,
    LicenseTier,
    HardwareType,
    ValidationStatus,
    TreeVerifyRequest,
    TreeVerifyResult,
    FailedFile,
    FailedFileKind,
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


class TestTreeVerifyTypes:
    """Pydantic shape tests for TreeVerifyRequest / TreeVerifyResult.
    These don't touch the FFI binary — they lock the wire contract."""

    def test_request_minimal(self):
        req = TreeVerifyRequest(root="/tmp/x", project="p", binary_version="1.0")
        # Defaults populate as empty lists.
        assert req.include_roots == []
        assert req.exempt_dirs == []
        assert req.exempt_extensions == []

    def test_request_full(self):
        req = TreeVerifyRequest(
            root="/app",
            include_roots=["ciris_engine", "ciris_adapters"],
            exempt_dirs=["__pycache__"],
            exempt_extensions=["pyc", "pyo"],
            project="ciris-agent",
            binary_version="2.8.3",
        )
        # Round-trip through JSON locks the wire shape the FFI consumes.
        as_json = req.model_dump_json()
        back = TreeVerifyRequest.model_validate_json(as_json)
        assert back == req

    def test_result_round_trip(self):
        # Mirrors the JSON the FFI produces.
        payload = {
            "valid": False,
            "files_checked": 3,
            "files_passed": 1,
            "failed_files": [
                {
                    "path": "drift.py",
                    "kind": "mismatch",
                    "computed_hash": "sha256:aa",
                    "expected_hash": "sha256:bb",
                },
                {
                    "path": "missing.py",
                    "kind": "missing",
                    "expected_hash": "sha256:cc",
                },
                {
                    "path": "extra.py",
                    "kind": "extra",
                    "computed_hash": "sha256:dd",
                },
            ],
            "total_hash": "sha256:ee",
            "expected_total_hash": "sha256:ff",
            "registry_match": False,
            "project": "ciris-agent",
            "binary_version": "2.8.3",
        }
        r = TreeVerifyResult.model_validate(payload)
        assert len(r.failed_files) == 3
        kinds = {f.kind for f in r.failed_files}
        assert kinds == {FailedFileKind.MISMATCH, FailedFileKind.MISSING, FailedFileKind.EXTRA}

    def test_result_registry_unreachable(self):
        # Registry-down case: no expected_total_hash, registry_error set.
        r = TreeVerifyResult(
            valid=False,
            files_checked=42,
            files_passed=0,
            total_hash="sha256:abc",
            registry_match=False,
            registry_error="connection refused",
            project="ciris-verify",
            binary_version="1.13.0",
        )
        assert r.expected_total_hash is None
        assert r.registry_error == "connection refused"


class TestVerifyTreeFFI:
    """End-to-end FFI tests for verify_tree(). Skipped when the bundled
    libciris_verify_ffi.so isn't present (e.g. on a fresh checkout
    before `cargo build --release` + copy)."""

    @pytest.fixture
    def lib_present(self):
        """Skip the test if the bundled binary isn't there."""
        import platform
        suffix = {"Darwin": ".dylib", "Windows": ".dll"}.get(platform.system(), ".so")
        binary = Path(__file__).parent.parent / "ciris_verify" / f"libciris_verify_ffi{suffix}"
        if not binary.exists():
            pytest.skip(f"FFI binary not present at {binary}")

    def test_walk_succeeds_registry_returns_404(self, lib_present, tmp_path, monkeypatch):
        """Walks a synthetic tree, queries registry for a version that
        doesn't exist. Walk must succeed (total_hash populated), registry
        compare must fail with a 404 surfaced via registry_error.

        CIRIS_SKIP_EARLY_VERIFY skips the .init_array constructor's
        network fetch which can hang on dlopen() in dev environments.
        """
        monkeypatch.setenv("CIRIS_SKIP_EARLY_VERIFY", "1")

        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "a.py").write_text("# hi\n")
        (tmp_path / "pkg" / "b.py").write_text("# hello\n")

        req = TreeVerifyRequest(
            root=str(tmp_path),
            include_roots=["pkg"],
            exempt_dirs=["__pycache__"],
            exempt_extensions=["pyc"],
            project="ciris-agent",
            binary_version="99.99.99-not-a-real-version",
        )
        r = verify_tree(req)

        # Walk-side invariants: 2 files, total_hash populated, sha256: prefix.
        assert r.files_checked == 2
        assert r.total_hash.startswith("sha256:")
        assert len(r.total_hash) == 7 + 64

        # Registry-side: no match, error surfaced, no expected_total_hash.
        assert r.valid is False
        assert r.registry_match is False
        assert r.registry_error is not None
        assert "404" in r.registry_error or "not found" in r.registry_error.lower()
        assert r.expected_total_hash is None

    def test_request_round_trip_through_ffi(self, lib_present, tmp_path, monkeypatch):
        """The FFI echoes project + binary_version in the result. Locks
        the wire-format keys so a Rust-side rename would break this."""
        monkeypatch.setenv("CIRIS_SKIP_EARLY_VERIFY", "1")

        (tmp_path / "x.py").write_text("x\n")

        req = TreeVerifyRequest(
            root=str(tmp_path),
            project="ciris-agent",
            binary_version="zzz-no-such-version",
        )
        r = verify_tree(req)
        assert r.project == "ciris-agent"
        assert r.binary_version == "zzz-no-such-version"


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
