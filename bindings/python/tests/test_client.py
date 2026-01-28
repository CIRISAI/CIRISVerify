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
