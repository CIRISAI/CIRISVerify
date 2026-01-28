"""Tests for CIRISVerify type definitions."""

import pytest
from datetime import datetime, timezone, timedelta

from ciris_verify.types import (
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
)


class TestLicenseStatus:
    """Tests for LicenseStatus enum."""

    def test_licensed_professional_allows_operation(self):
        assert LicenseStatus.LICENSED_PROFESSIONAL.allows_licensed_operation()
        assert LicenseStatus.LICENSED_PROFESSIONAL_GRACE.allows_licensed_operation()

    def test_community_mode_denies_operation(self):
        assert not LicenseStatus.UNLICENSED_COMMUNITY.allows_licensed_operation()
        assert not LicenseStatus.UNLICENSED_COMMUNITY_OFFLINE.allows_licensed_operation()

    def test_error_states_deny_operation(self):
        assert not LicenseStatus.ERROR_REVOKED.allows_licensed_operation()
        assert not LicenseStatus.ERROR_EXPIRED.allows_licensed_operation()
        assert not LicenseStatus.ERROR_BINARY_TAMPERED.allows_licensed_operation()

    def test_lockdown_detection(self):
        assert LicenseStatus.LOCKDOWN_INTEGRITY_FAILURE.requires_lockdown()
        assert LicenseStatus.LOCKDOWN_ATTACK_DETECTED.requires_lockdown()
        assert not LicenseStatus.LICENSED_PROFESSIONAL.requires_lockdown()

    def test_restricted_detection(self):
        assert LicenseStatus.RESTRICTED_VERIFICATION_FAILED.requires_restricted()
        assert LicenseStatus.RESTRICTED_SOURCES_DISAGREE.requires_restricted()
        assert not LicenseStatus.LICENSED_PROFESSIONAL.requires_restricted()

    def test_community_mode_detection(self):
        assert LicenseStatus.UNLICENSED_COMMUNITY.is_community_mode()
        assert LicenseStatus.UNLICENSED_COMMUNITY_OFFLINE.is_community_mode()
        assert not LicenseStatus.LICENSED_PROFESSIONAL.is_community_mode()


class TestHardwareType:
    """Tests for HardwareType enum."""

    def test_hardware_supports_professional(self):
        assert HardwareType.ANDROID_STRONGBOX.supports_professional_license()
        assert HardwareType.IOS_SECURE_ENCLAVE.supports_professional_license()
        assert HardwareType.TPM_DISCRETE.supports_professional_license()

    def test_software_only_denies_professional(self):
        assert not HardwareType.SOFTWARE_ONLY.supports_professional_license()

    def test_security_levels(self):
        assert HardwareType.ANDROID_STRONGBOX.security_level() == 5
        assert HardwareType.SOFTWARE_ONLY.security_level() == 1
        assert HardwareType.ANDROID_KEYSTORE.security_level() == 3


class TestLicenseDetails:
    """Tests for LicenseDetails model."""

    @pytest.fixture
    def license_details(self):
        return LicenseDetails(
            license_id="test-license-001",
            tier=LicenseTier.PROFESSIONAL_FULL,
            capabilities={"medical:*", "legal:consultation"},
            prohibited_capabilities={"weapons:*"},
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=365),
            issuer="test-issuer",
        )

    def test_has_exact_capability(self, license_details):
        assert license_details.has_capability("legal:consultation")

    def test_has_wildcard_capability(self, license_details):
        assert license_details.has_capability("medical:diagnosis")
        assert license_details.has_capability("medical:triage")
        assert license_details.has_capability("medical:prescription")

    def test_prohibited_capability_denied(self, license_details):
        assert not license_details.has_capability("weapons:manufacturing")

    def test_missing_capability_denied(self, license_details):
        assert not license_details.has_capability("financial:trading")


class TestMandatoryDisclosure:
    """Tests for MandatoryDisclosure model."""

    def test_disclosure_creation(self):
        disclosure = MandatoryDisclosure(
            text="Test disclosure",
            severity=DisclosureSeverity.WARNING,
        )
        assert disclosure.text == "Test disclosure"
        assert disclosure.severity == DisclosureSeverity.WARNING
        assert disclosure.locale == "en"

    def test_disclosure_immutable(self):
        disclosure = MandatoryDisclosure(
            text="Test",
            severity=DisclosureSeverity.INFO,
        )
        with pytest.raises(Exception):  # Frozen model
            disclosure.text = "Modified"


class TestLicenseStatusResponse:
    """Tests for LicenseStatusResponse model."""

    @pytest.fixture
    def licensed_response(self):
        return LicenseStatusResponse(
            status=LicenseStatus.LICENSED_PROFESSIONAL,
            license=LicenseDetails(
                license_id="test-001",
                tier=LicenseTier.PROFESSIONAL_FULL,
                capabilities={"medical:*"},
                prohibited_capabilities=set(),
                issued_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(days=365),
                issuer="test",
            ),
            mandatory_disclosure=MandatoryDisclosure(
                text="Licensed",
                severity=DisclosureSeverity.INFO,
            ),
            hardware_type=HardwareType.TPM_DISCRETE,
        )

    @pytest.fixture
    def community_response(self):
        return LicenseStatusResponse(
            status=LicenseStatus.UNLICENSED_COMMUNITY,
            license=None,
            mandatory_disclosure=MandatoryDisclosure(
                text="Community mode",
                severity=DisclosureSeverity.INFO,
            ),
            hardware_type=HardwareType.SOFTWARE_ONLY,
        )

    def test_licensed_allows_operation(self, licensed_response):
        assert licensed_response.allows_licensed_operation()

    def test_community_denies_operation(self, community_response):
        assert not community_response.allows_licensed_operation()

    def test_has_capability_when_licensed(self, licensed_response):
        assert licensed_response.has_capability("medical:triage")

    def test_no_capability_when_community(self, community_response):
        assert not community_response.has_capability("medical:triage")

    def test_prohibited_capabilities_in_community(self, community_response):
        prohibited = community_response.get_prohibited_capabilities()
        assert "medical:*" in prohibited
        assert "legal:*" in prohibited
        assert "financial:*" in prohibited


class TestCapabilityCheckResult:
    """Tests for CapabilityCheckResult model."""

    def test_allowed_result(self):
        result = CapabilityCheckResult(
            capability="medical:triage",
            allowed=True,
            reason="Granted by license",
        )
        assert result.allowed
        assert result.capability == "medical:triage"

    def test_denied_result(self):
        result = CapabilityCheckResult(
            capability="weapons:manufacturing",
            allowed=False,
            reason="Absolutely prohibited",
        )
        assert not result.allowed


class TestSourceDetails:
    """Tests for SourceDetails model."""

    def test_all_sources_reachable(self):
        details = SourceDetails(
            dns_us_reachable=True,
            dns_eu_reachable=True,
            https_reachable=True,
            validation_status=ValidationStatus.ALL_SOURCES_AGREE,
            sources_agreeing=3,
        )
        assert details.sources_agreeing == 3

    def test_partial_sources(self):
        details = SourceDetails(
            dns_us_reachable=True,
            dns_eu_reachable=False,
            https_reachable=True,
            validation_status=ValidationStatus.PARTIAL_AGREEMENT,
            sources_agreeing=2,
        )
        assert details.sources_agreeing == 2
