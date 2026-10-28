"""Запуск каталога независимых проверок одной ревизии устройства."""

from datetime import datetime

from firewall_compliance.analysis.management_checks import ManagementCheck, management_checks
from firewall_compliance.analysis.policy_checks import (
    AnyAnyCheck,
    CommentsCheck,
    DisabledRulesCheck,
    DuplicateRulesCheck,
    LoggingCheck,
    MergeCandidateCheck,
    PartialShadowedRulesCheck,
    PolicyCheck,
    PolicyCheckContext,
    ShadowedRulesCheck,
    UnionShadowedRulesCheck,
    check_version,
)
from firewall_compliance.analysis.policy_exposure import (
    DangerousServicesCheck,
    UntrustedAdministrativeAccessCheck,
)
from firewall_compliance.domain import DeviceRevision
from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile

CHECK_CATALOG_VERSION = "1.0.0"


def analyze_firewall(
    revision: DeviceRevision,
    *,
    analyzed_at: datetime | None = None,
    require_logging: bool = True,
    require_comments: bool = True,
    max_pair_rules: int = 1000,
    checks: tuple[PolicyCheck, ...] | None = None,
    management_profile: ManagementProfile | None = None,
    extended_policy_checks: bool = False,
    policy_exposure_profile: PolicyExposureProfile | None = None,
) -> FirewallAssuranceResult:
    """Выполнить проверки без файлов, сети и изменения входной ревизии."""
    timestamp = analyzed_at or revision.imported_at
    if timestamp.tzinfo is None or timestamp < revision.imported_at:
        raise ValueError("время анализа должно содержать часовой пояс и быть не раньше импорта")
    if max_pair_rules < 1:
        raise ValueError("лимит попарного анализа должен быть положительным")
    catalog: tuple[PolicyCheck, ...] = (
        checks
        if checks is not None
        else (
            AnyAnyCheck(),
            DuplicateRulesCheck(),
            ShadowedRulesCheck(),
            MergeCandidateCheck(),
            LoggingCheck(),
            CommentsCheck(),
            DisabledRulesCheck(),
        )
    )
    if checks is None and extended_policy_checks:
        catalog += (
            PartialShadowedRulesCheck(),
            UnionShadowedRulesCheck(),
            DangerousServicesCheck(policy_exposure_profile),
            UntrustedAdministrativeAccessCheck(policy_exposure_profile),
        )
    if checks is None and revision.parse_result.management is not None:
        catalog += management_checks(management_profile)
    used_profiles = [check.profile for check in catalog if isinstance(check, ManagementCheck)]
    if used_profiles:
        effective_profile = management_profile or used_profiles[0]
        if any(profile != effective_profile for profile in used_profiles):
            raise ValueError("management checks must use one consistent profile")
    else:
        effective_profile = management_profile or ManagementProfile()
    if len({check.check_id for check in catalog}) != len(catalog):
        raise ValueError("идентификаторы проверок каталога должны быть уникальными")
    context = PolicyCheckContext(
        revision, timestamp, require_logging, require_comments, max_pair_rules
    )
    return FirewallAssuranceResult(
        revision_id=revision.revision_id,
        configuration_id=revision.parse_result.configuration.configuration_id,
        device_id=revision.device.device_id,
        application_version=revision.application_version,
        parser_version=revision.parse_result.configuration.parser_version,
        check_catalog_version="1.4.0"
        if any(check.check_id in {"FW-RULE-GOVERNANCE", "FW-UNUSED-CANDIDATE"} for check in catalog)
        else "1.3.0"
        if any(
            check.check_id
            in {
                "FW-PARTIAL-SHADOWED",
                "FW-UNION-SHADOWED",
                "FW-DANGEROUS-SERVICES",
                "FW-ADMIN-UNTRUSTED",
            }
            for check in catalog
        )
        else "1.2.0"
        if any(check.check_id.startswith("MGMT-") for check in catalog)
        else check_version(context),
        require_logging=require_logging,
        require_comments=require_comments,
        max_pair_rules=max_pair_rules,
        analyzed_at=timestamp,
        checks=tuple(check.evaluate(context) for check in catalog),
        parse_warnings=revision.parse_result.warnings,
        parse_errors=revision.parse_result.errors,
        unsupported_constructs=revision.parse_result.unsupported_constructs,
        parse_coverage=revision.parse_result.coverage,
        management_profile=effective_profile.model_dump(mode="json")
        if any(check.check_id.startswith("MGMT-") for check in catalog)
        else None,
    )
