"""Сценарий анализа входного документа через нейтральный parser registry."""

from datetime import datetime
from uuid import UUID, uuid4

from firewall_compliance import __version__
from firewall_compliance.analysis.firewall_assurance import analyze_firewall
from firewall_compliance.domain import Device, DeviceRevision, RevisionSource, SourceDocumentKind
from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.domain.policy_scope import PolicyScopeProfile
from firewall_compliance.parsers import ParseFailure, ParseRequest, ParserRegistry, SourceDocument


def build_source_revision(
    source: SourceDocument,
    registry: ParserRegistry,
    *,
    imported_at: datetime,
    revision_id: UUID | None = None,
) -> DeviceRevision | ParseFailure:
    """Parse one captured source once and retain its exact normalized revision."""
    outcome = registry.parse(ParseRequest(source=source, imported_at=imported_at))
    if isinstance(outcome, ParseFailure):
        return outcome
    configuration = outcome.configuration
    revision = DeviceRevision(
        revision_id=revision_id or uuid4(),
        device=Device(
            device_id=configuration.device_id,
            vendor=configuration.vendor,
            platform=configuration.platform,
        ),
        parse_result=outcome,
        sources=(
            RevisionSource(
                source_name=source.source_name,
                content_sha256=source.content_sha256,
                captured_at=source.captured_at,
                file_modified_at=source.file_modified_at,
                observation=source.observation,
                kind=SourceDocumentKind.CONFIGURATION,
            ),
        ),
        application_version=__version__,
        observed_at=source.observation.observed_at if source.observation is not None else None,
        imported_at=imported_at,
    )
    return revision


def analyze_source(
    source: SourceDocument,
    registry: ParserRegistry,
    *,
    imported_at: datetime,
    revision_id: UUID | None = None,
    require_logging: bool = True,
    require_comments: bool = True,
    management_profile: ManagementProfile | None = None,
    extended_policy_checks: bool = False,
    policy_exposure_profile: PolicyExposureProfile | None = None,
    policy_scope_profile: PolicyScopeProfile | None = None,
) -> FirewallAssuranceResult | ParseFailure:
    """Построить ревизию с неизвестными сетевыми данными и выполнить policy checks."""
    revision = build_source_revision(
        source,
        registry,
        imported_at=imported_at,
        revision_id=revision_id,
    )
    if isinstance(revision, ParseFailure):
        return revision
    return analyze_firewall(
        revision,
        require_logging=require_logging,
        require_comments=require_comments,
        management_profile=management_profile,
        extended_policy_checks=extended_policy_checks,
        policy_exposure_profile=policy_exposure_profile,
        policy_scope_profile=policy_scope_profile,
    )
