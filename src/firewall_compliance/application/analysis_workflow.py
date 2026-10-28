"""Pure source-to-bundle workflow, independent from Qt, SQLite and source paths."""

from datetime import datetime
from uuid import UUID, uuid4

from firewall_compliance import __version__
from firewall_compliance.analysis.firewall_assurance import analyze_firewall
from firewall_compliance.application.analysis_result import (
    AnalysisResult,
    AnalysisSource,
    AttemptComponent,
    ComponentLimitation,
    PolicyAnalysisOptions,
    PolicyComponent,
    source_manifest,
)
from firewall_compliance.application.firewall_assurance import build_source_revision
from firewall_compliance.domain.enums import SourceDocumentKind
from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.parsers import ParseFailure, ParserRegistry, SourceDocument


def analyze_source_result(
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
) -> AnalysisResult:
    """Keep the same parsed input and conclusions together with replayable options."""
    revision = build_source_revision(
        source,
        registry,
        imported_at=imported_at,
        revision_id=revision_id,
    )
    if isinstance(revision, ParseFailure):
        source_id = uuid4()
        diagnostics = tuple(
            ComponentLimitation(
                code=issue.code,
                message=issue.message
                + (
                    "\nИсточник: " + issue.source_location.model_dump_json()
                    if issue.source_location is not None
                    else ""
                ),
            )
            for issue in (*revision.errors, *revision.warnings)
        )
        return AnalysisResult(
            application_version=__version__,
            started_at=imported_at,
            finished_at=imported_at,
            sources=(
                AnalysisSource(
                    source_document_id=source_id,
                    source_name=source.source_name,
                    content_sha256=source.content_sha256,
                    hash_basis="raw_file",
                    source_kind=SourceDocumentKind.CONFIGURATION,
                    captured_at=source.captured_at,
                    file_modified_at=source.file_modified_at,
                    observation=source.observation,
                ),
            ),
            components=(
                AttemptComponent(
                    component_id="policy",
                    family="policy",
                    operation="Разбор конфигурации",
                    state="failed",
                    diagnostic=diagnostics[0],
                    limitations=diagnostics,
                    source_ids=(source_id,),
                ),
            ),
        )
    report = analyze_firewall(
        revision,
        require_logging=require_logging,
        require_comments=require_comments,
        management_profile=management_profile,
        extended_policy_checks=extended_policy_checks,
        policy_exposure_profile=policy_exposure_profile,
    )
    options = PolicyAnalysisOptions(
        check_ids=tuple(check.check_id for check in report.checks),
        require_logging=report.require_logging,
        require_comments=report.require_comments,
        max_pair_rules=report.max_pair_rules,
        management_profile=management_profile or ManagementProfile(),
        exposure_profile=policy_exposure_profile or PolicyExposureProfile(),
    )
    return AnalysisResult(
        application_version=__version__,
        started_at=imported_at,
        finished_at=report.analyzed_at,
        sources=source_manifest((revision,)),
        components=(
            PolicyComponent(
                component_id="policy",
                revision=revision,
                options=options,
                result=report,
            ),
        ),
    )
