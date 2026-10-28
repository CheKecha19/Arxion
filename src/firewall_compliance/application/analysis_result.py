"""Immutable, replay-validated analysis bundles without desktop, file or network I/O."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from hashlib import sha256
from typing import Annotated, Any, Literal, Self
from uuid import UUID, uuid4

from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    SerializerFunctionWrapHandler,
    StringConstraints,
    model_serializer,
    model_validator,
)

from firewall_compliance.analysis.device_decision import (
    analyze_device_decisions,
    evaluate_interface,
)
from firewall_compliance.analysis.firewall_assurance import analyze_firewall
from firewall_compliance.analysis.forwarding_policy import evaluate_forwarding_policy
from firewall_compliance.analysis.management_checks import management_checks
from firewall_compliance.analysis.policy_checks import (
    AnyAnyCheck,
    CommentsCheck,
    DisabledRulesCheck,
    DuplicateRulesCheck,
    LoggingCheck,
    MergeCandidateCheck,
    PartialShadowedRulesCheck,
    PolicyCheck,
    ShadowedRulesCheck,
    UnionShadowedRulesCheck,
)
from firewall_compliance.analysis.policy_decision import evaluate_policy
from firewall_compliance.analysis.policy_exposure import (
    DangerousServicesCheck,
    UntrustedAdministrativeAccessCheck,
)
from firewall_compliance.analysis.policy_governance import (
    RuleGovernanceCheck,
    UnusedRuleCandidatesCheck,
)
from firewall_compliance.analysis.revision_diff import compare_device_revisions
from firewall_compliance.analysis.route_selection import analyze_reachability, select_route
from firewall_compliance.application.device_decision import analyze_imported_device
from firewall_compliance.application.forwarding_binding import ForwardingBindingResult
from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.enums import FindingStatus, SourceDocumentKind
from firewall_compliance.domain.forwarding import FlowApplicability, ForwardingContext
from firewall_compliance.domain.forwarding_policy import ForwardingPolicyResult
from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.domain.observation import ObservationEvidence
from firewall_compliance.domain.policy_decision import (
    InterfaceDecisionResult,
    PolicyBindingEvidence,
    PolicyDecisionResult,
    SingleDeviceDecisionResult,
)
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.domain.policy_governance import (
    PolicyGovernanceInputs,
    PolicyGovernanceProfile,
)
from firewall_compliance.domain.policy_matching import ScopeKey
from firewall_compliance.domain.reachability import (
    ReachabilityQuery,
    ReachabilityResult,
    RouteSelectionResult,
)
from firewall_compliance.domain.revision import DeviceRevision, DeviceRevisionDiff
from firewall_compliance.domain.snapshot import freeze_snapshot_fields
from firewall_compliance.parsers.forwarding_contracts import ForwardingParseResult

ExecutionState = Literal["complete", "partial", "failed", "cancelled", "not_executed"]


def _plain(value: Any) -> Any:
    if isinstance(value, DomainModel):
        return value.model_dump(mode="python")
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


class ResultModel(DomainModel):
    """Ordinary construction, JSON and model_copy all validate and freeze the complete graph."""

    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    @model_validator(mode="before")
    @classmethod
    def revalidate_nested(cls, value: Any) -> Any:
        return _plain(value)

    @model_validator(mode="after")
    def freeze(self) -> Self:
        freeze_snapshot_fields(self)
        return self

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        payload = self.model_dump(mode="python")
        payload.update(update or {})
        return self.__class__.model_validate(payload)


def canonical_api_sha256(record: Mapping[str, JsonValue]) -> str:
    """Cloud VMware canonical record basis: sorted UTF-8 JSON with standard separators."""
    return sha256(
        json.dumps(
            dict(record),
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


class AnalysisSource(ResultModel):
    source_document_id: UUID
    source_name: str = Field(min_length=1)
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    hash_basis: Literal["raw_file", "canonical_api_record"]
    canonical_api_record: dict[str, JsonValue] | None = None
    source_kind: SourceDocumentKind | None = None
    captured_at: datetime | None = None
    file_modified_at: datetime | None = None
    observation: ObservationEvidence | None = None

    @model_validator(mode="after")
    def verify_digest_basis(self) -> Self:
        if any(
            value is not None and value.tzinfo is None
            for value in (
                self.captured_at,
                self.file_modified_at,
            )
        ):
            raise ValueError("source timestamps require timezone")
        if (
            self.observation is not None
            and self.captured_at is not None
            and (self.observation.observed_at > self.captured_at)
        ):
            raise ValueError("source observation cannot follow its capture")
        if self.hash_basis == "canonical_api_record":
            if self.canonical_api_record is None or (
                canonical_api_sha256(self.canonical_api_record) != self.content_sha256
            ):
                raise ValueError("canonical API source requires matching canonical record SHA-256")
        elif self.canonical_api_record is not None:
            raise ValueError("raw file source cannot be relabelled with a canonical API record")
        return self


class ComponentLimitation(ResultModel):
    code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=16384)


class PolicyAnalysisOptions(ResultModel):
    check_ids: tuple[str, ...] = Field(max_length=128)
    require_logging: bool = Field(default=True, strict=True)
    require_comments: bool = Field(default=True, strict=True)
    max_pair_rules: int = Field(default=1000, ge=1, strict=True)
    management_profile: ManagementProfile = Field(default_factory=ManagementProfile)
    exposure_profile: PolicyExposureProfile = Field(default_factory=PolicyExposureProfile)
    exposure_max_operations: int = Field(default=100000, ge=1, le=10000000, strict=True)
    union_complete_scopes: tuple[ScopeKey, ...] | None = None
    union_max_fragments: int = Field(default=4096, ge=1, strict=True)
    union_max_operations: int = Field(default=200000, ge=1, strict=True)
    governance_profile: PolicyGovernanceProfile | None = None
    governance_inputs: PolicyGovernanceInputs | None = None
    governance_max_operations: int | None = Field(default=None, ge=1, le=10000000, strict=True)

    @model_serializer(mode="wrap")
    def serialize_governance(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        for name in ("governance_profile", "governance_inputs", "governance_max_operations"):
            if getattr(self, name) is None:
                payload.pop(name, None)
        return payload

    @model_validator(mode="after")
    def unique_checks(self) -> Self:
        if len(set(self.check_ids)) != len(self.check_ids):
            raise ValueError("requested check IDs must be unique")
        return self


def replay_policy(
    revision: DeviceRevision,
    options: PolicyAnalysisOptions,
    analyzed_at: datetime,
    *,
    check_versions: Mapping[str, str] | None = None,
) -> FirewallAssuranceResult:
    """Explicit catalogue selection preserves selected options rather than future defaults."""

    def evidence_version(check_id: str) -> Literal["1.0.0", "1.1.0"]:
        version = check_versions.get(check_id, "1.1.0") if check_versions is not None else "1.1.0"
        if version not in {"1.0.0", "1.1.0"}:
            raise ValueError("unsupported policy evidence version")
        return "1.0.0" if version == "1.0.0" else "1.1.0"

    checks: tuple[PolicyCheck, ...] = (
        AnyAnyCheck(),
        DuplicateRulesCheck(),
        ShadowedRulesCheck(),
        MergeCandidateCheck(),
        LoggingCheck(),
        CommentsCheck(),
        DisabledRulesCheck(),
        *management_checks(options.management_profile),
        DangerousServicesCheck(
            options.exposure_profile,
            max_operations=options.exposure_max_operations,
            evidence_version=evidence_version("FW-DANGEROUS-SERVICES"),
        ),
        UntrustedAdministrativeAccessCheck(
            options.exposure_profile,
            max_operations=options.exposure_max_operations,
            evidence_version=evidence_version("FW-ADMIN-UNTRUSTED"),
        ),
        PartialShadowedRulesCheck(
            complete_scopes=frozenset(options.union_complete_scopes)
            if options.union_complete_scopes is not None
            else None,
            max_fragments=options.union_max_fragments,
            max_operations=options.union_max_operations,
            evidence_version=evidence_version("FW-PARTIAL-SHADOWED"),
        ),
        UnionShadowedRulesCheck(
            complete_scopes=frozenset(options.union_complete_scopes)
            if options.union_complete_scopes is not None
            else None,
            max_fragments=options.union_max_fragments,
            max_operations=options.union_max_operations,
            evidence_version=evidence_version("FW-UNION-SHADOWED"),
        ),
        RuleGovernanceCheck(
            options.governance_profile,
            options.governance_inputs,
            max_operations=options.governance_max_operations or 100000,
        ),
        UnusedRuleCandidatesCheck(
            options.governance_profile,
            options.governance_inputs,
            max_operations=options.governance_max_operations or 100000,
        ),
    )
    catalog = {check.check_id: check for check in checks}
    if set(options.check_ids) - catalog.keys():
        raise ValueError("policy result catalogue is not supported by this replay engine")
    return analyze_firewall(
        revision,
        analyzed_at=analyzed_at,
        require_logging=options.require_logging,
        require_comments=options.require_comments,
        max_pair_rules=options.max_pair_rules,
        checks=tuple(catalog[key] for key in options.check_ids),
        management_profile=options.management_profile,
    )


class _Component(ResultModel):
    component_id: str = Field(min_length=1, max_length=256)
    limitations: tuple[ComponentLimitation, ...] = ()


class PolicyComponent(_Component):
    kind: Literal["policy"] = "policy"
    revision: DeviceRevision
    options: PolicyAnalysisOptions
    result: FirewallAssuranceResult

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        expected = replay_policy(
            self.revision,
            self.options,
            self.result.analyzed_at,
            check_versions={check.check_id: check.check_version for check in self.result.checks},
        )
        # Evidence facts are JSON values: a saved array must compare identically
        # with an engine tuple while boolean/number substitutions remain distinct.
        expected_json = json.dumps(
            expected.model_dump(mode="json"), sort_keys=True, allow_nan=False
        )
        result_json = json.dumps(
            self.result.model_dump(mode="json"), sort_keys=True, allow_nan=False
        )
        if expected_json != result_json:
            raise ValueError("policy report does not replay from its revision/options/versions")
        return self


class _NetworkComponent(_Component):
    revision: DeviceRevision
    imported: NetworkImportResult | None = None

    @model_validator(mode="after")
    def validate_import_snapshot(self) -> Self:
        _validate_import_snapshot(self.revision, self.imported)
        return self


def _validate_import_snapshot(
    revision: DeviceRevision, imported: NetworkImportResult | None
) -> None:
    configuration = revision.parse_result.configuration
    supplemental = {
        source.source_document_id
        for source in revision.sources
        if (source.source_name, source.content_sha256.lower())
        != (
            configuration.source_name,
            configuration.content_sha256.lower(),
        )
    }
    if imported is None:
        if supplemental:
            raise ValueError("supplemental network sources require their full import documents")
        return
    if imported.revision != revision:
        raise ValueError("network import snapshot must be retained whole for this exact revision")
    document_ids = [document.source.source_document_id for document in imported.documents]
    if len(set(document_ids)) != len(document_ids) or not supplemental <= set(document_ids):
        raise ValueError("network import documents are missing or duplicated")


def _query_matches(revision: DeviceRevision, query: ReachabilityQuery) -> None:
    if (query.revision_id, query.device_id, query.device_context) != (
        revision.revision_id,
        revision.device.device_id,
        revision.device.context,
    ):
        raise ValueError("query belongs to another revision/device/context")


class RouteComponent(_NetworkComponent):
    kind: Literal["route"] = "route"
    query: ReachabilityQuery
    result: RouteSelectionResult

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        _query_matches(self.revision, self.query)
        if select_route(self.revision, self.query) != self.result:
            raise ValueError("route result does not replay from its exact snapshot/query")
        return self


class ReachabilityComponent(_NetworkComponent):
    kind: Literal["reachability"] = "reachability"
    query: ReachabilityQuery
    result: ReachabilityResult

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        _query_matches(self.revision, self.query)
        if analyze_reachability(self.revision, self.query) != self.result:
            raise ValueError("reachability result does not replay from its exact snapshot/query")
        return self


class InterfaceComponent(_NetworkComponent):
    kind: Literal["interface"] = "interface"
    interface_id: str = Field(min_length=1)
    result: InterfaceDecisionResult

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if evaluate_interface(self.revision, self.interface_id) != self.result:
            raise ValueError("interface decision does not replay from its exact snapshot")
        return self


class PolicyDecisionComponent(_NetworkComponent):
    kind: Literal["policy_decision"] = "policy_decision"
    query: ReachabilityQuery
    binding: PolicyBindingEvidence
    result: PolicyDecisionResult

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        _query_matches(self.revision, self.query)
        if evaluate_policy(self.revision, self.query, self.binding) != self.result:
            raise ValueError("policy decision does not replay from revision/query/binding")
        return self


class DeviceDecisionComponent(_NetworkComponent):
    kind: Literal["device_decision"] = "device_decision"
    query: ReachabilityQuery
    binding: PolicyBindingEvidence
    result: SingleDeviceDecisionResult

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        _query_matches(self.revision, self.query)
        expected = (
            analyze_imported_device(self.imported, self.query, self.binding)
            if self.imported is not None
            else analyze_device_decisions(self.revision, self.query, self.binding)
        )
        if expected != self.result:
            raise ValueError(
                "device decision does not replay from its whole snapshot/query/binding"
            )
        return self


class ForwardingComponent(_NetworkComponent):
    kind: Literal["forwarding"] = "forwarding"
    query: ReachabilityQuery
    profile_id: Literal["asa-9.16-single-routed-ipv4-data-default"]
    flow: FlowApplicability
    context: ForwardingContext
    parsed: ForwardingParseResult | None = None
    binding: ForwardingBindingResult | None = None
    ingress_interface_id: str = Field(min_length=1)
    egress_interface_id: str = Field(min_length=1)
    egress_basis: Literal["caller_supplied_conditional"] = "caller_supplied_conditional"
    result: ForwardingPolicyResult

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        _query_matches(self.revision, self.query)
        context = self.context
        if (
            (
                context.revision_id,
                context.configuration_id,
                context.device_id,
                context.device_context,
                context.imported_at,
            )
            != (
                self.revision.revision_id,
                self.revision.parse_result.configuration.configuration_id,
                self.revision.device.device_id,
                self.revision.device.context,
                self.revision.imported_at,
            )
            or context.flow != self.flow
            or self.flow.query != self.query
        ):
            raise ValueError("forwarding context/flow/query identity is inconsistent")
        if self.ingress_interface_id != self.query.ingress_interface_id:
            raise ValueError("forwarding ingress differs from query")
        if (self.revision.device.vendor, self.revision.device.platform) != ("cisco", "asa-9.16"):
            raise ValueError("forwarding profile is not supported for this device")
        for key, value in (
            ("context_mode", "single"),
            ("firewall_mode", "routed"),
            ("address_family", "ipv4"),
            ("table_role", "data"),
            ("table_id", "default"),
        ):
            if getattr(context, key) != value:
                raise ValueError("forwarding profile is unknown or unsupported")
        originals = {source.source_document_id: source for source in self.revision.sources}
        for source in context.sources:
            original = originals.get(source.source_document_id)
            if original is None or (
                source.source_name,
                source.content_sha256,
                source.captured_at,
                source.observation,
            ) != (
                original.source_name,
                original.content_sha256,
                original.captured_at,
                original.observation,
            ):
                raise ValueError("forwarding source anchors differ from revision")
        original_context = (
            self.parsed.context
            if self.parsed is not None
            else self.binding.forwarding.context
            if self.binding is not None
            else context
        )
        if original_context.model_copy(update={"flow": self.flow}) != context:
            raise ValueError("only the explicitly selected flow may differ from original context")
        if self.binding is not None and (
            self.imported is None
            or self.binding.imported != self.imported
            or self.parsed is not None
            and self.binding.forwarding
            not in (
                self.parsed,
                self.parsed.model_copy(
                    update={"context": self.parsed.context.model_copy(update={"flow": self.flow})}
                ),
            )
        ):
            raise ValueError("forwarding binding/parsed/imported snapshots disagree")
        if (
            evaluate_forwarding_policy(
                context,
                ingress_interface_id=self.ingress_interface_id,
                egress_interface_id=self.egress_interface_id,
            )
            != self.result
        ):
            raise ValueError("forwarding result does not replay from its exact declared inputs")
        return self


class RevisionDiffComponent(_Component):
    kind: Literal["revision_diff"] = "revision_diff"
    before: DeviceRevision
    after: DeviceRevision
    result: DeviceRevisionDiff

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.result.schema_version != "2.0.0":
            raise ValueError("legacy structural diff cannot be relabelled evidence-aware")
        if compare_device_revisions(self.before, self.after) != self.result:
            raise ValueError("revision diff does not replay from both exact snapshots")
        return self


class AttemptComponent(_Component):
    """Explicit unsuccessful/unexecuted operation; never an empty successful report."""

    kind: Literal["attempt"] = "attempt"
    family: Literal["policy", "network", "revision_diff"]
    operation: str = Field(min_length=1)
    state: Literal["failed", "cancelled", "not_executed"]
    diagnostic: ComponentLimitation
    revision: DeviceRevision | None = None
    imported: NetworkImportResult | None = None
    query: ReachabilityQuery | None = None
    flow: FlowApplicability | None = None
    profile_id: str | None = None
    policy_binding: PolicyBindingEvidence | None = None
    forwarding_context: ForwardingContext | None = None
    source_ids: tuple[UUID, ...] = ()

    @model_validator(mode="after")
    def validate_retained_inputs(self) -> Self:
        revision = self.revision or (self.imported.revision if self.imported else None)
        if (
            self.imported is not None
            and self.revision is not None
            and (self.imported.revision != self.revision)
        ):
            raise ValueError("attempt imported snapshot belongs to another revision")
        if self.imported is not None:
            _validate_import_snapshot(self.imported.revision, self.imported)
        if self.query is not None:
            if revision is None:
                raise ValueError("attempt query requires its retained revision")
            _query_matches(revision, self.query)
        if self.flow is not None and (self.query is None or self.flow.query != self.query):
            raise ValueError("attempt flow requires the same retained query")
        if self.forwarding_context is not None:
            context = self.forwarding_context
            if revision is None or (
                context.revision_id,
                context.configuration_id,
                context.device_id,
                context.device_context,
                context.imported_at,
            ) != (
                revision.revision_id,
                revision.parse_result.configuration.configuration_id,
                revision.device.device_id,
                revision.device.context,
                revision.imported_at,
            ):
                raise ValueError("attempt forwarding context belongs to another revision")
            if context.flow is not None and context.flow != self.flow:
                raise ValueError("attempt forwarding flow differs from retained flow")
        if self.policy_binding is not None and (
            revision is None
            or self.policy_binding.source_document_id
            not in {source.source_document_id for source in revision.sources}
        ):
            raise ValueError("attempt binding requires its exact source revision")
        return self


type AnalysisComponent = Annotated[
    PolicyComponent
    | RouteComponent
    | ReachabilityComponent
    | InterfaceComponent
    | PolicyDecisionComponent
    | DeviceDecisionComponent
    | ForwardingComponent
    | RevisionDiffComponent
    | AttemptComponent,
    Field(discriminator="kind"),
]


class FindingDecision(ResultModel):
    component_id: str = Field(min_length=1)
    finding_id: UUID
    status: FindingStatus
    comment: Annotated[str, StringConstraints(strip_whitespace=False)] = Field(
        default="", max_length=16384
    )
    decided_at: datetime
    actor_reference: str | None = None

    @model_validator(mode="after")
    def aware_time(self) -> Self:
        if self.decided_at.tzinfo is None:
            raise ValueError("decision time requires timezone")
        return self


class AnalysisSummary(ResultModel):
    components: int = Field(ge=0)
    complete_components: int = Field(ge=0)
    partial_components: int = Field(ge=0)
    failed_components: int = Field(ge=0)
    cancelled_components: int = Field(ge=0)
    not_executed_components: int = Field(ge=0)
    checks_executed: int = Field(ge=0)
    findings: int = Field(ge=0)
    network_results: int = Field(ge=0)
    semantic_changes: int = Field(ge=0)
    provenance_changes: int = Field(ge=0)
    normalization_changes: int = Field(ge=0)
    completeness_changes: int = Field(ge=0)


def component_state(component: AnalysisComponent) -> ExecutionState:
    if isinstance(component, AttemptComponent):
        return component.state
    if component.limitations:
        return "partial"
    if isinstance(component, PolicyComponent):
        if not component.result.checks or all(
            any(limit.code == "CHECK_NOT_EXECUTED" for limit in check.limitations)
            for check in component.result.checks
        ):
            return "not_executed"
        return (
            "partial"
            if any(check.status.value == "partial" for check in component.result.checks)
            or component.result.parse_errors
            or component.result.parse_warnings
            or (component.result.unsupported_constructs)
            else "complete"
        )
    if isinstance(component, RevisionDiffComponent):
        return (
            "partial"
            if component.result.limitations or component.result.completeness_changes
            else "complete"
        )
    if isinstance(component, InterfaceComponent):
        return "partial" if component.result.status == "unknown" else "complete"
    return (
        "partial" if component.result.status in {"unknown", "not_enough_evidence"} else "complete"
    )


def component_revisions(component: AnalysisComponent) -> tuple[DeviceRevision, ...]:
    if isinstance(component, RevisionDiffComponent):
        return component.before, component.after
    values = (component.revision,) if component.revision is not None else ()
    if isinstance(component, AttemptComponent) and component.imported is not None:
        return (*values, component.imported.revision)
    return values


def _summary(components: tuple[AnalysisComponent, ...]) -> tuple[ExecutionState, AnalysisSummary]:
    states = [component_state(component) for component in components]
    all_states: tuple[ExecutionState, ...] = (
        "complete",
        "partial",
        "failed",
        "cancelled",
        "not_executed",
    )
    counts = {state: states.count(state) for state in all_states}
    state: ExecutionState = (
        "not_executed" if not states else states[0] if len(set(states)) == 1 else "partial"
    )
    policies = [component for component in components if isinstance(component, PolicyComponent)]
    diffs = [
        component.result for component in components if isinstance(component, RevisionDiffComponent)
    ]
    return state, AnalysisSummary(
        components=len(components),
        complete_components=counts["complete"],
        partial_components=counts["partial"],
        failed_components=counts["failed"],
        cancelled_components=counts["cancelled"],
        not_executed_components=counts["not_executed"],
        checks_executed=sum(
            not any(limit.code == "CHECK_NOT_EXECUTED" for limit in check.limitations)
            and check.status.value != "not_applicable"
            for component in policies
            for check in component.result.checks
        ),
        findings=sum(
            len(check.findings) for component in policies for check in component.result.checks
        ),
        network_results=sum(isinstance(component, _NetworkComponent) for component in components),
        semantic_changes=sum(len(diff.changes) for diff in diffs),
        provenance_changes=sum(len(diff.provenance_changes) for diff in diffs),
        normalization_changes=sum(len(diff.normalization_changes) for diff in diffs),
        completeness_changes=sum(len(diff.completeness_changes) for diff in diffs),
    )


class AnalysisResult(ResultModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    analysis_id: UUID = Field(default_factory=uuid4)
    application_version: str = Field(min_length=1)
    started_at: datetime
    finished_at: datetime
    project_reference: str | None = None
    run_reference: str | None = None
    sources: tuple[AnalysisSource, ...] = Field(default=(), max_length=10000)
    components: tuple[AnalysisComponent, ...] = Field(default=(), max_length=10000)
    decisions: tuple[FindingDecision, ...] = ()
    limitations: tuple[ComponentLimitation, ...] = ()
    state: ExecutionState | None = None
    summary: AnalysisSummary | None = None

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        if (
            self.started_at.tzinfo is None
            or self.finished_at.tzinfo is None
            or (self.finished_at < self.started_at)
        ):
            raise ValueError("analysis interval requires ordered timezone-aware times")
        ids = [component.component_id for component in self.components]
        if len(set(ids)) != len(ids):
            raise ValueError("component IDs must be unique in an analysis")
        manifest = {source.source_document_id: source for source in self.sources}
        if len(manifest) != len(self.sources):
            raise ValueError("source manifest IDs must be unique")
        required: set[UUID] = set()
        findings: dict[tuple[str, UUID], datetime] = {}
        for component in self.components:
            for revision in component_revisions(component):
                if revision.imported_at > self.finished_at:
                    raise ValueError("revision import cannot follow analysis completion")
                for source in revision.sources:
                    required.add(source.source_document_id)
                    supplied = manifest.get(source.source_document_id)
                    if supplied is None or (
                        supplied.source_name,
                        supplied.content_sha256.lower(),
                    ) != (
                        source.source_name,
                        source.content_sha256.lower(),
                    ):
                        raise ValueError("source manifest does not match the retained revision")
                    for name in ("captured_at", "file_modified_at", "observation"):
                        metadata = getattr(supplied, name)
                        if metadata is not None and metadata != getattr(source, name):
                            raise ValueError(
                                "source manifest capture metadata contradicts snapshot"
                            )
                    if supplied.source_kind is not None and supplied.source_kind != source.kind:
                        raise ValueError("source manifest kind contradicts snapshot")
                    if revision.device.platform == "cloud-ru-vmware-nsxt" and (
                        supplied.hash_basis != "canonical_api_record"
                    ):
                        raise ValueError(
                            "VMware adapter source hash is a canonical API record hash"
                        )
            if isinstance(component, PolicyComponent):
                timestamp = component.result.analyzed_at
                if not self.started_at <= timestamp <= self.finished_at:
                    raise ValueError("policy analysis time is outside the operation interval")
                for check in component.result.checks:
                    for finding in check.findings:
                        key = component.component_id, finding.finding_id
                        if key in findings:
                            raise ValueError("finding IDs must be unique within a component")
                        findings[key] = timestamp
            if isinstance(component, AttemptComponent):
                required.update(component.source_ids)
                if not set(component.source_ids) <= manifest.keys():
                    raise ValueError("attempt references an unknown source")
        if required != manifest.keys():
            raise ValueError("source manifest contains missing or unreferenced source entries")
        seen: set[tuple[str, UUID]] = set()
        for decision in self.decisions:
            key = decision.component_id, decision.finding_id
            if key not in findings or key in seen:
                raise ValueError("decision must identify exactly one existing finding")
            if decision.decided_at < findings[key]:
                raise ValueError("decision cannot precede the finding analysis")
            seen.add(key)
        state, summary = _summary(self.components)
        if self.limitations and state == "complete":
            state = "partial"
        if self.state is not None and self.state != state:
            raise ValueError("analysis state contradicts actual component execution")
        if self.summary is not None and self.summary != summary:
            raise ValueError("analysis summary contradicts component results")
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "summary", summary)
        return self

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        payload = self.model_dump(mode="python")
        supplied = update or {}
        if "state" not in supplied:
            payload.pop("state", None)
        if "summary" not in supplied:
            payload.pop("summary", None)
        payload.update(supplied)
        return self.__class__.model_validate(payload)


def source_manifest(
    revisions: tuple[DeviceRevision, ...],
    *,
    api_records: Mapping[UUID, Mapping[str, JsonValue]] | None = None,
) -> tuple[AnalysisSource, ...]:
    """Build provenance from explicit caller-selected digest bases, without opening sources."""
    sources: dict[UUID, AnalysisSource] = {}
    for revision in revisions:
        for source in revision.sources:
            record = (api_records or {}).get(source.source_document_id)
            if revision.device.platform == "cloud-ru-vmware-nsxt" and record is None:
                raise ValueError("VMware source requires its retained canonical API record")
            value = AnalysisSource(
                source_document_id=source.source_document_id,
                source_name=source.source_name,
                content_sha256=source.content_sha256.lower(),
                hash_basis="canonical_api_record" if record is not None else "raw_file",
                canonical_api_record=dict(record) if record is not None else None,
                source_kind=source.kind,
                captured_at=source.captured_at,
                file_modified_at=source.file_modified_at,
                observation=source.observation,
            )
            if source.source_document_id in sources and sources[source.source_document_id] != value:
                raise ValueError("same source UUID carries conflicting provenance")
            sources[source.source_document_id] = value
    return tuple(sources.values())
