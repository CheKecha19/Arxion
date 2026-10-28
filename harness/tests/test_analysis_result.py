"""Mixed, immutable analysis exports and source/query replay invariants."""

import csv
import io
import json
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

import pytest
from pydantic import ValidationError
from test_policy_exposure import AT, context, profile, rule

from firewall_compliance.analysis.device_decision import (
    analyze_device_decisions,
    evaluate_interface,
)
from firewall_compliance.analysis.forwarding_policy import evaluate_forwarding_policy
from firewall_compliance.analysis.policy_decision import evaluate_policy
from firewall_compliance.analysis.revision_diff import compare_device_revisions
from firewall_compliance.analysis.route_selection import analyze_reachability, select_route
from firewall_compliance.application import analysis_result as result_module
from firewall_compliance.application.analysis_reports import (
    export_analysis_csv,
    export_analysis_html,
    export_analysis_json,
)
from firewall_compliance.application.analysis_result import (
    AnalysisResult,
    AnalysisSource,
    AttemptComponent,
    ComponentLimitation,
    DeviceDecisionComponent,
    FindingDecision,
    ForwardingComponent,
    InterfaceComponent,
    PolicyAnalysisOptions,
    PolicyComponent,
    PolicyDecisionComponent,
    ReachabilityComponent,
    RevisionDiffComponent,
    RouteComponent,
    canonical_api_sha256,
    component_revisions,
    replay_policy,
    source_manifest,
)
from firewall_compliance.application.network_import import import_network_documents
from firewall_compliance.domain import DeviceRevision, Protocol, SourceLocation
from firewall_compliance.domain.enums import FindingStatus
from firewall_compliance.domain.forwarding import FlowApplicability, ForwardingContext
from firewall_compliance.domain.policy_decision import PolicyBindingEvidence
from firewall_compliance.domain.reachability import ReachabilityQuery
from firewall_compliance.parsers.contracts import SourceDocument
from firewall_compliance.parsers.network_contracts import (
    NetworkDocumentMetadata,
    NetworkParseRequest,
)


def policy():
    revision = context(rule()).revision
    options = PolicyAnalysisOptions(
        check_ids=("FW-DANGEROUS-SERVICES",), exposure_profile=profile()
    )
    return PolicyComponent(
        component_id="policy",
        revision=revision,
        options=options,
        result=replay_policy(revision, options, AT),
    )


def query(revision):
    return ReachabilityQuery(
        revision_id=revision.revision_id,
        device_id=revision.device.device_id,
        ingress_interface_id="inside",
        source_ip="198.51.100.1",
        destination_ip="192.0.2.1",
        protocol=Protocol.TCP,
        destination_port=23,
    )


def binding(revision):
    return PolicyBindingEvidence(
        policy_id="synthetic-policy",
        direction="in",
        interface_id="inside",
        interface_label="inside",
        interface_mapping_reference="Synthetic explicit mapping",
        source_document_id=revision.sources[0].source_document_id,
        binding_location=SourceLocation(source_name="synthetic", object_path="$.bindings[0]"),
        declaration_origin="synthetic",
        coordinate_space="acl_input",
    )


def bundle(*components, **changes):
    revisions = tuple(
        revision for component in components for revision in component_revisions(component)
    )
    values = dict(
        application_version="0.4.0",
        started_at=AT,
        finished_at=AT + timedelta(seconds=2),
        components=components,
        sources=source_manifest(revisions),
    )
    values.update(changes)
    return AnalysisResult(**values)


def network_components(revision):
    request, bind = query(revision), binding(revision)
    return (
        RouteComponent(
            component_id="route",
            revision=revision,
            query=request,
            result=select_route(revision, request),
        ),
        ReachabilityComponent(
            component_id="reachability",
            revision=revision,
            query=request,
            result=analyze_reachability(revision, request),
        ),
        InterfaceComponent(
            component_id="interface",
            revision=revision,
            interface_id="inside",
            result=evaluate_interface(revision, "inside"),
        ),
        PolicyDecisionComponent(
            component_id="policy-decision",
            revision=revision,
            query=request,
            binding=bind,
            result=evaluate_policy(revision, request, bind),
        ),
        DeviceDecisionComponent(
            component_id="device-decision",
            revision=revision,
            query=request,
            binding=bind,
            result=analyze_device_decisions(revision, request, bind),
        ),
    )


def test_mixed_bundle_roundtrip_retains_all_families_and_truthful_summary():
    component = policy()
    revision = component.revision
    later = revision.model_copy(update={"revision_id": uuid4()})
    diff = RevisionDiffComponent(
        component_id="diff",
        before=revision,
        after=later,
        result=compare_device_revisions(revision, later),
    )
    result = bundle(component, *network_components(revision), diff)
    reopened = AnalysisResult.model_validate_json(export_analysis_json(result))
    assert reopened == result
    assert reopened.state == "partial" and reopened.summary.components == 7
    assert reopened.summary.findings == 1 and reopened.summary.checks_executed == 1
    assert reopened.summary.network_results == 5
    assert {value.kind for value in reopened.components} == {
        "policy",
        "route",
        "reachability",
        "interface",
        "policy_decision",
        "device_decision",
        "revision_diff",
    }


def test_deep_inputs_and_decisions_are_separate_immutable_snapshots():
    component = policy()
    finding = component.result.checks[0].findings[0]
    decision = FindingDecision(
        component_id="policy",
        finding_id=finding.finding_id,
        status=FindingStatus.CONFIRMED,
        comment="Reviewed independently",
        decided_at=AT + timedelta(days=1),
    )
    result = bundle(component, decisions=(decision,))
    assert result.components[0].result.checks[0].findings[0].status == FindingStatus.NEW
    assert result.decisions[0].status == FindingStatus.CONFIRMED
    with pytest.raises((TypeError, ValidationError)):
        result.components[0].revision.parse_result.configuration.vendor = "tampered"
    with pytest.raises(TypeError):
        result.components[0].result.checks[0].findings[0].evidence.facts["basis"] = "tampered"
    with pytest.raises((TypeError, ValidationError)):
        result.decisions[0].comment = "tampered"
    assert AnalysisResult.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize(
    "field,value",
    [
        ("device_id", "another"),
        ("revision_id", str(uuid4())),
        ("application_version", "not-the-revision-version"),
    ],
)
def test_policy_report_identity_and_version_tampering_is_rejected(field, value):
    payload = policy().model_dump(mode="json")
    payload["result"][field] = value
    with pytest.raises(ValidationError):
        PolicyComponent.model_validate(payload)


def test_policy_report_finding_and_option_tampering_is_rejected():
    original = policy().model_dump(mode="json")
    for mutate in (
        lambda payload: payload["result"]["checks"][0].update(findings=[]),
        lambda payload: payload["options"].update(require_logging=False),
        lambda payload: payload["options"].update(check_ids=["FW-UNKNOWN-ENGINE"]),
    ):
        payload = json.loads(json.dumps(original))
        mutate(payload)
        with pytest.raises(ValidationError):
            PolicyComponent.model_validate(payload)


def test_source_digest_and_references_cannot_be_detached_from_revision():
    payload = bundle(policy()).model_dump(mode="json")
    payload["sources"][0]["content_sha256"] = "b" * 64
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(payload)
    payload = bundle(policy()).model_dump(mode="json")
    payload["sources"] = []
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(payload)
    payload = bundle(policy()).model_dump(mode="json")
    extra = dict(payload["sources"][0], source_document_id=str(uuid4()))
    payload["sources"].append(extra)
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(payload)


def test_canonical_api_digest_basis_is_distinct_and_recomputed():
    record = {"id": "synthetic-api", "rules": [{"name": "Unicode имя", "action": "ALLOW"}]}
    digest = canonical_api_sha256(record)
    assert (
        digest
        == sha256(json.dumps(record, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    )
    source = AnalysisSource(
        source_document_id=uuid4(),
        source_name="API synthetic",
        content_sha256=digest,
        hash_basis="canonical_api_record",
        canonical_api_record=record,
    )
    assert AnalysisSource.model_validate_json(source.model_dump_json()) == source
    payload = source.model_dump(mode="json")
    payload["canonical_api_record"]["id"] = "tampered"
    with pytest.raises(ValidationError):
        AnalysisSource.model_validate(payload)
    with pytest.raises(ValidationError):
        source.model_copy(update={"hash_basis": "raw_file"})
    with pytest.raises(ValueError):
        canonical_api_sha256({"not_json": float("nan")})


def test_query_and_result_tampering_cannot_reuse_original_network_answer():
    revision = policy().revision
    for component in network_components(revision):
        payload = component.model_dump(mode="json")
        if component.kind == "interface":
            payload["interface_id"] = "another"
        else:
            payload["query"]["destination_ip"] = "203.0.113.5"
        with pytest.raises(ValidationError):
            type(component).model_validate(payload)
    route = network_components(revision)[0]
    bad_query = route.query.model_copy(update={"revision_id": uuid4()})
    with pytest.raises(ValidationError):
        route.model_copy(update={"query": bad_query})


def test_revision_diff_requires_both_snapshots_and_current_semantics():
    revision = policy().revision
    later = revision.model_copy(update={"revision_id": uuid4()})
    component = RevisionDiffComponent(
        component_id="diff",
        before=revision,
        after=later,
        result=compare_device_revisions(revision, later),
    )
    payload = component.model_dump(mode="json")
    payload["after"]["revision_id"] = str(uuid4())
    with pytest.raises(ValidationError):
        RevisionDiffComponent.model_validate(payload)
    payload = component.model_dump(mode="json")
    payload["result"].update(
        schema_version=None,
        provenance_changes=[],
        normalization_changes=[],
        completeness_changes=[],
    )
    with pytest.raises(ValidationError):
        RevisionDiffComponent.model_validate(payload)


@pytest.mark.parametrize("state", ["failed", "cancelled", "not_executed"])
def test_explicit_unsuccessful_attempt_is_never_empty_success(state):
    component = AttemptComponent(
        component_id="attempt",
        family="network",
        operation="route",
        state=state,
        diagnostic=ComponentLimitation(code="synthetic", message="No result produced"),
    )
    result = bundle(component)
    assert result.state == state and result.summary.checks_executed == 0
    assert result.summary.network_results == 0
    assert f'"{state}"' in export_analysis_json(result)
    assert state in export_analysis_csv(result)
    assert state in export_analysis_html(result)
    with pytest.raises(ValidationError):
        component.model_copy(update={"state": "complete"})


def test_empty_run_and_unknown_network_are_not_pass():
    empty = bundle()
    assert empty.state == "not_executed"
    network = bundle(network_components(policy().revision)[0])
    assert network.state == "partial" and network.summary.findings == 0
    assert "PASS" not in export_analysis_html(network)


def test_summary_and_state_cannot_be_forged_by_json_or_copy():
    result = bundle(policy())
    payload = result.model_dump(mode="json")
    payload["summary"]["findings"] = 0
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(payload)
    with pytest.raises(ValidationError):
        result.model_copy(update={"state": "failed"})
    cancelled = AttemptComponent(
        component_id="cancelled",
        family="policy",
        operation="checks",
        state="cancelled",
        diagnostic=ComponentLimitation(code="cancelled", message="Cancelled"),
    )
    changed = result.model_copy(update={"components": (*result.components, cancelled)})
    assert changed.state == "partial" and changed.summary.cancelled_components == 1


def test_duplicate_component_or_decision_and_early_time_are_rejected():
    component = policy()
    with pytest.raises(ValidationError):
        bundle(component, component)
    with pytest.raises(ValidationError):
        bundle(component, started_at=AT + timedelta(days=1))
    with pytest.raises(ValidationError):
        bundle(component, finished_at=AT.replace(tzinfo=None))
    finding = component.result.checks[0].findings[0]
    decision = FindingDecision(
        component_id="policy",
        finding_id=finding.finding_id,
        status=FindingStatus.CONFIRMED,
        decided_at=AT,
    )
    with pytest.raises(ValidationError):
        bundle(component, decisions=(decision, decision))
    with pytest.raises(ValidationError):
        bundle(component, decisions=(decision.model_copy(update={"finding_id": uuid4()}),))


def test_exports_preserve_all_component_families_without_replay_or_source_io(monkeypatch):
    component = policy()
    result = bundle(component, *network_components(component.revision))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("export attempted replay or source access")

    for name in (
        "replay_policy",
        "select_route",
        "evaluate_interface",
        "evaluate_policy",
        "analyze_reachability",
        "analyze_device_decisions",
        "compare_device_revisions",
    ):
        monkeypatch.setattr(result_module, name, forbidden)
    monkeypatch.setattr("builtins.open", forbidden)
    assert AnalysisResult.__name__ in export_analysis_html(result)
    text = export_analysis_csv(result)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len([row for row in rows if row["row_type"] == "component"]) == 6
    assert {row["row_type"] for row in rows} >= {
        "component",
        "check",
        "finding",
        "limitation",
        "source",
    }
    assert set(json.loads(export_analysis_json(result))) >= {"sources", "components", "summary"}


@pytest.mark.parametrize("comment", ["=1+2", "+SUM(1,2)", "-2+3", "@SUM(1,2)", "\t=1", " \n=1"])
def test_csv_formula_escaping_and_separate_decision_rows(comment):
    component = policy()
    decision = FindingDecision(
        component_id="policy",
        finding_id=component.result.checks[0].findings[0].finding_id,
        status=FindingStatus.CONFIRMED,
        comment=comment,
        decided_at=AT,
    )
    rows = list(
        csv.DictReader(io.StringIO(export_analysis_csv(bundle(component, decisions=(decision,)))))
    )
    row = next(value for value in rows if value["row_type"] == "decision")
    assert row["title"] == "'" + comment


def test_html_escapes_user_comments_identifiers_and_never_renders_api_source_payload():
    component = policy().model_copy(update={"component_id": '<script>alert("id")</script>'})
    decision = FindingDecision(
        component_id=component.component_id,
        finding_id=component.result.checks[0].findings[0].finding_id,
        status=FindingStatus.CONFIRMED,
        comment="<img src=x onerror=alert(1)>",
        decided_at=AT,
    )
    result = bundle(component, decisions=(decision,), application_version='<svg onload="bad">')
    html = export_analysis_html(result)
    assert "<script>" not in html and "<img " not in html and "<svg " not in html
    assert "&lt;script&gt;" in html and "&lt;img " in html
    assert (
        "profile-exposure" not in html
    )  # Explicit profile has a different name; no fabricated profile.


def imported_snapshot():
    payload = policy().revision.model_dump(mode="python")
    payload["device"].update(vendor="cisco", platform="asa-9.16")
    payload["parse_result"]["configuration"].update(vendor="cisco", platform="asa-9.16")
    base = DeviceRevision.model_validate(payload)
    document = SourceDocument(
        source_name="interfaces",
        content=(
            b"interface GigabitEthernet0/0\n nameif inside\n"
            b" ip address 192.0.2.1 255.255.255.0\n!\n"
        ),
        captured_at=AT,
    )
    metadata = NetworkDocumentMetadata(
        source_document_id=uuid4(),
        source_kind="asa_running_config_interfaces",
        device_id=base.device.device_id,
        context_mode="single",
        firewall_mode="routed",
        declared_version="9.16",
        version_provenance="operator_declared",
        version_reference="Synthetic version statement",
        origin="synthetic",
        origin_reference="Synthetic fixture",
        address_family="ipv4",
        table_role="data",
        table_id="default",
        command="show running-config interface",
        content_sha256=document.content_sha256,
        encoding="utf-8",
        selection="authored_excerpt",
        extent="excerpt",
        capture_success=True,
    )
    return import_network_documents(
        base,
        (NetworkParseRequest(source=document, metadata=metadata, imported_at=AT),),
        revision_id=uuid4(),
    )


def test_whole_network_import_documents_metadata_and_partial_status_survive_roundtrip():
    imported = imported_snapshot()
    revision = imported.revision
    request = query(revision)
    component = RouteComponent(
        component_id="imported-route",
        revision=revision,
        imported=imported,
        query=request,
        result=select_route(revision, request),
    )
    reopened = AnalysisResult.model_validate_json(bundle(component).model_dump_json())
    saved = reopened.components[0].imported
    assert saved == imported and len(saved.documents) == 1
    assert saved.documents[0].metadata.version_reference == "Synthetic version statement"
    assert saved.documents[0].metadata.complete is False and reopened.state == "partial"
    assert "NetworkDocumentMetadata" not in export_analysis_csv(reopened)  # Real values, not repr.
    assert "Synthetic version statement" in export_analysis_html(reopened)


def test_forwarding_profile_query_flow_and_evaluation_replay_without_desktop_imports():
    imported = imported_snapshot()
    revision = imported.revision
    request = query(revision)
    flow = FlowApplicability(
        query=request, origin="synthetic", reference="Explicit unknown runtime"
    )
    snapshot = ForwardingContext(
        revision_id=revision.revision_id,
        configuration_id=revision.parse_result.configuration.configuration_id,
        device_id=revision.device.device_id,
        imported_at=revision.imported_at,
        context_mode="single",
        firewall_mode="routed",
        address_family="ipv4",
        table_role="data",
        table_id="default",
        profile_reference="Synthetic explicit supported profile",
        flow=flow,
    )
    evaluation = evaluate_forwarding_policy(
        snapshot, ingress_interface_id="inside", egress_interface_id="outside"
    )
    component = ForwardingComponent(
        component_id="forwarding",
        revision=revision,
        imported=imported,
        query=request,
        flow=flow,
        context=snapshot,
        profile_id="asa-9.16-single-routed-ipv4-data-default",
        ingress_interface_id="inside",
        egress_interface_id="outside",
        result=evaluation,
    )
    reopened = AnalysisResult.model_validate_json(bundle(component).model_dump_json())
    assert reopened.state == "partial" and reopened.components[0].result.status in {
        "unknown",
        "not_enough_evidence",
    }
    for changes in (
        {"profile_id": "unsupported"},
        {"ingress_interface_id": "different"},
        {"flow": flow.model_copy(update={"reference": "different"})},
    ):
        with pytest.raises(ValidationError):
            component.model_copy(update=changes)


def test_network_import_cannot_silently_drop_documents_or_entire_import():
    imported = imported_snapshot()
    revision = imported.revision
    request = query(revision)
    component = RouteComponent(
        component_id="network-inputs",
        revision=revision,
        imported=imported,
        query=request,
        result=select_route(revision, request),
    )
    for mutate in (
        lambda value: value.update(imported=None),
        lambda value: value["imported"].update(documents=[]),
        lambda value: value["imported"]["documents"].extend(value["imported"]["documents"][:1]),
    ):
        payload = component.model_dump(mode="json")
        mutate(payload)
        with pytest.raises(ValidationError):
            RouteComponent.model_validate(payload)


def test_source_capture_metadata_is_preserved_and_tampering_rejected():
    component = policy()
    result = bundle(component)
    source = result.sources[0]
    original = component.revision.sources[0]
    assert source.captured_at == original.captured_at
    assert source.source_kind == original.kind
    assert AnalysisResult.model_validate_json(result.model_dump_json()) == result
    payload = result.model_dump(mode="json")
    payload["sources"][0]["captured_at"] = (AT + timedelta(seconds=1)).isoformat()
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(payload)
    with pytest.raises(ValidationError):
        source.model_copy(update={"captured_at": AT.replace(tzinfo=None)})


def test_known_vmware_revision_requires_canonical_api_hash_basis_and_record():
    component = policy()
    record = {"id": "synthetic-edge", "data": {"firewall": {"userDefinedRules": []}}}
    digest = canonical_api_sha256(record)
    payload = component.revision.model_dump(mode="python")
    payload["device"].update(vendor="vmware", platform="cloud-ru-vmware-nsxt")
    payload["parse_result"]["configuration"].update(
        vendor="vmware", platform="cloud-ru-vmware-nsxt", content_sha256=digest
    )
    payload["sources"][0]["content_sha256"] = digest
    revision = DeviceRevision.model_validate(payload)
    component = PolicyComponent(
        component_id="vmware",
        revision=revision,
        options=component.options,
        result=replay_policy(revision, component.options, AT),
    )
    with pytest.raises(ValueError):
        source_manifest((revision,))
    sources = source_manifest(
        (revision,), api_records={revision.sources[0].source_document_id: record}
    )
    result = AnalysisResult(
        application_version="0.4.0",
        started_at=AT,
        finished_at=AT,
        components=(component,),
        sources=sources,
    )
    assert result.sources[0].hash_basis == "canonical_api_record"
    assert AnalysisResult.model_validate_json(result.model_dump_json()) == result
    payload = result.model_dump(mode="json")
    payload["sources"][0].update(hash_basis="raw_file", canonical_api_record=None)
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(payload)


def test_failed_attempt_typed_inputs_cannot_reference_a_different_revision_or_query():
    revision = policy().revision
    request = query(revision)
    attempt = AttemptComponent(
        component_id="failed-inputs",
        family="network",
        operation="route",
        state="failed",
        diagnostic=ComponentLimitation(code="route_error", message="Synthetic failure"),
        revision=revision,
        query=request,
    )
    assert AnalysisResult.model_validate_json(bundle(attempt).model_dump_json()).state == "failed"
    for changes in (
        {"revision": None},
        {"query": request.model_copy(update={"revision_id": uuid4()})},
        {
            "flow": FlowApplicability(
                query=request.model_copy(update={"destination_ip": "203.0.113.9"}),
                origin="synthetic",
                reference="A different query",
            )
        },
        {"policy_binding": binding(revision).model_copy(update={"source_document_id": uuid4()})},
    ):
        with pytest.raises(ValidationError):
            attempt.model_copy(update=changes)


def test_unsupported_envelope_version_and_nested_bad_summary_are_rejected():
    payload = bundle(policy()).model_dump(mode="json")
    payload["schema_version"] = "999.0.0"
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate(payload)


def test_decision_comments_preserve_whitespace_across_json_roundtrip():
    component = policy()
    original = "\t  Reviewed\nwith trailing spaces  \n"
    decision = FindingDecision(
        component_id=component.component_id,
        finding_id=component.result.checks[0].findings[0].finding_id,
        status=FindingStatus.CONFIRMED,
        comment=original,
        decided_at=AT,
    )
    result = bundle(component, decisions=(decision,))
    assert (
        AnalysisResult.model_validate_json(result.model_dump_json()).decisions[0].comment
        == original
    )


def test_diff_completeness_diagnostics_survive_all_export_formats():
    from test_revision_diff_semantics import revision

    before, after = revision(1), revision(2, complete=False, empty=True)
    component = RevisionDiffComponent(
        component_id="incomplete-diff",
        before=before,
        after=after,
        result=compare_device_revisions(before, after),
    )
    result = AnalysisResult(
        application_version="0.4.0",
        started_at=before.imported_at,
        finished_at=after.imported_at,
        components=(component,),
        sources=source_manifest((before, after)),
    )
    assert result.summary.semantic_changes == 0 and result.state == "partial"
    assert "not_observed" in export_analysis_json(result)
    assert "not_observed" in export_analysis_csv(result)
    assert "not_observed" in export_analysis_html(result)


def test_real_forwarding_parser_and_binding_snapshots_are_retained_and_cross_checked():
    from synthetic_network_inputs import CAPTURED, IMPORTED, INTERFACES, POLICY

    from firewall_compliance.application.forwarding_binding import bind_forwarding_context
    from firewall_compliance.domain import Device, RevisionSource, SourceDocumentKind
    from firewall_compliance.domain.forwarding import ForwardingSource
    from firewall_compliance.parsers import CiscoAsaParser, ParseRequest
    from firewall_compliance.parsers.cisco_asa_forwarding import CiscoAsaForwardingParser
    from firewall_compliance.parsers.forwarding_contracts import (
        ForwardingParseRequest,
        ForwardingParseResult,
    )

    source = SourceDocument(
        source_name="authored-forwarding.cfg",
        content=POLICY + INTERFACES.encode("ascii"),
        captured_at=CAPTURED,
    )
    parsed_policy = CiscoAsaParser().parse(ParseRequest(source=source, imported_at=IMPORTED))
    base = DeviceRevision(
        device=Device(
            device_id=parsed_policy.configuration.device_id, vendor="cisco", platform="asa-9.16"
        ),
        parse_result=parsed_policy,
        sources=(
            RevisionSource(
                source_name=source.source_name,
                content_sha256=source.content_sha256,
                kind=SourceDocumentKind.CONFIGURATION,
                captured_at=CAPTURED,
            ),
        ),
        application_version="0.4.0",
        imported_at=IMPORTED,
    )
    imported = import_network_documents(base, (), revision_id=uuid4())
    metadata = ForwardingSource(
        source_document_id=base.sources[0].source_document_id,
        source_name=source.source_name,
        content_sha256=source.content_sha256,
        purpose="configuration",
        device_id=base.device.device_id,
        command="show running-config",
        declared_version="9.16(4)",
        version_provenance="operator_declared",
        version_reference="Authored version",
        origin="synthetic",
        origin_reference="Authored partial export",
        captured_at=CAPTURED,
        selection="authored_excerpt",
        extent="excerpt",
        encoding="ascii",
        capture_success=True,
    )
    revision = imported.revision
    parsed = CiscoAsaForwardingParser().parse(
        ForwardingParseRequest(
            source=source,
            metadata=metadata,
            revision_id=revision.revision_id,
            configuration_id=revision.parse_result.configuration.configuration_id,
            imported_at=IMPORTED,
            context_mode="single",
            firewall_mode="routed",
            address_family="ipv4",
            table_role="data",
            table_id="default",
            profile_reference="Authored supported profile",
        )
    )
    assert isinstance(parsed, ForwardingParseResult)
    bound = bind_forwarding_context(imported, parsed)
    ingress, egress = (value.interface_id for value in parsed.context.interfaces[:2])
    request = query(revision).model_copy(update={"ingress_interface_id": ingress})
    flow = FlowApplicability(query=request, origin="synthetic", reference="Authored flow")
    context_with_flow = parsed.context.model_copy(update={"flow": flow})
    component = ForwardingComponent(
        component_id="parsed-forwarding",
        revision=revision,
        imported=imported,
        parsed=parsed,
        binding=bound,
        query=request,
        flow=flow,
        context=context_with_flow,
        profile_id="asa-9.16-single-routed-ipv4-data-default",
        ingress_interface_id=ingress,
        egress_interface_id=egress,
        result=evaluate_forwarding_policy(
            context_with_flow, ingress_interface_id=ingress, egress_interface_id=egress
        ),
    )
    reopened = AnalysisResult.model_validate_json(bundle(component).model_dump_json())
    assert reopened.components[0].parsed == parsed and reopened.components[0].binding == bound
    payload = component.model_dump(mode="json")
    payload["parsed"]["context"]["profile_reference"] = "Contradictory parsed inputs"
    with pytest.raises(ValidationError):
        ForwardingComponent.model_validate(payload)
