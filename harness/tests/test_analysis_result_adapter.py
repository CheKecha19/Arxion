"""Saved operation adapters preserve provenance and the original typed query inputs."""

import json
import subprocess
import sys
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest
from synthetic_network_inputs import INTERFACES, make_document, make_network_base

from firewall_compliance.analysis.device_decision import evaluate_interface
from firewall_compliance.analysis.forwarding_policy import evaluate_forwarding_policy
from firewall_compliance.analysis.policy_decision import evaluate_policy
from firewall_compliance.analysis.route_selection import analyze_reachability, select_route
from firewall_compliance.application.analysis_reports import (
    export_analysis_csv,
    export_analysis_html,
    export_analysis_json,
)
from firewall_compliance.application.analysis_result import AnalysisResult
from firewall_compliance.application.device_decision import analyze_imported_device
from firewall_compliance.application.network_import import (
    NetworkImportResult,
    import_network_documents,
)
from firewall_compliance.domain import Protocol, SourceLocation
from firewall_compliance.domain.forwarding import FlowApplicability, ForwardingContext
from firewall_compliance.domain.policy_decision import PolicyBindingEvidence
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.domain.reachability import AnalysisReason, ReachabilityQuery
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.interfaces.desktop.analysis_result_adapter import (
    analysis_from_network,
    analysis_from_run,
)
from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.cloud_analysis import analyze_saved_vmware
from firewall_compliance.interfaces.desktop.jobs import JobError
from firewall_compliance.interfaces.desktop.network_backend import (
    SUPPORTED_FORWARDING_PROFILE,
    ForwardingQueryResult,
)
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.qt_network import (
    NetworkFactsSnapshot,
    NetworkQuerySnapshot,
)

AT = datetime(2026, 10, 27, 10, tzinfo=UTC)
CONFIG = {"platform": "vmware", "site": "https://synthetic.invalid", "tenant": "synthetic"}


@pytest.fixture
def saved():
    directory = Path("artifacts/analysis-result-adapter") / str(uuid4())
    directory.mkdir(parents=True)
    store = ProjectStore(directory / "projects.sqlite3")
    project = store.create_project("Synthetic adapter project")
    return directory, store, project


def exposure():
    return PolicyExposureProfile.model_validate(
        {
            "profile_id": "explicit-admin",
            "version": "7",
            "dangerous_services": [
                {
                    "selector_id": "organization-port-22",
                    "name": "Organization service",
                    "protocol": "tcp",
                    "port_ranges": [{"start": 22, "end": 22}],
                }
            ],
        }
    )


def saved_local(saved):
    directory, store, project = saved
    source = directory / "synthetic.cfg"
    source.write_text(
        "hostname SYNTHETIC-ADAPTER\n"
        "access-list OUTSIDE extended permit tcp any host 192.0.2.10 eq 22\n"
        "access-group OUTSIDE in interface outside\n",
        encoding="utf-8",
    )
    profile = exposure()
    store.update_settings(project, {"policy_exposure_profile": profile.model_dump(mode="json")})
    run_id = store.create_run(project)
    session = analyze_file(
        source,
        enabled_check_ids=("FW-DANGEROUS-SERVICES",),
        policy_exposure_profile=profile,
    )
    assert isinstance(session, AnalysisSession)
    item_id = store.record_session(run_id, session)
    store.finish_run(run_id)
    return source, run_id, item_id, session


def saved_cloud(saved):
    _, store, project = saved
    scan_id = store.create_cloud_scan(project, {}, CONFIG)
    record = {
        "id": "urn:vcloud:gateway:aaaaaaaa-bbbb-cccc-dddd-000000000001",
        "type": "edges",
        "name": "Synthetic Edge",
        "collected_at": "2026-10-26T10:00:00+00:00",
        "inventory": {},
        "data": {
            "firewall": {
                "userDefinedRules": [
                    {
                        "id": "synthetic-rule",
                        "name": "Synthetic allow",
                        "active": True,
                        "direction": "IN_OUT",
                        "ipProtocol": "IPV4",
                        "actionValue": "ALLOW",
                        "sourceFirewallGroups": None,
                        "sourceFirewallIpAddresses": None,
                        "destinationFirewallGroups": None,
                        "destinationFirewallIpAddresses": None,
                        "applicationPortProfiles": None,
                        "rawPortProtocols": None,
                        "logging": False,
                        "description": "",
                    }
                ],
                "systemRules": [],
                "defaultRules": [],
            }
        },
    }
    store.finish_cloud_scan(scan_id, {"state": "completed", "records": [record], "errors": []})
    scan = store.list_cloud_scans(project)[0]
    items = analyze_saved_vmware(scan, {}, Event())
    run_id = store.save_cloud_analysis(scan_id, items, {})
    return run_id, scan, record


def network_inputs():
    base = make_network_base(observed=False)
    imported = import_network_documents(
        base,
        (make_document(base, INTERFACES, "asa_running_config_interfaces"),),
        revision_id=uuid4(),
    )
    assert isinstance(imported, NetworkImportResult)
    revision = imported.revision
    physical = imported.documents[0].interface_labels["inside"]
    query = ReachabilityQuery(
        revision_id=revision.revision_id,
        device_id=revision.device.device_id,
        ingress_interface_id=physical,
        source_ip="198.51.100.10",
        destination_ip="192.0.2.10",
        protocol=Protocol.TCP,
        destination_port=443,
    )
    binding = PolicyBindingEvidence(
        policy_id=base.parse_result.rules[0].policy_id,
        direction="in",
        interface_id=physical,
        interface_label="inside",
        interface_mapping_reference="Authored explicit interface mapping",
        source_document_id=base.sources[0].source_document_id,
        binding_location=SourceLocation(source_name=base.sources[0].source_name, line_start=4),
        declaration_origin="synthetic",
        coordinate_space="acl_input",
    )
    return NetworkFactsSnapshot(base, imported, None, input_generation=7), query, binding


def snapshot(facts, query, result, **changes):
    values = {
        "facts": facts,
        "profile_id": "legacy",
        "query": query,
        "result": result,
        "input_generation": 7,
        "project_reference": "project-a",
        "started_at": AT,
        "finished_at": AT + timedelta(seconds=2),
    }
    values.update(changes)
    return NetworkQuerySnapshot(**values)


def test_saved_local_report_and_decision_use_run_profile_without_reading_source(saved, monkeypatch):
    source, run_id, _, session = saved_local(saved)
    _, store, project = saved
    finding = session.report.checks[0].findings[0]
    store.set_finding_mark(run_id, str(finding.finding_id), "confirmed", "\t<review> saved \n")
    store.update_settings(project, {"policy_exposure_profile": {"profile_id": "different"}})

    def forbidden(*_args, **_kwargs):
        raise AssertionError("saved adapter reread a source or started a new file analysis")

    monkeypatch.setattr(FileSourceReader, "read", forbidden)
    monkeypatch.setattr("firewall_compliance.interfaces.desktop.backend.analyze_file", forbidden)
    result = analysis_from_run(store, project, run_id)
    assert result.project_reference == project and result.run_reference == run_id
    assert result.components[0].result == session.report
    assert result.components[0].revision == session.revision
    assert result.components[0].options.exposure_profile == exposure()
    assert result.sources[0].hash_basis == "raw_file"
    assert result.sources[0].content_sha256 == session.source.content_sha256
    assert result.decisions[0].comment == "\t<review> saved \n"
    assert result.decisions[0].status == "confirmed"
    assert result.components[0].result.checks[0].findings[0].status == "new"
    assert source.exists()

    monkeypatch.setattr("firewall_compliance.application.analysis_result.replay_policy", forbidden)
    assert json.loads(export_analysis_json(result))["run_reference"] == run_id
    assert "confirmed" in export_analysis_csv(result)
    assert "&lt;review&gt;" in export_analysis_html(result)


def test_saved_cloud_report_retains_canonical_record_basis_and_not_fake_raw_http_hash(saved):
    run_id, _, record = saved_cloud(saved)
    _, store, project = saved
    result = analysis_from_run(store, project, run_id)
    assert result.sources[0].hash_basis == "canonical_api_record"
    assert result.sources[0].canonical_api_record == record
    assert result.components[0].revision.device.platform == "cloud-ru-vmware-nsxt"
    assert AnalysisResult.model_validate_json(result.model_dump_json()) == result


def test_saved_errors_and_cancellation_keep_original_diagnostics_and_distinct_states(saved):
    _, store, project = saved
    run_id = store.create_run(project)
    store.record_error(run_id, Path("authored.cfg"), "Synthetic transport denied")
    store.record_cancelled(run_id, Path("cancelled.cfg"))
    store.finish_run(run_id)
    result = analysis_from_run(store, project, run_id)
    assert {component.state for component in result.components} == {"failed", "cancelled"}
    assert result.summary.failed_components == 1 and result.summary.cancelled_components == 1
    text = export_analysis_json(result)
    assert "Synthetic transport denied" in text and "IMPORT_ERROR" in text
    assert "IMPORT_CANCELLED" in text


def test_empty_cancelled_saved_run_is_not_relabelled_as_never_executed(saved):
    _, store, project = saved
    run_id = store.create_run(project)
    store.finish_run(run_id, state="cancelled")
    assert analysis_from_run(store, project, run_id).state == "cancelled"


def test_run_adapter_rejects_cross_project_and_naive_or_unknown_operation_dates(saved):
    _, run_id, _, _ = saved_local(saved)
    _, store, project = saved
    other = store.create_project("Another project")
    with pytest.raises(ValueError):
        analysis_from_run(store, other, run_id)
    run = store.get_run(run_id)

    class Stored:
        def get_run(self, _run_id):
            return run

        def list_cloud_scans(self, _project):
            return []

    for timestamp in (None, "", "2026-10-27T10:00:00"):
        run["created_at"] = timestamp
        with pytest.raises(ValueError):
            analysis_from_run(Stored(), project, run_id)


@pytest.mark.parametrize("change", ["index", "resource", "hash", "source_hash", "connection"])
def test_cloud_record_and_origin_tampering_cannot_reuse_original_policy_report(saved, change):
    run_id, scan, _ = saved_cloud(saved)
    _, store, project = saved
    run = deepcopy(store.get_run(run_id))
    item = run["items"][0]
    scans = [deepcopy(scan)]
    if change == "index":
        item["cloud_origin"]["record_index"] = 99
    elif change == "resource":
        item["cloud_origin"]["resource_id"] = "different"
    elif change == "hash":
        scans[0]["result"]["records"][0]["name"] = "Changed record"
    elif change == "source_hash":
        item["revision"]["sources"][0]["content_sha256"] = "b" * 64
    else:
        item["cloud_origin"]["connection"]["site"] = "https://another.invalid"

    class Stored:
        def get_run(self, _run_id):
            return run

        def list_cloud_scans(self, _project):
            return scans

    with pytest.raises(ValueError):
        analysis_from_run(Stored(), project, run_id)


@pytest.mark.parametrize("kind", ["route", "reachability", "interface", "policy", "device"])
def test_all_original_network_api_families_retain_import_documents_query_and_partial_state(kind):
    facts, query, binding = network_inputs()
    imported, revision = facts.imported, facts.imported.revision
    results = {
        "route": lambda: select_route(revision, query),
        "reachability": lambda: analyze_reachability(revision, query),
        "interface": lambda: evaluate_interface(revision, query.ingress_interface_id),
        "policy": lambda: evaluate_policy(revision, query, binding),
        "device": lambda: analyze_imported_device(imported, query, binding),
    }
    actual = results[kind]()
    stored = snapshot(facts, None if kind == "interface" else query, actual)
    result = analysis_from_network(stored, "project-a")
    component = result.components[0]
    assert component.result == actual and component.imported == imported
    assert len(component.imported.documents) == 1
    assert component.imported.documents[0].metadata.origin == "synthetic"
    assert result.started_at == AT and result.finished_at == AT + timedelta(seconds=2)
    assert result.state == "partial"
    if kind != "interface":
        assert component.query == query


def forwarding_snapshot():
    facts, query, _ = network_inputs()
    revision = facts.imported.revision
    flow = FlowApplicability(query=query, origin="synthetic", reference="Explicit authored flow")
    context = ForwardingContext(
        revision_id=revision.revision_id,
        configuration_id=revision.parse_result.configuration.configuration_id,
        device_id=revision.device.device_id,
        imported_at=revision.imported_at,
        context_mode="single",
        firewall_mode="routed",
        address_family="ipv4",
        table_role="data",
        table_id="default",
        profile_reference="Authored supported profile",
        flow=flow,
    )
    evaluation = evaluate_forwarding_policy(
        context, ingress_interface_id=query.ingress_interface_id, egress_interface_id="outside"
    )
    result = ForwardingQueryResult(
        query=query,
        profile_id=SUPPORTED_FORWARDING_PROFILE,
        ingress_interface_id=query.ingress_interface_id,
        egress_interface_id="outside",
        status=evaluation.status,
        binding=None,
        evaluation=evaluation,
        reasons=evaluation.reasons,
        context=context,
    )
    return snapshot(
        replace(facts, bound_context=context),
        query,
        result,
        profile_id=SUPPORTED_FORWARDING_PROFILE,
    )


def test_forwarding_context_flow_profile_and_evaluation_are_preserved():
    stored = forwarding_snapshot()
    result = analysis_from_network(stored, "project-a")
    component = result.components[0]
    assert component.kind == "forwarding"
    assert component.result == stored.result.evaluation
    assert component.context == stored.facts.bound_context
    assert component.flow.query == stored.query
    assert component.profile_id == stored.profile_id
    assert result.state == "partial"


@pytest.mark.parametrize("failure", ["reason", "job", "forwarding"])
def test_failed_network_operations_preserve_inputs_and_never_become_empty_success(failure):
    facts, query, _ = network_inputs()
    reason = AnalysisReason(
        code="authored_input_missing",
        category="missing_evidence",
        message="Synthetic missing input",
    )
    if failure == "job":
        actual = JobError("internal", "Synthetic worker failure")
    elif failure == "reason":
        actual = reason
    else:
        actual = ForwardingQueryResult(
            query=query,
            profile_id=SUPPORTED_FORWARDING_PROFILE,
            ingress_interface_id=query.ingress_interface_id,
            egress_interface_id=None,
            status="not_enough_evidence",
            binding=None,
            evaluation=None,
            reasons=(reason,),
        )
    stored = snapshot(
        facts,
        query,
        actual,
        profile_id=SUPPORTED_FORWARDING_PROFILE if failure == "forwarding" else "legacy",
    )
    result = analysis_from_network(stored, "project-a")
    component = result.components[0]
    assert component.kind == "attempt" and component.query == query
    assert component.imported == facts.imported
    assert result.state == ("failed" if failure == "job" else "not_executed")
    assert result.summary.network_results == 0
    assert "Synthetic" in export_analysis_html(result)


@pytest.mark.parametrize("kind", ["route", "reachability", "policy", "device", "forwarding"])
def test_network_adapter_rejects_cached_query_mismatch_instead_of_replacing_it(kind):
    facts, query, binding = network_inputs()
    revision = facts.imported.revision
    if kind == "forwarding":
        stored = forwarding_snapshot()
    else:
        result = {
            "route": lambda: select_route(revision, query),
            "reachability": lambda: analyze_reachability(revision, query),
            "policy": lambda: evaluate_policy(revision, query, binding),
            "device": lambda: analyze_imported_device(facts.imported, query, binding),
        }[kind]()
        stored = snapshot(facts, query, result)
    changed = stored.query.model_copy(update={"destination_ip": "203.0.113.55"})
    with pytest.raises(ValueError):
        analysis_from_network(replace(stored, query=changed), "project-a")


def test_network_adapter_rejects_foreign_project_profile_or_base_revision():
    stored = forwarding_snapshot()
    with pytest.raises(ValueError):
        analysis_from_network(stored, "another-project")
    with pytest.raises(ValueError):
        analysis_from_network(replace(stored, profile_id="unsupported"), "project-a")
    base = stored.facts.base_revision.model_dump(mode="python")
    base["parse_result"]["configuration"]["content_sha256"] = "b" * 64
    base["sources"][0]["content_sha256"] = "b" * 64
    changed = type(stored.facts.base_revision).model_validate(base)
    with pytest.raises(ValueError):
        analysis_from_network(
            replace(stored, facts=replace(stored.facts, base_revision=changed)), "project-a"
        )


def test_network_adapter_revalidates_source_ids_even_for_preconstructed_input_models():
    facts, query, _ = network_inputs()
    imported = facts.imported
    document = imported.documents[0]
    foreign_source = document.source.model_copy(update={"source_document_id": uuid4()})
    # Model construction intentionally bypasses validation to simulate a corrupted
    # caller cache. The adapter must validate its nested inputs again on ingestion.
    corrupted_document = type(document).model_construct(
        **{**document.__dict__, "source": foreign_source}
    )
    corrupted_import = NetworkImportResult.model_construct(
        revision=imported.revision, documents=(corrupted_document,), warnings=imported.warnings
    )
    stored = snapshot(
        replace(facts, imported=corrupted_import),
        query,
        select_route(imported.revision, query),
    )
    with pytest.raises(ValueError):
        analysis_from_network(stored, "project-a")


def actual_forwarding_snapshot():
    from synthetic_network_inputs import CAPTURED, IMPORTED, POLICY

    from firewall_compliance.domain import Device, DeviceRevision, ParseResult, RevisionSource
    from firewall_compliance.domain.enums import SourceDocumentKind
    from firewall_compliance.domain.forwarding import ForwardingSource
    from firewall_compliance.domain.observation import ObservationEvidence
    from firewall_compliance.interfaces.desktop.network_backend import run_forwarding_query
    from firewall_compliance.parsers import CiscoAsaParser, ParseRequest, SourceDocument
    from firewall_compliance.parsers.cisco_asa_forwarding import CiscoAsaForwardingParser
    from firewall_compliance.parsers.forwarding_contracts import (
        ForwardingParseRequest,
        ForwardingParseResult,
    )
    from firewall_compliance.parsers.network_contracts import NetworkParseRequest

    observation = ObservationEvidence(
        observed_at=CAPTURED, method="synthetic", reference="Authored shared capture"
    )
    source = SourceDocument(
        source_name="authored-full-forwarding.cfg",
        content=POLICY + INTERFACES.encode("ascii"),
        captured_at=CAPTURED,
        observation=observation,
    )
    parsed_policy = CiscoAsaParser().parse(ParseRequest(source=source, imported_at=IMPORTED))
    assert isinstance(parsed_policy, ParseResult)
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
                observation=observation,
            ),
        ),
        application_version="0.4.0",
        imported_at=IMPORTED,
        observed_at=CAPTURED,
    )
    network_request = make_document(
        base, INTERFACES, "asa_running_config_interfaces", capture_success=True
    ).model_dump(mode="python")
    network_request["source"]["observation"] = observation.model_dump(mode="python")
    imported = import_network_documents(
        base, (NetworkParseRequest.model_validate(network_request),), revision_id=uuid4()
    )
    assert isinstance(imported, NetworkImportResult)
    revision = imported.revision
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
        origin_reference="Authored export",
        captured_at=CAPTURED,
        observation=observation,
        selection="authored_excerpt",
        extent="excerpt",
        encoding="ascii",
        capture_success=True,
    )
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
            profile_reference="Authored profile",
        )
    )
    assert isinstance(parsed, ForwardingParseResult)
    ingress, egress = (item.interface_id for item in parsed.context.interfaces[:2])
    query = ReachabilityQuery(
        revision_id=revision.revision_id,
        device_id=revision.device.device_id,
        ingress_interface_id=ingress,
        source_ip="192.0.2.10",
        destination_ip="198.51.100.10",
        protocol="tcp",
        destination_port=443,
    )
    flow = FlowApplicability(query=query, origin="synthetic", reference="Authored runtime unknown")
    actual = run_forwarding_query(
        imported,
        parsed,
        query,
        profile_id=SUPPORTED_FORWARDING_PROFILE,
        ingress_interface_id=ingress,
        egress_interface_id=egress,
        flow=flow,
    )
    assert actual.evaluation is not None
    assert parsed.context.flow is None and actual.binding.forwarding.context.flow == flow
    facts = NetworkFactsSnapshot(base, imported, parsed)
    return snapshot(facts, query, actual, profile_id=SUPPORTED_FORWARDING_PROFILE)


def test_actual_forwarding_backend_original_parser_and_derived_flow_can_be_saved():
    stored = actual_forwarding_snapshot()
    saved = analysis_from_network(stored, "project-a")
    assert saved.components[0].result == stored.result.evaluation
    assert saved.components[0].parsed == stored.facts.parsed
    assert saved.components[0].binding == stored.result.binding


@pytest.mark.parametrize("change", ["arbitrary_flow", "different_parse_coverage"])
def test_forwarding_derivation_does_not_accept_other_flow_or_unrelated_parser_changes(change):
    stored = actual_forwarding_snapshot()
    if change == "arbitrary_flow":
        bound = stored.result.binding
        another = bound.forwarding.context.flow.model_copy(
            update={"reference": "A third unrelated flow declaration"}
        )
        altered_context = bound.forwarding.context.model_copy(update={"flow": another})
        altered_parsed = bound.forwarding.model_copy(update={"context": altered_context})
        altered_binding = bound.model_copy(update={"forwarding": altered_parsed})
        stored = replace(stored, result=replace(stored.result, binding=altered_binding))
    else:
        parsed = stored.facts.parsed
        coverage = parsed.coverage.model_copy(
            update={
                "discovered_constructs": parsed.coverage.discovered_constructs + 1,
            }
        )
        altered_parsed = parsed.model_copy(update={"coverage": coverage})
        stored = replace(stored, facts=replace(stored.facts, parsed=altered_parsed))
    with pytest.raises(ValueError):
        analysis_from_network(stored, "project-a")


@pytest.mark.parametrize(
    "change",
    [
        {"started_at": None},
        {"finished_at": None},
        {"started_at": AT.replace(tzinfo=None)},
        {"finished_at": AT.replace(tzinfo=None)},
        {"finished_at": AT - timedelta(seconds=1)},
    ],
)
def test_network_operation_never_invents_unknown_or_invalid_times(change):
    stored = forwarding_snapshot()
    with pytest.raises(ValueError):
        analysis_from_network(replace(stored, **change), "project-a")


def test_cli_import_and_adapter_runtime_do_not_import_qt_in_a_fresh_process():
    code = (
        "import sys; "
        "import firewall_compliance.interfaces.cli.main; "
        "import firewall_compliance.interfaces.desktop.analysis_result_adapter; "
        "assert not any(name.startswith(('PySide6', 'tkinter')) for name in sys.modules); "
        "assert 'firewall_compliance.interfaces.desktop.qt_network' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
