"""Desktop-оркестрация сетевого ядра на собственных synthetic входах."""

from pathlib import Path

import pytest
from pydantic import ValidationError
from tests.asa_forwarding_fixtures import ROOT, forwarding_request
from tests.device_decision_fixtures import device_scenario
from tests.network_import_fixtures import (
    CONFIGURED,
    INTERFACES,
    RIB,
    import_scenario,
    make_document,
    make_network_base,
)
from tests.revision_fixtures import OBSERVATION

from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.domain.policy_decision import (
    PolicyDecisionResult,
    SingleDeviceDecisionResult,
)
from firewall_compliance.domain.reachability import ReachabilityResult, RouteSelectionResult
from firewall_compliance.interfaces.desktop.network_backend import (
    NetworkDocumentDraft,
    import_documents,
    parse_forwarding,
    run_network_query,
)
from firewall_compliance.parsers.contracts import ParseFailure, SourceDocument
from firewall_compliance.parsers.forwarding_contracts import ForwardingParseResult


def test_desktop_import_retains_all_roles_and_original_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = make_network_base()
    original = base.model_dump_json()
    drafts = []
    documents: dict[Path, SourceDocument] = {}
    for index, (content, kind) in enumerate(
        (
            (INTERFACES, "asa_running_config_interfaces"),
            (CONFIGURED, "asa_running_config_static_routes"),
            (RIB, "asa_ipv4_rib"),
        )
    ):
        request = make_document(base, content, kind)  # type: ignore[arg-type]
        path = Path(f"synthetic-document-{index}.txt")
        documents[path] = request.source
        metadata = request.metadata.model_dump()
        for key in ("source_document_id", "device_id", "content_sha256"):
            metadata.pop(key)
        drafts.append(NetworkDocumentDraft(path, metadata, OBSERVATION.model_dump()))
    monkeypatch.setattr(
        "firewall_compliance.interfaces.desktop.network_backend.FileSourceReader.read",
        lambda _reader, path: documents[path],
    )
    result = import_documents(base, tuple(drafts))
    assert isinstance(result, NetworkImportResult)
    assert result.revision.revision_id != base.revision_id
    assert base.model_dump_json() == original
    assert {document.scope for document in result.documents} == {
        "interfaces",
        "configured_routes",
        "routing_table",
    }
    assert NetworkImportResult.model_validate_json(result.model_dump_json()) == result
    route = run_network_query(result.revision, "route", _query())
    assert isinstance(route, RouteSelectionResult)
    assert route.status == "selected"
    reachability = run_network_query(result.revision, "reachability", _query())
    assert isinstance(reachability, ReachabilityResult)
    assert reachability.status in {"unknown", "not_enough_evidence"}


def _query() -> dict[str, object]:
    return {
        "ingress_interface_id": "interface:GigabitEthernet0/1",
        "source_ip": "10.20.0.10",
        "destination_ip": "198.51.100.25",
        "protocol": "tcp",
        "destination_port": 443,
        "table_id": "default",
    }


@pytest.mark.parametrize("scenario", ["allow", "no_match", "implicit_deny", "incomplete"])
def test_desktop_local_apis_keep_policy_and_end_to_end_status_separate(scenario: str) -> None:
    imported = import_scenario()
    expected = device_scenario(scenario)
    query = expected.policy.query.model_dump()
    binding = expected.policy.binding.model_dump()
    policy = run_network_query(imported.revision, "policy", query, binding_values=binding)
    assert isinstance(policy, PolicyDecisionResult)
    assert policy.status == expected.policy.status
    composed = run_network_query(
        imported.revision, "device", query, binding_values=binding, imported=imported
    )
    assert isinstance(composed, SingleDeviceDecisionResult)
    assert composed.status in {"unknown", "not_enough_evidence"}
    interface = run_network_query(imported.revision, "interface", query)
    assert interface.model_dump()["status"] == "unknown"
    outside = run_network_query(
        imported.revision, "interface", {"ingress_interface_id": "interface:GigabitEthernet0/0"}
    )
    assert outside.model_dump()["status"] == "administratively_enabled"


def test_missing_binding_does_not_invent_complete_or_terminal() -> None:
    imported = import_scenario()
    with pytest.raises(ValueError, match="PolicyBindingEvidence"):
        run_network_query(imported.revision, "policy", _query())
    binding = device_scenario().policy.binding.model_dump()
    binding.update(complete=True, completeness_reference=None)
    with pytest.raises(ValidationError):
        run_network_query(imported.revision, "policy", _query(), binding_values=binding)
    with pytest.raises(ValueError, match="NetworkImportResult"):
        run_network_query(
            imported.revision,
            "device",
            _query(),
            binding_values=device_scenario().policy.binding.model_dump(),
        )


def test_desktop_import_without_observation_remains_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = make_network_base(observed=False)
    request = make_document(base, INTERFACES, "asa_running_config_interfaces")
    path = Path("synthetic-interfaces.txt")
    source = SourceDocument.model_validate({**request.source.model_dump(), "observation": None})
    monkeypatch.setattr(
        "firewall_compliance.interfaces.desktop.network_backend.FileSourceReader.read",
        lambda _reader, _path: source,
    )
    metadata = request.metadata.model_dump()
    metadata.update(complete=False, completeness_reference=None)
    outcome = import_documents(base, (NetworkDocumentDraft(path, metadata),))
    assert isinstance(outcome, NetworkImportResult)
    assert outcome.revision.observed_at is None
    assert outcome.revision.interfaces_status.value == "unknown"
    assert any(warning.code == "network_observation_incoherent" for warning in outcome.warnings)


def test_forwarding_is_separate_original_contract_with_effective_nat_unknown() -> None:
    request = forwarding_request("ingress_permit_outbound_deny")
    base = make_network_base()
    draft = NetworkDocumentDraft(
        ROOT / "ingress_permit_outbound_deny.cfg", request.metadata.model_dump()
    )
    profile = {
        key: value
        for key, value in request.model_dump().items()
        if key
        in {
            "context_mode",
            "firewall_mode",
            "address_family",
            "table_role",
            "table_id",
            "profile_reference",
        }
    }
    result = parse_forwarding(base, draft, profile)
    assert isinstance(result, ForwardingParseResult)
    assert result.context.revision_id == base.revision_id
    assert result.context.configuration_id == base.parse_result.configuration.configuration_id
    assert result.context.bindings
    assert ForwardingParseResult.model_validate_json(result.model_dump_json()) == result
    effective = next(inv for inv in result.context.inventories if inv.feature == "effective_nat")
    assert effective.status.value == "unknown"


def test_bad_forwarding_command_returns_failure_without_inventory() -> None:
    request = forwarding_request("ingress_permit_outbound_deny")
    metadata = request.metadata.model_dump()
    metadata["command"] = "show route"
    result = parse_forwarding(
        make_network_base(),
        NetworkDocumentDraft(
            ROOT / "ingress_permit_outbound_deny.cfg",
            metadata,
        ),
        {},
    )
    assert isinstance(result, ParseFailure)
    assert result.errors


@pytest.mark.parametrize(
    "key",
    [
        "source",
        "metadata",
        "revision_id",
        "configuration_id",
        "imported_at",
        "schema_version",
    ],
)
def test_forwarding_profile_cannot_override_controlled_input_before_read(
    key: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_read(_reader: object, _path: Path) -> SourceDocument:
        pytest.fail("Недопустимый профиль должен отклоняться до чтения файла.")

    monkeypatch.setattr(
        "firewall_compliance.interfaces.desktop.network_backend.FileSourceReader.read",
        unexpected_read,
    )
    base = make_network_base()
    original = base.model_dump_json()
    with pytest.raises(ValueError, match="недопустимые поля"):
        parse_forwarding(
            base,
            NetworkDocumentDraft(Path("missing-synthetic.cfg"), {}),
            {key: "attempted-override"},
        )
    assert base.model_dump_json() == original
