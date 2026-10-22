"""Сетевые документы, новая ревизия и нейтральный routing decision."""

from datetime import timedelta
from itertools import permutations
from pathlib import Path

import pytest
from tests.network_import_fixtures import (
    CONFIGURED,
    INTERFACES,
    NETWORK_REVISION_ID,
    RIB,
    import_scenario,
    make_document,
    make_network_base,
)
from tests.revision_fixtures import OBSERVED_AT

from firewall_compliance.analysis import analyze_reachability, select_route
from firewall_compliance.application.network_import import (
    NetworkImportResult,
    import_network_documents,
)
from firewall_compliance.domain import (
    DataStatus,
    DeviceRevision,
    ObservationWindow,
    ReachabilityQuery,
)
from firewall_compliance.parsers import ParseFailure
from firewall_compliance.parsers.network_contracts import NetworkParseRequest


def test_complete_authored_documents_enrich_revision_without_modifying_base() -> None:
    base = make_network_base()
    before = base.model_dump_json()
    requests = (
        make_document(base, RIB, "asa_ipv4_rib"),
        make_document(base, INTERFACES, "asa_running_config_interfaces"),
        make_document(base, CONFIGURED, "asa_running_config_static_routes"),
    )
    result = import_network_documents(base, requests, revision_id=NETWORK_REVISION_ID)
    assert isinstance(result, NetworkImportResult)
    assert base.model_dump_json() == before
    assert result.revision.routes_status == result.revision.interfaces_status == DataStatus.KNOWN
    assert result.revision.routes_evidence.scope == "routing_table"
    assert len(result.revision.routes) == 3
    assert not any(route.is_blackhole for route in result.revision.routes)
    configured = next(
        document for document in result.documents if document.scope == "configured_routes"
    )
    assert configured.routes[1].is_blackhole
    assert configured.routes[1].administrative_distance is None
    assert len(result.revision.sources) == 4
    query = ReachabilityQuery(
        revision_id=NETWORK_REVISION_ID,
        device_id=base.device.device_id,
        ingress_interface_id="interface:GigabitEthernet0/1",
        source_ip="10.20.0.10",
        destination_ip="198.51.100.10",
        protocol="tcp",
        destination_port=443,
    )
    assert select_route(result.revision, query).status == "selected"
    assert analyze_reachability(result.revision, query).status == "unknown"
    assert NetworkImportResult.model_validate_json(result.model_dump_json()) == result
    with pytest.raises(TypeError):
        result.documents[0].interface_labels.clear()


@pytest.mark.parametrize("scenario", ["unsupported", "configured_only"])
def test_configured_routes_do_not_complete_rib(scenario: str) -> None:
    result = import_scenario(scenario)
    assert result.revision.routes_evidence.scope == (
        "routing_table" if scenario == "unsupported" else "configured_routes"
    )
    if scenario == "unsupported":
        assert result.revision.routes_status == DataStatus.UNKNOWN
        assert not result.revision.routes_evidence.complete
        assert next(
            document for document in result.documents if document.scope == "routing_table"
        ).unsupported_constructs
    assert (
        next(
            document for document in result.documents if document.scope == "configured_routes"
        ).status
        == DataStatus.KNOWN
    )


def test_missing_interface_document_does_not_invent_binding() -> None:
    base = make_network_base()
    result = import_network_documents(
        base, (make_document(base, RIB, "asa_ipv4_rib"),), revision_id=NETWORK_REVISION_ID
    )
    assert isinstance(result, NetworkImportResult)
    assert result.revision.interfaces_status == result.revision.routes_status == DataStatus.UNKNOWN
    assert all(route.outgoing_interface_id is None for route in result.revision.routes)


def test_document_order_does_not_change_bundle() -> None:
    base = make_network_base()
    requests = (
        make_document(base, INTERFACES, "asa_running_config_interfaces"),
        make_document(base, RIB, "asa_ipv4_rib"),
        make_document(base, CONFIGURED, "asa_running_config_static_routes"),
    )
    serialized = [
        import_network_documents(base, order, revision_id=NETWORK_REVISION_ID).model_dump(
            mode="json"
        )
        for order in permutations(requests)
    ]
    assert all(result == serialized[0] for result in serialized)


@pytest.mark.parametrize("with_window", [False, True])
def test_explicit_observation_window_not_automatic_tolerance(with_window: bool) -> None:
    base = make_network_base()
    if with_window:
        payload = base.model_dump(mode="python")
        payload["observation_window"] = ObservationWindow(
            start=OBSERVED_AT - timedelta(seconds=5),
            end=OBSERVED_AT,
            reason="Собственный synthetic сценарий согласованного окна.",
        )
        base = DeviceRevision.model_validate(payload)
    request = make_document(base, INTERFACES, "asa_running_config_interfaces")
    payload = request.model_dump(mode="python")
    payload["source"]["observation"]["observed_at"] -= timedelta(seconds=5)
    result = import_network_documents(
        base, (NetworkParseRequest.model_validate(payload),), revision_id=NETWORK_REVISION_ID
    )
    assert isinstance(result, NetworkImportResult)
    assert result.revision.interfaces_status == (
        DataStatus.KNOWN if with_window else DataStatus.UNKNOWN
    )
    assert bool(result.warnings) == (not with_window)


def test_config_observation_missing_cannot_be_filled_from_network_source() -> None:
    base = make_network_base(observed=False)
    result = import_network_documents(
        base,
        (make_document(base, INTERFACES, "asa_running_config_interfaces"),),
        revision_id=NETWORK_REVISION_ID,
    )
    assert isinstance(result, NetworkImportResult)
    assert result.revision.observed_at is None
    assert result.revision.interfaces_status == DataStatus.UNKNOWN


def test_stale_interface_observation_cannot_make_rib_binding_known() -> None:
    base = make_network_base()
    interface_request = make_document(base, INTERFACES, "asa_running_config_interfaces")
    payload = interface_request.model_dump(mode="python")
    payload["source"]["observation"]["observed_at"] -= timedelta(days=1)
    result = import_network_documents(
        base,
        (
            NetworkParseRequest.model_validate(payload),
            make_document(base, RIB, "asa_ipv4_rib"),
        ),
        revision_id=NETWORK_REVISION_ID,
    )
    assert isinstance(result, NetworkImportResult)
    assert result.revision.routes_status == result.revision.interfaces_status == DataStatus.UNKNOWN
    assert all(route.outgoing_interface_id is None for route in result.revision.routes)
    assert all(route.data_status == DataStatus.UNKNOWN for route in result.revision.routes)


@pytest.mark.parametrize(
    "fault",
    [
        "duplicate_role",
        "duplicate_uuid",
        "device",
        "context",
        "same_revision",
        "bound_interfaces",
        "existing_facts",
    ],
)
def test_unsafe_merges_are_rejected(fault: str) -> None:
    base = make_network_base()
    request = make_document(base, INTERFACES, "asa_running_config_interfaces")
    requests, revision_id = (request,), NETWORK_REVISION_ID
    payload = request.model_dump(mode="python")
    if fault == "duplicate_role":
        requests = (request, request)
    elif fault == "duplicate_uuid":
        payload["metadata"]["source_document_id"] = base.sources[0].source_document_id
    elif fault == "device":
        payload["metadata"]["device_id"] = "another"
    elif fault == "context":
        payload["metadata"].update(context_mode="multiple", context="another")
    elif fault == "same_revision":
        revision_id = base.revision_id
    elif fault == "bound_interfaces":
        payload["interfaces"] = import_scenario().revision.interfaces
    elif fault == "existing_facts":
        base = import_scenario().revision
    if fault not in {"duplicate_role", "same_revision", "existing_facts"}:
        requests = (NetworkParseRequest.model_validate(payload),)
    with pytest.raises(ValueError):
        import_network_documents(base, requests, revision_id=revision_id)


def test_profile_failure_does_not_publish_partial_revision() -> None:
    base = make_network_base()
    result = import_network_documents(
        base,
        (
            make_document(
                base, INTERFACES, "asa_running_config_interfaces", declared_version="9.20"
            ),
        ),
        revision_id=NETWORK_REVISION_ID,
    )
    assert isinstance(result, ParseFailure)


@pytest.mark.parametrize(
    "scenario", ["connected_static_default", "narrower_null0", "partial_unsupported"]
)
def test_existing_authored_excerpts_never_become_known(scenario: str) -> None:
    directory = Path(__file__).parents[1] / "fixtures" / "network_asa" / scenario
    base = make_network_base()
    files = (
        ("interfaces.cfg", "asa_running_config_interfaces"),
        ("static_routes.cfg", "asa_running_config_static_routes"),
        ("show_route.txt", "asa_ipv4_rib"),
    )
    requests = tuple(
        make_document(
            base,
            (directory / filename).read_bytes(),
            kind,
            complete=False,
            extent="excerpt",
            selection="authored_excerpt",
        )
        for filename, kind in files
        if (directory / filename).exists()
    )
    result = import_network_documents(base, requests, revision_id=NETWORK_REVISION_ID)
    assert isinstance(result, NetworkImportResult)
    assert result.revision.interfaces_status == result.revision.routes_status == DataStatus.UNKNOWN
    assert all(not document.collection_evidence.complete for document in result.documents)
