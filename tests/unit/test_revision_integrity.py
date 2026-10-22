"""Регрессии полноты, происхождения, адресов и времени сетевых фактов."""

from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from tests.revision_fixtures import (
    CONFIGURATION_SOURCE_ID,
    IMPORTED_AT,
    OBSERVATION,
    OBSERVED_AT,
    SECOND_SOURCE_ID,
    make_revision,
)

from firewall_compliance.domain import (
    CollectionEvidence,
    DataOrigin,
    DataStatus,
    DeviceRevision,
    ObservationEvidence,
    ObservationWindow,
    SourceDocumentKind,
)


def rebuild(**updates: Any) -> DeviceRevision:
    payload = make_revision().model_dump(mode="python")
    payload.update(updates)
    return DeviceRevision.model_validate(payload)


@pytest.mark.parametrize(
    "address,network",
    [
        ("10.0.0.1/24", "10.0.0.0/24"),
        ("2001:db8::1234/64", "2001:db8::/64"),
        ("192.0.2.1/32", "192.0.2.1/32"),
        ("2001:db8::1/128", "2001:db8::1/128"),
    ],
)
def test_interface_preserves_host_address_and_derives_network(address: str, network: str) -> None:
    interface = make_revision().interfaces[0].model_dump()
    interface["addresses"] = [address, address]
    revision = rebuild(interfaces=[interface])
    assert revision.interfaces[0].addresses == (address,)
    assert revision.interfaces[0].networks == (network,)


@pytest.mark.parametrize("status", [DataStatus.UNKNOWN, DataStatus.UNSUPPORTED, DataStatus.ABSENT])
def test_known_collection_rejects_unreliable_fact(status: DataStatus) -> None:
    interface = make_revision().interfaces[0].model_dump()
    interface["data_status"] = status
    with pytest.raises(ValidationError, match="известных фактов"):
        rebuild(interfaces=[interface])


@pytest.mark.parametrize(
    "evidence",
    [None, CollectionEvidence(scope="interfaces", source_document_ids=(CONFIGURATION_SOURCE_ID,))],
)
def test_known_collection_requires_complete_evidence(evidence: CollectionEvidence | None) -> None:
    with pytest.raises(ValidationError, match="полноты"):
        rebuild(interfaces_evidence=evidence)


def test_source_location_name_must_match_identified_document() -> None:
    interface = make_revision().interfaces[0].model_dump()
    interface["source_location"]["source_name"] = "another.cfg"
    with pytest.raises(ValidationError, match="source mapping"):
        rebuild(interfaces=[interface])


def test_interface_and_segment_ids_cannot_collide() -> None:
    segment = make_revision().network_segments[0].model_dump()
    segment["segment_id"] = "interface:inside"
    with pytest.raises(ValidationError, match="пересекаться"):
        rebuild(network_segments=[segment])


@pytest.mark.parametrize("target", ["next_hop", "outgoing_interface_id"])
def test_blackhole_rejects_forwarding_targets(target: str) -> None:
    route = make_revision().routes[0].model_dump()
    route.update(is_blackhole=True, next_hop=None, outgoing_interface_id=None)
    route[target] = "192.0.2.1" if target == "next_hop" else "interface:inside"
    with pytest.raises(ValidationError, match="blackhole"):
        rebuild(routes=[route])


def test_route_rejects_mixed_ip_families() -> None:
    route = make_revision().routes[0].model_dump()
    route["next_hop"] = "2001:db8::1"
    with pytest.raises(ValidationError, match="семейство"):
        rebuild(routes=[route])


def test_route_rejects_missing_interface_even_for_unknown_inventory() -> None:
    with pytest.raises(ValidationError, match="интерфейс ревизии"):
        rebuild(
            interfaces=[],
            interfaces_status=DataStatus.UNKNOWN,
            interfaces_evidence=None,
            topology_links=[],
            topology_status=DataStatus.UNKNOWN,
            topology_evidence=None,
        )


def test_configured_routes_do_not_prove_full_rib() -> None:
    with pytest.raises(ValidationError, match="routing_table"):
        rebuild(
            routes_evidence=CollectionEvidence(
                scope="routing_table", complete=True, source_document_ids=(CONFIGURATION_SOURCE_ID,)
            )
        )


@pytest.mark.parametrize("status", [DataStatus.KNOWN, DataStatus.ABSENT])
def test_empty_routes_need_explicit_complete_source(status: DataStatus) -> None:
    revision = rebuild(routes=[], routes_status=status)
    assert not revision.routes
    assert revision.routes_evidence is not None and revision.routes_evidence.complete
    with pytest.raises(ValidationError, match="полноты"):
        rebuild(routes=[], routes_status=status, routes_evidence=None)


def test_absent_collection_cannot_hide_present_fact() -> None:
    with pytest.raises(ValidationError, match="содержать факты"):
        rebuild(routes_status=DataStatus.ABSENT)


def test_fact_source_must_be_in_completeness_evidence() -> None:
    source = make_revision().sources[0].model_copy(update={"source_document_id": SECOND_SOURCE_ID})
    with pytest.raises(ValidationError, match="источник факта"):
        rebuild(
            sources=(
                *make_revision().sources,
                source.model_copy(update={"kind": SourceDocumentKind.ROUTING_TABLE}),
            ),
            routes_evidence=CollectionEvidence(
                scope="configured_routes", complete=True, source_document_ids=(SECOND_SOURCE_ID,)
            ),
        )


def test_known_data_requires_explicit_observation_not_capture_time() -> None:
    source = make_revision().sources[0].model_dump()
    source["observation"] = None
    with pytest.raises(ValidationError, match="observed_at"):
        rebuild(sources=[source])
    with pytest.raises(ValidationError, match="observed_at"):
        rebuild(observed_at=None)


def test_capture_and_import_times_can_differ_from_observation() -> None:
    payload = make_revision().model_dump(mode="python")
    payload["sources"][0]["captured_at"] = OBSERVED_AT + timedelta(seconds=20)
    payload["parse_result"]["configuration"]["captured_at"] = payload["sources"][0]["captured_at"]
    revision = DeviceRevision.model_validate(payload)
    assert revision.observed_at == OBSERVED_AT
    assert revision.sources[0].captured_at != revision.observed_at


def test_multi_source_window_is_explicit_and_bounded() -> None:
    payload = make_revision().model_dump(mode="python")
    later = OBSERVED_AT + timedelta(seconds=20)
    source = {
        **payload["sources"][0],
        "source_document_id": SECOND_SOURCE_ID,
        "kind": "routing_table",
        "source_name": "routes.txt",
        "captured_at": later,
        "observation": ObservationEvidence(
            observed_at=later, method="synthetic", reference="Второй экспорт."
        ),
    }
    payload["sources"] = (*payload["sources"], source)
    payload["routes"][0].update(
        source_document_id=SECOND_SOURCE_ID,
        source_location={"source_name": "routes.txt", "line_start": 1},
    )
    payload["routes_evidence"] = CollectionEvidence(
        scope="routing_table", complete=True, source_document_ids=(SECOND_SOURCE_ID,)
    )
    with pytest.raises(ValidationError, match="observed_at"):
        DeviceRevision.model_validate(payload)
    payload["observation_window"] = ObservationWindow(
        start=OBSERVED_AT, end=later, reason="Synthetic согласованные экспорты."
    )
    revision = DeviceRevision.model_validate(payload)
    assert (
        revision.routes_evidence is not None and revision.routes_evidence.scope == "routing_table"
    )
    payload["observation_window"] = ObservationWindow(
        start=OBSERVED_AT, end=later - timedelta(seconds=1), reason="Слишком узкий интервал."
    )
    with pytest.raises(ValidationError, match="интервала"):
        DeviceRevision.model_validate(payload)


def test_future_capture_manual_entry_and_naive_observation_are_rejected() -> None:
    source = make_revision().sources[0].model_dump()
    source["captured_at"] = IMPORTED_AT + timedelta(seconds=1)
    with pytest.raises(ValidationError):
        rebuild(sources=[source])
    with pytest.raises(ValidationError, match="часовой пояс"):
        ObservationEvidence(
            observed_at=OBSERVED_AT.replace(tzinfo=None), method="synthetic", reference="Тест."
        )
    with pytest.raises(ValidationError):
        ObservationWindow(start=IMPORTED_AT, end=OBSERVED_AT, reason="Обратный порядок.")


def test_unknown_schema_version_is_rejected() -> None:
    with pytest.raises(ValidationError):
        rebuild(schema_version="3.0.0")


@pytest.mark.parametrize("version", [None, "1.0.0"])
def test_legacy_schema_is_read_without_inventing_evidence(version: str | None) -> None:
    payload = make_revision().model_dump(mode="json")
    if version is None:
        payload.pop("schema_version")
    else:
        payload["schema_version"] = version
    payload["interfaces"][0]["addresses"] = ["10.0.0.0/24"]
    restored = DeviceRevision.model_validate(payload)
    assert restored.observed_at is None
    assert restored.legacy_observed_at == OBSERVED_AT
    assert restored.interfaces_status == restored.routes_status == DataStatus.UNKNOWN
    assert restored.interfaces[0].addresses_status == DataStatus.UNKNOWN
    assert restored.interfaces[0].data_status == DataStatus.UNKNOWN
    assert restored.routes_evidence is None and restored.migration_limitations
    assert payload["routes_status"] == "known"


def test_revalidation_catches_untrusted_model_copy_update() -> None:
    invalid = make_revision().routes[0].model_copy(update={"next_hop": "not-an-ip"})
    with pytest.raises(ValidationError):
        rebuild(routes=[invalid])
    invalid_revision = make_revision().model_copy(update={"routes": (invalid,)})
    with pytest.raises(ValidationError):
        DeviceRevision.model_validate(invalid_revision)


def test_actual_previous_golden_is_read_conservatively() -> None:
    path = Path(__file__).parents[1] / "fixtures" / "revisions" / "device_revision_v1.json"
    content = path.read_bytes()
    assert sha256(content).hexdigest() == (
        "ecee4a0fd486ad8d3f670defc16b63682a4028aee8f8e3351e13db1592574cb8"
    )
    restored = DeviceRevision.model_validate_json(content)
    assert restored.observed_at is None
    assert restored.legacy_observed_at == OBSERVED_AT
    assert restored.interfaces[0].addresses == ("10.0.0.0/24",)
    assert restored.interfaces[0].addresses_status == DataStatus.UNKNOWN
    assert restored.routes_status == DataStatus.UNKNOWN
    assert restored.routes[0].administrative_distance is None
    assert restored.migration_limitations


@pytest.mark.parametrize("case", ["future_record", "missing_observation"])
def test_manual_entry_time_is_not_device_observation(case: str) -> None:
    link = make_revision().topology_links[0].model_dump()
    link.update(
        origin=DataOrigin.MANUAL,
        source_document_id=None,
        source_location=None,
        manual_reason="Синтетическое ручное подтверждение.",
        recorded_at=IMPORTED_AT + timedelta(seconds=1) if case == "future_record" else IMPORTED_AT,
        observation=OBSERVATION if case == "future_record" else None,
    )
    evidence = CollectionEvidence(
        scope="topology",
        complete=True,
        manual_reason="Синтетическое основание полноты.",
        recorded_at=IMPORTED_AT,
        observation=OBSERVATION,
    )
    with pytest.raises(ValidationError, match="фиксация|observed_at"):
        rebuild(topology_links=[link], topology_evidence=evidence)
