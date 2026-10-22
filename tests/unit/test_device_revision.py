"""Проверки целостности неизменяемой ревизии устройства."""

from datetime import datetime
from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.revision_fixtures import (
    CONFIGURATION_SOURCE_ID,
    OBSERVATION,
    OBSERVED_AT,
    SECOND_HASH,
    SECOND_SOURCE_ID,
    make_revision,
)

from firewall_compliance.domain import (
    CollectionEvidence,
    DataOrigin,
    DataStatus,
    Interface,
    ObservationEvidence,
    RevisionSource,
    SourceDocumentKind,
    SourceLocation,
    TopologyLink,
)


def test_complete_revision_is_serializable_and_immutable() -> None:
    """Полный снимок сериализуется и не допускает подмены времени."""
    revision = make_revision()

    assert revision.model_dump(mode="json")["routes_status"] == "known"
    with pytest.raises((ValidationError, TypeError)):
        revision.observed_at = OBSERVED_AT


def test_known_empty_collection_requires_explicit_completeness() -> None:
    """Доказанно пустой набор допускается с основанием полноты."""
    revision = make_revision(routes=(), routes_status=DataStatus.KNOWN)
    assert revision.routes == ()
    assert revision.routes_evidence is not None and revision.routes_evidence.complete


def test_unknown_network_data_can_be_empty() -> None:
    """Отсутствующие данные остаются unknown до появления достоверного источника."""
    revision = make_revision(
        interfaces=(),
        routes=(),
        network_segments=(),
        topology_links=(),
        interfaces_status=DataStatus.UNKNOWN,
        routes_status=DataStatus.UNKNOWN,
        network_segments_status=DataStatus.UNKNOWN,
        topology_status=DataStatus.UNKNOWN,
    )

    assert revision.routes == ()
    assert revision.routes_status == DataStatus.UNKNOWN


def test_imported_fact_requires_document_identity_and_source_mapping() -> None:
    """Импортированный факт нельзя принять без трассировки до исходного документа."""
    with pytest.raises(ValidationError, match="source mapping"):
        Interface(
            interface_id="interface:outside",
            device_id="fixture-device",
            origin=DataOrigin.IMPORTED,
            name="outside",
        )


def test_fact_from_another_device_or_unknown_document_is_rejected() -> None:
    """Ревизия не смешивает сетевые данные разных устройств или источников."""
    foreign_interface = Interface(
        interface_id="interface:foreign",
        device_id="another-device",
        origin=DataOrigin.IMPORTED,
        source_document_id=UUID("20000000-0000-0000-0000-000000000099"),
        source_location=SourceLocation(source_name="fixture.config", object_path="$.interfaces[1]"),
        name="foreign",
    )

    with pytest.raises(ValidationError, match="Interface должен принадлежать"):
        make_revision(interfaces=(foreign_interface,))


def test_sources_with_same_name_and_different_hashes_remain_distinct() -> None:
    """Имя файла не используется как единственная идентичность документа."""
    extra_source = RevisionSource(
        source_document_id=SECOND_SOURCE_ID,
        source_name="fixture.config",
        content_sha256=SECOND_HASH,
        kind=SourceDocumentKind.ROUTING_TABLE,
        captured_at=OBSERVED_AT,
    )
    revision = make_revision(
        sources=(
            RevisionSource(
                source_document_id=CONFIGURATION_SOURCE_ID,
                source_name="fixture.config",
                content_sha256=make_revision().parse_result.configuration.content_sha256,
                kind=SourceDocumentKind.CONFIGURATION,
                captured_at=OBSERVED_AT,
                observation=OBSERVATION,
            ),
            extra_source,
        )
    )

    assert {source.source_document_id for source in revision.sources} == {
        CONFIGURATION_SOURCE_ID,
        SECOND_SOURCE_ID,
    }


def test_known_network_data_from_another_observation_time_is_rejected() -> None:
    """Разновременные документы не создают ложную полную картину сети."""
    stale_source = RevisionSource(
        source_document_id=SECOND_SOURCE_ID,
        source_name="routes.txt",
        content_sha256=SECOND_HASH,
        kind=SourceDocumentKind.ROUTING_TABLE,
        captured_at=OBSERVED_AT.replace(minute=1),
        observation=ObservationEvidence(
            observed_at=OBSERVED_AT.replace(minute=1),
            method="synthetic",
            reference="Поздний снимок.",
        ),
    )
    stale_interface = Interface(
        interface_id="interface:stale",
        device_id="fixture-device",
        origin=DataOrigin.IMPORTED,
        source_document_id=SECOND_SOURCE_ID,
        source_location=SourceLocation(source_name="routes.txt", line_start=1),
        name="stale",
    )

    with pytest.raises(ValidationError, match="observed_at"):
        payload = make_revision().model_dump(mode="python")
        payload.update(
            sources=(
                RevisionSource(
                    source_document_id=CONFIGURATION_SOURCE_ID,
                    source_name="fixture.config",
                    content_sha256=make_revision().parse_result.configuration.content_sha256,
                    kind=SourceDocumentKind.CONFIGURATION,
                    captured_at=OBSERVED_AT,
                    observation=OBSERVATION,
                ),
                stale_source,
            ),
            interfaces=(stale_interface,),
            interfaces_evidence=CollectionEvidence(
                scope="interfaces", complete=True, source_document_ids=(SECOND_SOURCE_ID,)
            ),
        )
        type(make_revision()).model_validate(payload)


def test_manual_fact_is_preserved_separately_from_imported_data() -> None:
    """Ручное дополнение содержит собственные реквизиты и не выдаётся за импорт."""
    manual_link = TopologyLink(
        link_id="link:manual",
        device_id="fixture-device",
        origin=DataOrigin.MANUAL,
        manual_reason="Связь подтверждена по схеме эксплуатации.",
        recorded_at=OBSERVED_AT,
        observation=OBSERVATION,
        left_endpoint_id="interface:inside",
        right_endpoint_id="segment:inside",
    )
    revision = make_revision(topology_links=(manual_link,))

    assert revision.topology_links[0].origin == DataOrigin.MANUAL
    assert revision.topology_links[0].source_document_id is None


def test_invalid_topology_link_is_rejected() -> None:
    """Связь должна ссылаться только на сущности своей ревизии."""
    invalid_link = TopologyLink(
        link_id="link:invalid",
        device_id="fixture-device",
        origin=DataOrigin.IMPORTED,
        source_document_id=CONFIGURATION_SOURCE_ID,
        source_location=SourceLocation(source_name="fixture.config", object_path="$.links[0]"),
        left_endpoint_id="interface:inside",
        right_endpoint_id="segment:absent",
    )

    with pytest.raises(ValidationError, match="TopologyLink должен ссылаться"):
        make_revision(topology_links=(invalid_link,))


def test_naive_source_time_is_rejected() -> None:
    """Временная отметка исходного документа всегда содержит часовой пояс."""
    with pytest.raises(ValidationError, match="captured_at RevisionSource"):
        RevisionSource(
            source_name="fixture.config",
            content_sha256=SECOND_HASH,
            kind=SourceDocumentKind.ROUTING_TABLE,
            captured_at=datetime(2026, 10, 9, 10, 0),
        )
