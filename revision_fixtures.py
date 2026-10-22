"""Детерминированные фабрики ревизий устройства для тестов Фазы 6."""

from datetime import UTC, datetime
from uuid import UUID

from firewall_compliance import __version__
from firewall_compliance.domain import (
    CollectionEvidence,
    DataOrigin,
    DataStatus,
    Device,
    DeviceRevision,
    Interface,
    NetworkSegment,
    ObservationEvidence,
    ParseResult,
    RevisionSource,
    Route,
    SourceDocumentKind,
    SourceLocation,
    TopologyLink,
)
from tests.fakes import FixtureParser, make_fixture_request

REVISION_ID = UUID("10000000-0000-0000-0000-000000000001")
CONFIGURATION_SOURCE_ID = UUID("20000000-0000-0000-0000-000000000001")
SECOND_SOURCE_ID = UUID("20000000-0000-0000-0000-000000000002")
OBSERVED_AT = datetime(2026, 10, 9, 10, 0, tzinfo=UTC)
IMPORTED_AT = datetime(2026, 10, 9, 10, 1, tzinfo=UTC)
SECOND_HASH = "b" * 64
OBSERVATION = ObservationEvidence(
    observed_at=OBSERVED_AT, method="synthetic", reference="Детерминированный тестовый снимок."
)


def make_parse_result(
    *,
    device_id: str = "fixture-device",
    parser_version: str = "1.0.0",
    content_sha256: str | None = None,
) -> ParseResult:
    """Вернуть воспроизводимый ParseResult с при необходимости изменёнными метаданными."""
    outcome = FixtureParser().parse(make_fixture_request())
    assert isinstance(outcome, ParseResult)
    configuration = outcome.configuration.model_copy(
        update={
            "device_id": device_id,
            "parser_version": parser_version,
            "content_sha256": content_sha256 or outcome.configuration.content_sha256,
        }
    )
    return outcome.model_copy(update={"configuration": configuration})


def make_revision(
    *,
    revision_id: UUID = REVISION_ID,
    device_id: str = "fixture-device",
    parser_version: str = "1.0.0",
    content_sha256: str | None = None,
    sources: tuple[RevisionSource, ...] | None = None,
    interfaces: tuple[Interface, ...] | None = None,
    routes: tuple[Route, ...] | None = None,
    network_segments: tuple[NetworkSegment, ...] | None = None,
    topology_links: tuple[TopologyLink, ...] | None = None,
    interfaces_status: DataStatus = DataStatus.KNOWN,
    routes_status: DataStatus = DataStatus.KNOWN,
    network_segments_status: DataStatus = DataStatus.KNOWN,
    topology_status: DataStatus = DataStatus.KNOWN,
) -> DeviceRevision:
    """Собрать полную или явно неполную ревизию одного тестового устройства."""
    parse_result = make_parse_result(
        device_id=device_id,
        parser_version=parser_version,
        content_sha256=content_sha256,
    )
    configuration_source = RevisionSource(
        source_document_id=CONFIGURATION_SOURCE_ID,
        source_name=parse_result.configuration.source_name,
        content_sha256=parse_result.configuration.content_sha256,
        kind=SourceDocumentKind.CONFIGURATION,
        captured_at=parse_result.configuration.captured_at,
        observation=OBSERVATION,
    )
    revision_sources = sources or (configuration_source,)
    source_id = configuration_source.source_document_id
    source_name = parse_result.configuration.source_name
    location = SourceLocation(source_name=source_name, object_path="$.network")
    revision_interfaces = interfaces
    if revision_interfaces is None:
        revision_interfaces = (
            Interface(
                interface_id="interface:inside",
                device_id=device_id,
                origin=DataOrigin.IMPORTED,
                source_document_id=source_id,
                source_location=location,
                name="inside",
                addresses=("10.0.0.1/24",),
                addresses_status=DataStatus.KNOWN,
                zone="inside",
                enabled=True,
            ),
        )
    revision_routes = routes
    if revision_routes is None:
        revision_routes = (
            Route(
                route_id="route:default",
                device_id=device_id,
                origin=DataOrigin.IMPORTED,
                source_document_id=source_id,
                source_location=location,
                destination="0.0.0.0/0",
                outgoing_interface_id="interface:inside",
                metric=1,
                administrative_distance=1,
                route_kind="static",
            ),
        )
    revision_segments = network_segments
    if revision_segments is None:
        revision_segments = (
            NetworkSegment(
                segment_id="segment:inside",
                device_id=device_id,
                origin=DataOrigin.IMPORTED,
                source_document_id=source_id,
                source_location=location,
                name="inside-network",
                cidrs=("10.0.0.0/24",),
                zone="inside",
            ),
        )
    revision_links = topology_links
    if revision_links is None:
        revision_links = (
            TopologyLink(
                link_id="link:inside-network",
                device_id=device_id,
                origin=DataOrigin.IMPORTED,
                source_document_id=source_id,
                source_location=location,
                left_endpoint_id="interface:inside",
                right_endpoint_id="segment:inside",
            ),
        )
    return DeviceRevision(
        revision_id=revision_id,
        device=Device(
            device_id=device_id,
            vendor="test",
            platform="fixture-platform",
            hostname="fixture-device",
        ),
        parse_result=parse_result,
        sources=revision_sources,
        application_version=__version__,
        observed_at=OBSERVED_AT,
        imported_at=IMPORTED_AT,
        interfaces=revision_interfaces,
        routes=revision_routes,
        network_segments=revision_segments,
        topology_links=revision_links,
        interfaces_status=interfaces_status,
        routes_status=routes_status,
        network_segments_status=network_segments_status,
        topology_status=topology_status,
        interfaces_evidence=CollectionEvidence(
            scope="interfaces", complete=True, source_document_ids=(source_id,)
        )
        if interfaces_status in {DataStatus.KNOWN, DataStatus.ABSENT}
        else None,
        routes_evidence=CollectionEvidence(
            scope="configured_routes", complete=True, source_document_ids=(source_id,)
        )
        if routes_status in {DataStatus.KNOWN, DataStatus.ABSENT}
        else None,
        network_segments_evidence=CollectionEvidence(
            scope="segments", complete=True, source_document_ids=(source_id,)
        )
        if network_segments_status in {DataStatus.KNOWN, DataStatus.ABSENT}
        else None,
        topology_evidence=CollectionEvidence(
            scope="topology",
            complete=True,
            source_document_ids=(source_id,),
            manual_reason="Synthetic ручные сведения."
            if any(fact.origin == DataOrigin.MANUAL for fact in revision_links)
            else None,
            recorded_at=OBSERVED_AT
            if any(fact.origin == DataOrigin.MANUAL for fact in revision_links)
            else None,
            observation=OBSERVATION
            if any(fact.origin == DataOrigin.MANUAL for fact in revision_links)
            else None,
        )
        if topology_status in {DataStatus.KNOWN, DataStatus.ABSENT}
        else None,
    )
