"""Собственные synthetic RIB в канонической модели, без имитации ASA-экспорта."""

import hashlib
import json
from typing import Any

from firewall_compliance.domain import (
    CollectionEvidence,
    DataOrigin,
    DataStatus,
    DeviceRevision,
    Protocol,
    ReachabilityQuery,
    RevisionSource,
    Route,
    SourceDocumentKind,
    SourceLocation,
)
from tests.revision_fixtures import (
    OBSERVATION,
    OBSERVED_AT,
    REVISION_ID,
    SECOND_SOURCE_ID,
    make_revision,
)

RIB_NAME = "synthetic-rib.json"


def make_route(route_id: str = "default", destination: str = "0.0.0.0/0", **changes: Any) -> Route:
    payload = {
        "route_id": route_id,
        "device_id": "fixture-device",
        "origin": DataOrigin.IMPORTED,
        "source_document_id": SECOND_SOURCE_ID,
        "source_location": SourceLocation(
            source_name=RIB_NAME, object_path=f"$.routes[{json.dumps(route_id)}]"
        ),
        "destination": destination,
        "outgoing_interface_id": "interface:inside",
        "administrative_distance": 1,
        "metric": 0,
        "route_kind": "static",
        **changes,
    }
    return Route.model_validate(payload)


def make_rib_revision(
    routes: tuple[Route, ...] | None = None,
    *,
    complete: bool = True,
    status: DataStatus = DataStatus.KNOWN,
) -> DeviceRevision:
    facts = (make_route(),) if routes is None else routes
    payload = make_revision().model_dump(mode="python")
    rib_bytes = json.dumps(
        {
            "routes": {
                route.route_id: route.model_dump(mode="json")
                for route in sorted(facts, key=lambda route: route.route_id)
            }
        },
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    source = RevisionSource(
        source_document_id=SECOND_SOURCE_ID,
        source_name=RIB_NAME,
        content_sha256=hashlib.sha256(rib_bytes).hexdigest(),
        kind=SourceDocumentKind.ROUTING_TABLE,
        captured_at=OBSERVED_AT,
        observation=OBSERVATION,
    )
    payload.update(
        routes=facts,
        sources=(*payload["sources"], source),
        routes_status=status,
        routes_evidence=CollectionEvidence(
            scope="routing_table",
            complete=complete,
            source_document_ids=(SECOND_SOURCE_ID,),
        ),
    )
    return DeviceRevision.model_validate(payload)


def make_query(**changes: Any) -> ReachabilityQuery:
    return ReachabilityQuery.model_validate(
        {
            "revision_id": REVISION_ID,
            "device_id": "fixture-device",
            "ingress_interface_id": "interface:inside",
            "source_ip": "10.0.0.10",
            "destination_ip": "198.51.100.25",
            "protocol": Protocol.TCP,
            "destination_port": 443,
            **changes,
        }
    )
