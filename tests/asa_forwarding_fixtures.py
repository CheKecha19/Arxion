"""Фиксированные входы forwarding adapter из собственных выдержек."""

import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from firewall_compliance.domain.forwarding import ForwardingSource
from firewall_compliance.parsers.contracts import SourceDocument
from firewall_compliance.parsers.forwarding_contracts import ForwardingParseRequest
from tests.forwarding_fixtures import CAPTURED_AT, CONFIGURATION_ID, IMPORTED_AT, REVISION_ID

ROOT = Path(__file__).parent / "fixtures" / "forwarding_asa"
MANIFEST = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
SCENARIOS = tuple(item["id"] for item in MANIFEST["scenarios"])


def forwarding_request(scenario: str) -> ForwardingParseRequest:
    record = next(item for item in MANIFEST["scenarios"] if item["id"] == scenario)
    entry = record["sources"][0]
    source = SourceDocument(
        source_name=entry["path"],
        content=(ROOT / entry["path"]).read_bytes(),
        captured_at=CAPTURED_AT,
    )
    assert source.content_sha256 == entry["sha256"]
    metadata = ForwardingSource(
        source_document_id=uuid5(NAMESPACE_URL, "forwarding:" + scenario),
        source_name=source.source_name,
        content_sha256=source.content_sha256,
        purpose="configuration",
        device_id=record["device_id"],
        command=entry["command"],
        declared_version=entry["declared_version"],
        version_provenance="documentation",
        version_reference="Синтетический manifest; аппаратная сборка не проверена.",
        origin="synthetic",
        origin_reference="Собственная выдержка без клиентских данных.",
        captured_at=source.captured_at,
        selection=entry["selection"],
        extent=entry["extent"],
        encoding=entry["encoding"],
        capture_success=True,
    )
    return ForwardingParseRequest(
        source=source,
        metadata=metadata,
        revision_id=REVISION_ID,
        configuration_id=CONFIGURATION_ID,
        imported_at=IMPORTED_AT,
        context_mode="single",
        firewall_mode="routed",
        address_family="ipv4",
        table_role="data",
        table_id="default",
        profile_reference="Условный профиль собственного сценария, не runtime evidence.",
    )
