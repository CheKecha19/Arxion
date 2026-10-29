"""Small authored inputs shipped with the harness, independent of ignored tests/.

The two interfaces, documentation addresses and policy are deliberately synthetic.
They exercise parser DTOs without customer exports or assumptions of observation.
No file discovery, network access or external fixture package is required.
"""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from firewall_compliance import __version__
from firewall_compliance.domain import Device, DeviceRevision, ParseResult, RevisionSource
from firewall_compliance.domain.enums import SourceDocumentKind
from firewall_compliance.domain.observation import ObservationEvidence
from firewall_compliance.parsers import CiscoAsaParser, ParseRequest, SourceDocument
from firewall_compliance.parsers.network_contracts import (
    NetworkDocumentMetadata,
    NetworkParseRequest,
    NetworkSourceKind,
)

INTERFACES = (
    "interface GigabitEthernet0/0\n nameif outside\n security-level 0\n"
    " ip address 192.0.2.2 255.255.255.0\n no shutdown\n!\n"
    "interface GigabitEthernet0/1\n nameif inside\n security-level 100\n"
    " ip address 198.51.100.1 255.255.255.0\n no shutdown\n!\n"
)
POLICY = (
    b"ASA Version 9.16(4)\nhostname harness-authored-synthetic\n"
    b"access-list INSIDE extended permit tcp any any eq 443\n"
    b"access-group INSIDE in interface inside\n"
)
CAPTURED = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
IMPORTED = datetime(2026, 10, 1, 12, 1, tzinfo=UTC)
COMMANDS = {
    "asa_running_config_interfaces": "show running-config interface",
    "asa_running_config_static_routes": "show running-config route",
    "asa_ipv4_rib": "show route",
}


def make_network_base(*, observed: bool = True) -> DeviceRevision:
    observation = (
        ObservationEvidence(
            observed_at=CAPTURED,
            method="synthetic",
            reference="Authored harness observation scenario",
        )
        if observed
        else None
    )
    source = SourceDocument(
        source_name="harness-policy.cfg",
        content=POLICY,
        captured_at=CAPTURED,
        observation=observation,
    )
    parsed = CiscoAsaParser().parse(ParseRequest(source=source, imported_at=IMPORTED))
    assert isinstance(parsed, ParseResult)
    return DeviceRevision(
        revision_id=UUID("e42fea14-c47b-42d3-8682-9256fd6a7a01"),
        device=Device(
            device_id=parsed.configuration.device_id, vendor="cisco", platform="asa-9.16"
        ),
        parse_result=parsed,
        sources=(
            RevisionSource(
                source_document_id=UUID("e42fea14-c47b-42d3-8682-9256fd6a7a02"),
                source_name=source.source_name,
                content_sha256=source.content_sha256,
                kind=SourceDocumentKind.CONFIGURATION,
                captured_at=CAPTURED,
                observation=observation,
            ),
        ),
        application_version=__version__,
        observed_at=CAPTURED if observed else None,
        imported_at=IMPORTED,
    )


def make_document(
    base: DeviceRevision, text: str | bytes, kind: NetworkSourceKind, **changes: object
) -> NetworkParseRequest:
    source = SourceDocument(
        source_name="harness-interface-excerpt.cfg",
        content=text.encode("ascii") if isinstance(text, str) else text,
        captured_at=CAPTURED,
    )
    metadata = NetworkDocumentMetadata.model_validate(
        {
            "source_document_id": uuid4(),
            "device_id": base.device.device_id,
            "source_kind": kind,
            "context_mode": "single",
            "context": None,
            "firewall_mode": "routed",
            "declared_version": "9.16(4)",
            "version_provenance": "operator_declared",
            "version_reference": "Version authored for harness parser scenario",
            "origin": "synthetic",
            "origin_reference": "Authored harness excerpt, not a device capture",
            "address_family": "ipv4",
            "table_role": "data",
            "table_id": "default",
            "command": COMMANDS[kind],
            "content_sha256": source.content_sha256,
            "encoding": "ascii",
            "selection": "authored_excerpt",
            "extent": "excerpt",
            "capture_success": False,
            "complete": False,
            "completeness_reference": None,
            **changes,
        }
    )
    return NetworkParseRequest(source=source, metadata=metadata, imported_at=IMPORTED)
