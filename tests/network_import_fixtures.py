"""Воспроизводимый synthetic pipeline конфигурации и сетевых документов."""

from uuid import UUID

from firewall_compliance.application.network_import import (
    NetworkImportResult,
    import_network_documents,
)
from firewall_compliance.domain import (
    Device,
    DeviceRevision,
    ParseResult,
    RevisionSource,
    SourceDocumentKind,
)
from firewall_compliance.parsers import CiscoAsaParser, ParseRequest, SourceDocument
from firewall_compliance.parsers.network_contracts import NetworkParseRequest, NetworkSourceKind
from tests.network_fixtures import make_network_request
from tests.revision_fixtures import (
    CONFIGURATION_SOURCE_ID,
    IMPORTED_AT,
    OBSERVATION,
    OBSERVED_AT,
    REVISION_ID,
)

NETWORK_REVISION_ID = UUID("10000000-0000-0000-0000-000000000099")
POLICY = (
    b"ASA Version 9.16(4)\nhostname network-synthetic\n"
    b"access-list INSIDE extended permit tcp any any eq 443\n"
    b"access-group INSIDE in interface inside\n"
)
INTERFACES = (
    "interface GigabitEthernet0/0\n nameif outside\n security-level 0\n"
    " ip address 192.0.2.2 255.255.255.0\n no shutdown\n!\n"
    "interface GigabitEthernet0/1\n nameif inside\n security-level 100\n"
    " ip address 10.20.0.1 255.255.255.0\n!\n"
)
CONFIGURED = "route outside 0.0.0.0 0.0.0.0 192.0.2.1 1\nroute null0 203.0.113.0 255.255.255.0\n"
RIB = (
    "Gateway of last resort is 192.0.2.1 to network 0.0.0.0\n"
    "C 192.0.2.0 255.255.255.0 is directly connected, outside\n"
    "C 10.20.0.0 255.255.255.0 is directly connected, inside\n"
    "S* 0.0.0.0 0.0.0.0 [1/0] via 192.0.2.1, outside\n"
)


def make_network_base(*, observed: bool = True) -> DeviceRevision:
    source = SourceDocument(
        source_name="network-policy.cfg",
        content=POLICY,
        captured_at=OBSERVED_AT,
        observation=OBSERVATION if observed else None,
    )
    parsed = CiscoAsaParser().parse(ParseRequest(source=source, imported_at=IMPORTED_AT))
    assert isinstance(parsed, ParseResult)
    return DeviceRevision(
        revision_id=REVISION_ID,
        device=Device(
            device_id=parsed.configuration.device_id, vendor="cisco", platform="asa-9.16"
        ),
        parse_result=parsed,
        sources=(
            RevisionSource(
                source_document_id=CONFIGURATION_SOURCE_ID,
                source_name=source.source_name,
                content_sha256=source.content_sha256,
                kind=SourceDocumentKind.CONFIGURATION,
                captured_at=source.captured_at,
                observation=source.observation,
            ),
        ),
        application_version="0.1.0a0",
        observed_at=OBSERVED_AT if observed else None,
        imported_at=IMPORTED_AT,
    )


def make_document(
    base: DeviceRevision, text: str | bytes, kind: NetworkSourceKind, **metadata_changes: object
) -> NetworkParseRequest:
    index = {
        "asa_running_config_interfaces": 10,
        "asa_running_config_static_routes": 11,
        "asa_ipv4_rib": 12,
    }[kind]
    request = make_network_request(
        text,
        kind,
        interfaces=(),
        bindings=(),
        device_id=base.device.device_id,
        source_document_id=UUID(f"20000000-0000-0000-0000-{index:012d}"),
        **metadata_changes,
    )
    payload = request.model_dump(mode="python")
    payload["source"]["source_name"] = f"{kind}.txt"
    return NetworkParseRequest.model_validate(payload)


def import_scenario(scenario: str = "complete") -> NetworkImportResult:
    base = make_network_base()
    requests = [
        make_document(base, INTERFACES, "asa_running_config_interfaces"),
        make_document(base, CONFIGURED, "asa_running_config_static_routes"),
    ]
    if scenario != "configured_only":
        requests.append(
            make_document(
                base,
                RIB
                + (
                    "L 192.0.2.2 255.255.255.255 is directly connected, outside\n"
                    if scenario == "unsupported"
                    else ""
                ),
                "asa_ipv4_rib",
            )
        )
    result = import_network_documents(base, tuple(requests), revision_id=NETWORK_REVISION_ID)
    assert isinstance(result, NetworkImportResult)
    return result
