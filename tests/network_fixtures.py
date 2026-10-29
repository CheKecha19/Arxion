"""Собственные детерминированные документы для тестов сетевого адаптера."""

from typing import Any

from firewall_compliance.domain import DataOrigin, DataStatus, Interface, SourceLocation
from firewall_compliance.parsers.contracts import SourceDocument
from firewall_compliance.parsers.network_contracts import (
    NetworkDocumentMetadata,
    NetworkInterfaceBinding,
    NetworkParseRequest,
    NetworkSourceKind,
)
from tests.revision_fixtures import IMPORTED_AT, OBSERVATION, OBSERVED_AT, SECOND_SOURCE_ID

COMMANDS = {
    "asa_running_config_interfaces": "show running-config interface",
    "asa_running_config_static_routes": "show running-config route",
    "asa_ipv4_rib": "show route",
}


def make_network_request(
    text: str | bytes,
    kind: NetworkSourceKind = "asa_running_config_interfaces",
    *,
    interfaces: tuple[Interface, ...] | None = None,
    bindings: tuple[NetworkInterfaceBinding, ...] | None = None,
    observed: bool = True,
    **metadata_changes: Any,
) -> NetworkParseRequest:
    source = SourceDocument(
        source_name="synthetic-network.txt",
        content=text.encode("ascii") if isinstance(text, str) else text,
        captured_at=OBSERVED_AT,
        observation=OBSERVATION if observed else None,
    )
    metadata = NetworkDocumentMetadata.model_validate(
        {
            "source_document_id": SECOND_SOURCE_ID,
            "source_kind": kind,
            "device_id": "fixture-device",
            "context_mode": "single",
            "firewall_mode": "routed",
            "declared_version": "9.16",
            "version_provenance": "documentation",
            "version_reference": "Официальные примеры документации ASA 9.16.",
            "origin": "synthetic",
            "origin_reference": "Собственные тестовые данные проекта.",
            "address_family": "ipv4",
            "table_role": "data",
            "table_id": "default",
            "command": COMMANDS[kind],
            "content_sha256": source.content_sha256,
            "encoding": "ascii",
            "selection": "all",
            "extent": "full",
            "capture_success": True,
            "complete": True,
            "completeness_reference": "Полная область собственного synthetic сценария.",
            **metadata_changes,
        }
    )
    if interfaces is None:
        interfaces = (
            Interface(
                interface_id="interface:GigabitEthernet0/0",
                device_id=metadata.device_id,
                origin=DataOrigin.IMPORTED,
                source_document_id=SECOND_SOURCE_ID,
                source_location=SourceLocation(
                    source_name="synthetic-interfaces.txt", line_start=1
                ),
                name="GigabitEthernet0/0",
                addresses=("192.0.2.2/24",),
                addresses_status=DataStatus.KNOWN,
            ),
        )
    if bindings is None:
        bindings = (
            (NetworkInterfaceBinding(label="outside", interface_id=interfaces[0].interface_id),)
            if interfaces
            else ()
        )
    return NetworkParseRequest(
        source=source,
        metadata=metadata,
        imported_at=IMPORTED_AT,
        interfaces=interfaces,
        bindings=bindings,
    )
