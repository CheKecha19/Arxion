"""Согласованные снимки ASA из синтетических входов существующих парсеров."""

from typing import Any

from pydantic import BaseModel

from firewall_compliance.application.network_import import (
    NetworkImportResult,
    import_network_documents,
)
from firewall_compliance.domain import Device, DeviceRevision, ParseResult, RevisionSource
from firewall_compliance.domain.enums import SourceDocumentKind
from firewall_compliance.domain.forwarding import ForwardingSource
from firewall_compliance.parsers import CiscoAsaParser, ParseRequest, SourceDocument
from firewall_compliance.parsers.cisco_asa_forwarding import CiscoAsaForwardingParser
from firewall_compliance.parsers.forwarding_contracts import (
    ForwardingParseRequest,
    ForwardingParseResult,
)
from tests.network_import_fixtures import INTERFACES, NETWORK_REVISION_ID, POLICY, make_document
from tests.revision_fixtures import (
    CONFIGURATION_SOURCE_ID,
    IMPORTED_AT,
    OBSERVATION,
    OBSERVED_AT,
    REVISION_ID,
)

CONTENT = POLICY + INTERFACES.encode("ascii")


def unsafe_copy[T: BaseModel](model: T, **updates: Any) -> T:
    """Обойти валидацию копии, сохраняя вложенные экземпляры для проверки защиты."""
    return type(model).model_construct(**{**dict(model.__dict__), **updates})


def make_binding_inputs(
    *, observed: bool = True, interface_text: str = INTERFACES, include_document: bool = True
) -> tuple[NetworkImportResult, ForwardingParseResult]:
    source = SourceDocument(
        source_name="synthetic-binding.cfg",
        content=CONTENT,
        captured_at=OBSERVED_AT,
        observation=OBSERVATION if observed else None,
    )
    baseline = CiscoAsaParser().parse(ParseRequest(source=source, imported_at=IMPORTED_AT))
    assert isinstance(baseline, ParseResult), baseline
    base = DeviceRevision(
        revision_id=REVISION_ID,
        device=Device(
            device_id=baseline.configuration.device_id, vendor="cisco", platform="asa-9.16"
        ),
        parse_result=baseline,
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
    requests = (
        (make_document(base, interface_text, "asa_running_config_interfaces", observed=observed),)
        if include_document
        else ()
    )
    imported = import_network_documents(base, requests, revision_id=NETWORK_REVISION_ID)
    assert isinstance(imported, NetworkImportResult), imported
    metadata = ForwardingSource(
        source_document_id=CONFIGURATION_SOURCE_ID,
        source_name=source.source_name,
        content_sha256=source.content_sha256,
        purpose="configuration",
        device_id=base.device.device_id,
        command="show running-config",
        declared_version="9.16",
        version_provenance="documentation",
        version_reference="Синтетический пример ASA 9.16.",
        origin="synthetic",
        origin_reference="Собственный тестовый пример без клиентских данных.",
        captured_at=source.captured_at,
        observation=source.observation,
        selection="all",
        extent="full",
        encoding="ascii",
        capture_success=True,
    )
    parsed = CiscoAsaForwardingParser().parse(
        ForwardingParseRequest(
            source=source,
            metadata=metadata,
            revision_id=imported.revision.revision_id,
            configuration_id=baseline.configuration.configuration_id,
            imported_at=IMPORTED_AT,
            context_mode="single",
            firewall_mode="routed",
            address_family="ipv4",
            table_role="data",
            table_id="default",
            profile_reference="Согласованный профиль синтетического сетевого документа.",
        )
    )
    assert isinstance(parsed, ForwardingParseResult), parsed
    return imported, parsed
