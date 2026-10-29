"""Обогащение новой ревизии сетевыми документами без подмены RIB конфигурацией."""

from typing import Literal
from uuid import UUID

from pydantic import ConfigDict, model_validator

from firewall_compliance.devices.ngfw.cisco.asa.network import CiscoAsaNetworkParser
from firewall_compliance.domain import DataStatus, DeviceRevision, ParseIssue, ParseIssueLevel
from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.revision import CollectionEvidence
from firewall_compliance.domain.snapshot import freeze_snapshot_fields
from firewall_compliance.parsers.contracts import ParseFailure
from firewall_compliance.parsers.network_contracts import (
    NetworkInterfaceBinding,
    NetworkParseRequest,
    NetworkParseResult,
)


class NetworkImportResult(DomainModel):
    model_config = ConfigDict(frozen=True)

    schema_version: Literal["0.1.0"] = "0.1.0"
    revision: DeviceRevision
    documents: tuple[NetworkParseResult, ...]
    warnings: tuple[ParseIssue, ...] = ()

    @model_validator(mode="after")
    def validate_sources(self) -> "NetworkImportResult":
        sources = {source.source_document_id: source for source in self.revision.sources}
        if any(
            sources.get(document.source.source_document_id) != document.source
            for document in self.documents
        ):
            raise ValueError("исходные документы должны сохраняться в новой ревизии")
        freeze_snapshot_fields(self)
        return self


def _coherent(revision: DeviceRevision, document: NetworkParseResult) -> bool:
    observation = document.source.observation
    if observation is None or revision.observed_at is None:
        return False
    if revision.observation_window is None:
        return observation.observed_at == revision.observed_at
    return (
        revision.observation_window.start
        <= observation.observed_at
        <= revision.observation_window.end
    )


def import_network_documents(
    base: DeviceRevision,
    requests: tuple[NetworkParseRequest, ...],
    *,
    revision_id: UUID,
) -> NetworkImportResult | ParseFailure:
    """Создать новый снимок; повторное наложение или неоднозначность отклонить."""
    base = DeviceRevision.model_validate(base.model_dump(mode="python"))
    requests = tuple(
        NetworkParseRequest.model_validate(request.model_dump(mode="python"))
        for request in requests
    )
    if revision_id == base.revision_id:
        raise ValueError("новая ревизия требует другой revision_id")
    if base.device.vendor != "cisco" or base.device.platform != "asa-9.16":
        raise ValueError("сетевой профиль требует базовую ревизию Cisco ASA 9.16")
    if base.interfaces or base.routes or base.network_segments or base.topology_links:
        raise ValueError("наложение на существующие сетевые факты запрещено; нужен чистый baseline")
    kinds = [request.metadata.source_kind for request in requests]
    if len(set(kinds)) != len(kinds):
        raise ValueError("несколько документов одной роли требуют отдельного разрешения конфликтов")
    source_ids = [source.source_document_id for source in base.sources] + [
        request.metadata.source_document_id for request in requests
    ]
    if len(set(source_ids)) != len(source_ids):
        raise ValueError("UUID источников не должны повторяться")
    for request in requests:
        if (
            request.metadata.device_id != base.device.device_id
            or request.metadata.context != base.device.context
            or request.imported_at != base.imported_at
        ):
            raise ValueError(
                "документы должны относиться к одному устройству, контексту и запуску импорта"
            )
        if request.interfaces or request.bindings:
            raise ValueError(
                "привязки импорта формируются из документа интерфейсов, а не из внешней подстановки"
            )
    order = {
        "asa_running_config_interfaces": 0,
        "asa_running_config_static_routes": 1,
        "asa_ipv4_rib": 2,
    }
    parser = CiscoAsaNetworkParser()
    documents: list[NetworkParseResult] = []
    interface_document: NetworkParseResult | None = None
    for request in sorted(requests, key=lambda request: order[request.metadata.source_kind]):
        payload = request.model_dump(mode="python")
        if (
            request.metadata.source_kind != "asa_running_config_interfaces"
            and interface_document is not None
        ):
            usable = tuple(
                interface
                for interface in interface_document.interfaces
                if interface.data_status == DataStatus.KNOWN and _coherent(base, interface_document)
            )
            usable_ids = {interface.interface_id for interface in usable}
            payload.update(
                interfaces=usable,
                bindings=tuple(
                    NetworkInterfaceBinding(label=label, interface_id=identifier)
                    for label, identifier in interface_document.interface_labels.items()
                    if identifier in usable_ids
                ),
            )
        outcome = parser.parse(NetworkParseRequest.model_validate(payload))
        if isinstance(outcome, ParseFailure):
            return outcome
        documents.append(outcome)
        if outcome.scope == "interfaces":
            interface_document = outcome
    payload = base.model_dump(mode="python")
    payload.update(
        revision_id=revision_id,
        sources=(*base.sources, *(document.source for document in documents)),
    )
    warnings: list[ParseIssue] = []
    selected = [document for document in documents if document.scope == "interfaces"]
    ribs = [document for document in documents if document.scope == "routing_table"]
    configured = [document for document in documents if document.scope == "configured_routes"]
    selected.extend(ribs or configured)
    for document in selected:
        coherent = _coherent(base, document)
        prefix = "interfaces" if document.scope == "interfaces" else "routes"
        payload[prefix] = document.interfaces if prefix == "interfaces" else document.routes
        status = document.status if coherent else DataStatus.UNKNOWN
        evidence = document.collection_evidence.model_dump(mode="python")
        evidence["complete"] = evidence["complete"] and coherent
        payload[f"{prefix}_status"] = status
        payload[f"{prefix}_evidence"] = CollectionEvidence.model_validate(evidence)
        if not coherent:
            warnings.append(
                ParseIssue(
                    code="network_observation_incoherent",
                    level=ParseIssueLevel.WARNING,
                    message="Сетевой документ не доказывает согласованное наблюдение "
                    "с базовой конфигурацией.",
                )
            )
    return NetworkImportResult(
        revision=DeviceRevision.model_validate(payload),
        documents=tuple(documents),
        warnings=tuple(warnings),
    )
