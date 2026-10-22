"""Связь импортированных label/interface с нейтральным локальным анализом."""

from firewall_compliance.analysis.device_decision import analyze_device_decisions
from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.domain import DataStatus, ReachabilityQuery
from firewall_compliance.domain.policy_decision import (
    PolicyBindingEvidence,
    SingleDeviceDecisionResult,
)


def analyze_imported_device(
    imported: NetworkImportResult,
    query: ReachabilityQuery,
    binding: PolicyBindingEvidence,
) -> SingleDeviceDecisionResult:
    """Подтвердить mapping label по документу, не превращая его в зону."""
    imported = NetworkImportResult.model_validate(imported.model_dump(mode="python"))
    binding = PolicyBindingEvidence.model_validate(binding.model_dump(mode="python"))
    documents = [document for document in imported.documents if document.scope == "interfaces"]
    if len(documents) != 1:
        raise ValueError("для привязки ACL нужен один импортированный документ интерфейсов")
    document = documents[0]
    identifiers = {
        identifier
        for label, identifier in document.interface_labels.items()
        if label.casefold() == binding.interface_label.casefold()
    }
    if identifiers != {binding.interface_id}:
        raise ValueError("label ACL не соответствует импортированному interface_id")
    interface = next(
        (item for item in document.interfaces if item.interface_id == binding.interface_id), None
    )
    if interface is None or interface.data_status != DataStatus.KNOWN:
        raise ValueError("mapping ACL требует известного факта интерфейса")
    revision_interface = next(
        (
            item
            for item in imported.revision.interfaces
            if item.interface_id == binding.interface_id
        ),
        None,
    )
    if revision_interface != interface:
        raise ValueError("факт интерфейса документа не совпадает с ревизией")
    settings = [
        item
        for item in document.interface_settings
        if item.interface_id == binding.interface_id
        and item.label is not None
        and item.label.casefold() == binding.interface_label.casefold()
    ]
    if len(settings) != 1:
        raise ValueError("mapping label требует согласованных настроек интерфейса")
    result = analyze_device_decisions(imported.revision, query, binding)
    payload = result.model_dump(mode="python")
    payload["policy"]["evidence"]["facts"]["interface_mapping"] = {
        "source_document_id": str(document.source.source_document_id),
        "content_sha256": document.source.content_sha256,
        "parser_id": document.parser_id,
        "parser_version": document.parser_version,
        "settings": settings[0].model_dump(mode="json"),
    }
    return SingleDeviceDecisionResult.model_validate(payload)
