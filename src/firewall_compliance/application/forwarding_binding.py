"""Проверяемая привязка forwarding-фактов к импортированной ревизии ASA."""

import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import model_validator

from firewall_compliance.application.network_import import NetworkImportResult
from firewall_compliance.domain.enums import DataStatus, ParseIssueLevel, SourceDocumentKind
from firewall_compliance.domain.forwarding import ForwardingLocation, ForwardingModel
from firewall_compliance.domain.parse_result import ParseIssue
from firewall_compliance.parsers.forwarding_contracts import ForwardingParseResult


class ForwardingInterfaceMapping(ForwardingModel):
    interface_id: str
    interface_label: str
    network_interface_id: str | None
    network_source_document_id: UUID | None
    forwarding_source_document_id: UUID
    status: Literal[DataStatus.KNOWN, DataStatus.UNKNOWN]
    source_locations: tuple[ForwardingLocation, ...]


class ForwardingBindingResult(ForwardingModel):
    """Согласованность связи, но не полнота данных и не решение о доступе."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    imported: NetworkImportResult
    forwarding: ForwardingParseResult
    interfaces: tuple[ForwardingInterfaceMapping, ...]
    status: Literal["consistent", "not_enough_evidence"]
    reasons: tuple[ParseIssue, ...] = ()

    @model_validator(mode="after")
    def validate_binding(self) -> "ForwardingBindingResult":
        mappings, reasons = _check_links(self.imported, self.forwarding)
        status = "not_enough_evidence" if reasons else "consistent"
        if self.interfaces != mappings or self.reasons != reasons or self.status != status:
            raise ValueError("результат привязки не соответствует проверенным доказательствам")
        return self


def bind_forwarding_context(
    imported: NetworkImportResult, parsed: ForwardingParseResult
) -> ForwardingBindingResult:
    """Связать снимки без изменения их полноты, inventories и исходных фактов."""
    imported = NetworkImportResult.model_validate(imported.model_dump(mode="python"))
    parsed = ForwardingParseResult.model_validate(parsed.model_dump(mode="python"))
    mappings, reasons = _check_links(imported, parsed)
    return ForwardingBindingResult(
        imported=imported,
        forwarding=parsed,
        interfaces=mappings,
        status="not_enough_evidence" if reasons else "consistent",
        reasons=reasons,
    )


def _check_links(
    imported: NetworkImportResult, parsed: ForwardingParseResult
) -> tuple[tuple[ForwardingInterfaceMapping, ...], tuple[ParseIssue, ...]]:
    revision = imported.revision
    context = parsed.context
    configuration = revision.parse_result.configuration
    if revision.device.vendor != "cisco" or revision.device.platform != "asa-9.16":
        raise ValueError("привязка поддерживает только Cisco ASA 9.16")
    if (
        context.revision_id != revision.revision_id
        or context.configuration_id != configuration.configuration_id
        or context.device_id != revision.device.device_id
        or context.device_context != revision.device.context
        or context.imported_at != revision.imported_at
    ):
        raise ValueError(
            "forwarding context принадлежит другой ревизии, конфигурации или устройству"
        )
    sources = {source.source_document_id: source for source in revision.sources}
    configuration_sources = [s for s in context.sources if s.purpose == "configuration"]
    if len(configuration_sources) != 1 or len(context.sources) != 1:
        raise ValueError("первая привязка требует ровно один конфигурационный forwarding источник")
    source = configuration_sources[0]
    if source.command not in {"show running-config", "show running-config all"}:
        raise ValueError("неподдерживаемая команда forwarding источника")
    if re.fullmatch(r"9\.16(?:\([0-9]+\))?", source.declared_version) is None:
        raise ValueError("версия forwarding источника не соответствует ASA 9.16")
    original = sources.get(source.source_document_id)
    if original is None or original.kind != SourceDocumentKind.CONFIGURATION:
        raise ValueError("forwarding источник должен быть Configuration источником ревизии")
    if (
        source.source_name != original.source_name
        or source.content_sha256.lower() != original.content_sha256.lower()
        or source.captured_at != original.captured_at
        or source.observation != original.observation
        or source.source_name != configuration.source_name
        or source.content_sha256.lower() != configuration.content_sha256.lower()
        or source.captured_at != configuration.captured_at
    ):
        raise ValueError("идентичность конфигурационного источника не подтверждена")

    # Зоны и направление назначаются ACL-парсером по bindings, а не самим ACE.
    excluded = {"source_zone", "destination_zone", "policy_direction", "zone_status"}
    expected_rules = {
        rule.rule_id: rule.model_dump(mode="python", exclude=excluded)
        for rule in revision.parse_result.rules
    }
    actual_rules = {
        rule.rule_id: rule.model_dump(mode="python", exclude=excluded)
        for acl in context.acls
        for rule in acl.rules
    }
    if len(expected_rules) != len(revision.parse_result.rules) or len(actual_rules) != sum(
        len(acl.rules) for acl in context.acls
    ):
        raise ValueError("идентификаторы ACE не должны повторяться")
    if actual_rules != expected_rules:
        raise ValueError("forwarding ACE не совпадают с правилами Configuration")
    reasons: list[ParseIssue] = []

    def missing(code: str, message: str) -> None:
        reasons.append(ParseIssue(code=code, level=ParseIssueLevel.WARNING, message=message))

    if not source.capture_success:
        missing(
            "binding_capture_failed",
            "Успешность получения конфигурационного источника не подтверждена",
        )

    for field, expected in (
        ("context_mode", "single"),
        ("firewall_mode", "routed"),
        ("address_family", "ipv4"),
        ("table_role", "data"),
        ("table_id", "default"),
    ):
        value = getattr(context, field)
        if value is None:
            missing("binding_profile_unknown", f"Не подтверждён профиль: {field}")
        elif value != expected:
            raise ValueError(f"неподдерживаемый профиль привязки: {field}")
    if context.observed_at is not None and revision.observed_at is not None:
        if context.observed_at != revision.observed_at:
            raise ValueError("время наблюдения context не совпадает с ревизией")
    else:
        missing("binding_observation_unknown", "Не подтверждено общее время наблюдения")
    if context.observation_window != revision.observation_window:
        raise ValueError("интервал наблюдения context не совпадает с ревизией")

    def coherent(observed: datetime | None) -> bool:
        if observed is None or revision.observed_at is None:
            return False
        return bool(
            revision.observation_window.start <= observed <= revision.observation_window.end
            if revision.observation_window is not None
            else observed == revision.observed_at
        )

    if not coherent(source.observation.observed_at if source.observation else None):
        missing(
            "binding_source_observation_unknown", "Наблюдение конфигурации не связано с ревизией"
        )
    documents = [doc for doc in imported.documents if doc.scope == "interfaces"]
    if len(documents) > 1:
        raise ValueError("несколько документов интерфейсов не имеют однозначного приоритета")
    for doc in imported.documents:
        metadata = doc.metadata
        commands = {
            "asa_running_config_interfaces": "show running-config interface",
            "asa_running_config_static_routes": "show running-config route",
            "asa_ipv4_rib": "show route",
        }
        if metadata.command != commands[metadata.source_kind]:
            raise ValueError("команда сетевого документа не соответствует его роли")
        if re.fullmatch(r"9\.16(?:\([0-9]+\))?", metadata.declared_version) is None:
            raise ValueError("версия сетевого источника не соответствует ASA 9.16")
        if metadata.device_id != context.device_id or metadata.context != context.device_context:
            raise ValueError("сетевой документ принадлежит другому устройству или context")
        for field, expected in (
            ("context_mode", "single"),
            ("firewall_mode", "routed"),
            ("address_family", "ipv4"),
            ("table_role", "data"),
            ("table_id", "default"),
        ):
            if getattr(metadata, field) != expected:
                raise ValueError(f"неподдерживаемый профиль сетевого документа: {field}")
            value = getattr(context, field)
            if value is not None and value != getattr(metadata, field):
                raise ValueError(f"профиль сетевого документа противоречит context: {field}")
    document = documents[0] if documents else None
    if document is not None and document.interfaces != revision.interfaces:
        raise ValueError("набор сетевых интерфейсов не совпадает с ревизией")
    ribs = [doc for doc in imported.documents if doc.scope == "routing_table"]
    configured = [doc for doc in imported.documents if doc.scope == "configured_routes"]
    if len(ribs) > 1 or len(configured) > 1:
        raise ValueError("неоднозначные сетевые документы маршрутов")
    selected_routes = ribs or configured
    if selected_routes and selected_routes[0].routes != revision.routes:
        raise ValueError("выбранный набор маршрутов не совпадает с ревизией")
    for selected_document in [*documents, *selected_routes]:
        if not selected_document.metadata.capture_success:
            missing(
                "binding_capture_failed", "Успешность получения сетевого документа не подтверждена"
            )
        observation = selected_document.source.observation
        if not coherent(observation.observed_at if observation else None):
            missing(
                "binding_network_observation_unknown",
                "Наблюдение выбранного сетевого документа не связано с ревизией: "
                + selected_document.source.source_name,
            )
    if document is None:
        missing("binding_interfaces_missing", "Нет сетевого документа интерфейсов")
    facts = {fact.interface_id: fact for fact in document.interfaces} if document else {}
    revision_facts = {fact.interface_id: fact for fact in revision.interfaces}
    settings = {item.interface_id: item for item in document.interface_settings} if document else {}
    mappings: list[ForwardingInterfaceMapping] = []
    for interface in context.interfaces:
        network_id = "interface:" + interface.interface_id
        fact = facts.get(network_id)
        setting = settings.get(network_id)
        if document is not None:
            claimed_id = document.interface_labels.get(interface.label.casefold())
            if claimed_id is not None and claimed_id != network_id:
                raise ValueError("карта labels противоречит forwarding интерфейсу")
        locations = [interface.location]
        known = False
        if fact is not None and document is not None:
            if fact != revision_facts.get(network_id):
                raise ValueError("сетевой интерфейс не совпадает с фактом ревизии")
            if fact.name != interface.interface_id:
                raise ValueError("физическое имя интерфейса противоречит forwarding context")
            if fact.source_location is not None:
                locations.append(
                    ForwardingLocation(
                        source_document_id=document.source.source_document_id,
                        location=fact.source_location,
                    )
                )
            if setting is not None:
                if setting.label is not None and setting.label != interface.label:
                    raise ValueError("label интерфейса противоречит forwarding context")
                if (
                    setting.security_level is not None
                    and interface.security_level is not None
                    and setting.security_level != interface.security_level
                ):
                    raise ValueError("security-level интерфейса противоречит forwarding context")
                if any(
                    loc.source_name != document.source.source_name
                    or not (loc.line_start or loc.object_path or loc.object_id)
                    or fact.source_location is None
                    or fact.source_location.line_start is None
                    or loc.line_start is None
                    or not fact.source_location.line_start
                    < loc.line_start
                    <= (loc.line_end or loc.line_start)
                    <= (fact.source_location.line_end or fact.source_location.line_start)
                    for loc in setting.source_locations
                ):
                    raise ValueError(
                        "source mapping настроек интерфейса не соответствует документу"
                    )
                locations.extend(
                    ForwardingLocation(
                        source_document_id=document.source.source_document_id, location=loc
                    )
                    for loc in setting.source_locations
                )
                known = (
                    fact.data_status == DataStatus.KNOWN
                    and document.metadata.capture_success
                    and setting.label == interface.label
                    and setting.security_level is not None
                    and interface.security_status == DataStatus.KNOWN
                    and interface.physical_l3 is True
                    and claimed_id == network_id
                    and len({loc.line_start for loc in setting.source_locations}) >= 2
                    and coherent(
                        document.source.observation.observed_at
                        if document.source.observation
                        else None
                    )
                )
        if not known:
            missing(
                "binding_interface_unknown",
                f"Связь интерфейса не подтверждена: {interface.interface_id}",
            )
        mappings.append(
            ForwardingInterfaceMapping(
                interface_id=interface.interface_id,
                interface_label=interface.label,
                network_interface_id=network_id if fact is not None else None,
                network_source_document_id=document.source.source_document_id if document else None,
                forwarding_source_document_id=source.source_document_id,
                status=DataStatus.KNOWN if known else DataStatus.UNKNOWN,
                source_locations=tuple(locations),
            )
        )
    if not context.interfaces:
        missing("binding_interfaces_unknown", "Forwarding context не содержит интерфейсов")
    return tuple(mappings), tuple(reasons)
