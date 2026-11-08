"""Общие для CLI и desktop экспорты аналитической карты ACL."""

import json
from collections.abc import Sequence
from datetime import datetime
from html import escape
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from firewall_compliance.analysis.acl_map import AclMapFilter, build_acl_map, filter_acl_relations
from firewall_compliance.domain.acl_map import AclMap
from firewall_compliance.domain.base import DomainModel
from firewall_compliance.domain.parse_result import ParseIssue
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.snapshot import freeze_snapshot_fields
from firewall_compliance.domain.switch_policy import rule_purpose


class AclMapBatchFailure(DomainModel):
    """An explicit failed input; an absent graph is never an empty policy."""

    model_config = ConfigDict(frozen=True)
    input_reference: str = Field(min_length=1)
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    source_name: str | None = None
    content_sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    diagnostics: tuple[ParseIssue, ...] = ()


class AclMapBatchItem(DomainModel):
    model_config = ConfigDict(frozen=True)
    input_reference: str = Field(min_length=1)
    graph: AclMap


class AclMapBatch(DomainModel):
    """Independent device/revision maps, without address-based merging."""

    model_config = ConfigDict(frozen=True)
    schema_version: Literal["1.0.0"] = "1.0.0"
    mode: Literal["declared_rules_batch"] = "declared_rules_batch"
    items: tuple[AclMapBatchItem, ...] = ()
    failures: tuple[AclMapBatchFailure, ...] = ()

    @model_validator(mode="after")
    def validate_batch(self) -> "AclMapBatch":
        references = [item.input_reference for item in self.items]
        references.extend(item.input_reference for item in self.failures)
        if len(references) != len(set(references)):
            raise ValueError("batch input references must be unique")
        for item in self.items:
            AclMap.model_validate(item.graph.model_dump(mode="python"))
        freeze_snapshot_fields(self)
        return self


def build_acl_map_batch(
    revisions: Sequence[tuple[str, DeviceRevision]],
    *,
    built_at: datetime,
    failures: tuple[AclMapBatchFailure, ...] = (),
    max_maps: int = 1000,
    max_rules: int = 100_000,
) -> AclMapBatch:
    """Bounded batch projection over already captured immutable revisions."""
    if max_maps < 1 or max_rules < 1:
        raise ValueError("batch budgets must be positive")
    if len(revisions) + len(failures) > max_maps:
        raise ValueError("batch map budget exceeded")
    if sum(len(revision.parse_result.rules) for _, revision in revisions) > max_rules:
        raise ValueError("batch rule budget exceeded")
    items = tuple(
        AclMapBatchItem(input_reference=reference, graph=build_acl_map(revision, built_at=built_at))
        for reference, revision in revisions
    )
    return AclMapBatch(items=items, failures=failures)


def export_acl_map_html(graph: AclMap, *, filters: AclMapFilter | None = None) -> str:
    """Standalone escaped report; selected rows retain their original evidence."""
    validated = AclMap.model_validate(graph.model_dump(mode="python"))
    filters = filters or AclMapFilter()
    relations = filter_acl_relations(validated, filters)
    revision = validated.revision
    show_purpose = revision.parse_result.switch_policies is not None or any(
        relation.rule.policy_purpose is not None for relation in validated.relations
    )
    header = (
        f"<h1>Карта заданных условий ACL</h1><p>Устройство: {escape(revision.device.device_id)}; "
        f"ревизия: {revision.revision_id}; построена: {escape(validated.built_at.isoformat())}</p>"
        f"<p>Показано правил: {len(relations)} из {len(validated.relations)}. "
        "Фильтры меняют представление; неизвестное совпадение не доказывает доступ.</p>"
        f"<details><summary>Фильтры</summary><pre>{escape(filters.model_dump_json(indent=2))}</pre>"
        "</details><ul>"
        + "".join(f"<li>{escape(reason)}</li>" for reason in validated.limitations)
        + "</ul><h2>Источники</h2><ul>"
        + "".join(
            f"<li>{escape(source.source_name)}; {source.source_document_id}; "
            f"SHA-256 {escape(source.content_sha256)}</li>"
            for source in revision.sources
        )
        + "</ul>"
    )
    rows: list[str] = []
    for relation in relations:
        rule = relation.rule
        cells = (
            rule.policy_id or "unknown",
            *((rule_purpose(rule),) if show_purpose else ()),
            rule.rule_id,
            str(rule.sequence),
            rule.action.value,
            "enabled" if rule.enabled else "disabled",
            relation.condition_status,
            json.dumps(
                [value.model_dump(mode="json") for value in rule.sources], ensure_ascii=False
            ),
            json.dumps(
                [value.model_dump(mode="json") for value in rule.destinations], ensure_ascii=False
            ),
            json.dumps(
                [value.model_dump(mode="json") for value in rule.services], ensure_ascii=False
            ),
            rule.source_location.model_dump_json(),
        )
        rows.append(
            "<tr>" + "".join(f"<td><pre>{escape(cell)}</pre></td>" for cell in cells) + "</tr>"
        )
    labels = (
        "ACL",
        *(("Назначение",) if show_purpose else ()),
        "Правило",
        "Порядок",
        "Действие",
        "Активность",
        "Условия",
        "Источник",
        "Назначение",
        "Сервис",
        "Доказательство",
    )
    table = (
        "<table><thead><tr>"
        + "".join(f"<th>{label}</th>" for label in labels)
        + "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    return (
        '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Карта ACL</title>'
        "<style>body{font:14px system-ui;margin:24px;color:#182434}"
        "table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #ccd3dc;padding:8px;text-align:left;vertical-align:top}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px monospace;max-width:40em}"
        "th{background:#edf2f9}li{margin:5px 0}</style><body>" + header + table + "</body></html>"
    )


def export_acl_map_json(graph: AclMap) -> str:
    """Проверить проекцию и включить ограничения вместе с нормализованным снимком."""
    validated = AclMap.model_validate(graph.model_dump(mode="python"))
    return validated.model_dump_json(indent=2)


def export_acl_map_dot(graph: AclMap) -> str:
    """Сформировать DOT без Graphviz и без исполняемых атрибутов источника."""
    validated = AclMap.model_validate(graph.model_dump(mode="python"))
    configuration = validated.revision.parse_result.configuration
    graph_label = "\n".join(
        (
            "declared_rules; not reachability",
            f"device={validated.revision.device.device_id}",
            f"revision={validated.revision.revision_id}",
            f"source={configuration.source_name}; sha256={configuration.content_sha256}",
            *validated.limitations,
        )
    )
    lines = ["digraph acl_map {", f"  graph [label={_quote(graph_label)}];"]
    for node in validated.nodes:
        value = node.endpoint if node.endpoint is not None else node.service
        label = value.name if value is not None else f"unknown:{node.unknown_dimension}"
        if node.endpoint is not None:
            endpoint = node.endpoint
            values = (
                *endpoint.cidrs,
                *(f"{item.start}-{item.end}" for item in endpoint.ip_ranges),
                *((endpoint.fqdn,) if endpoint.fqdn is not None else ()),
            )
            label += f"\n{endpoint.kind.value} | {endpoint.resolution_status.value}"
            if values:
                label += "\n" + ", ".join(values)
        elif node.service is not None:
            service = node.service
            ports = ", ".join(f"{item.start}-{item.end}" for item in service.port_ranges)
            label += f"\n{service.protocol.value} | {service.resolution_status.value}"
            if ports:
                label += "\n" + ports
        shape = "ellipse" if node.kind == "endpoint" else "box"
        lines.append(f"  {_quote(node.node_id)} [label={_quote(label)}, shape={shape}];")
    for relation in validated.relations:
        rule = relation.rule
        label = (
            f"{rule.rule_id} | {rule.action.value} | sequence={rule.sequence} | "
            f"{'enabled' if rule.enabled else 'disabled'} | {relation.condition_status}"
        )
        if rule.policy_purpose is not None or validated.revision.parse_result.switch_policies:
            label += f" | purpose={rule_purpose(rule)}"
        location = rule.source_location
        label += (
            f"\npolicy={rule.policy_id}; direction={rule.policy_direction}"
            f"\nsource={location.source_name}; line={location.line_start}; "
            f"path={location.object_path}; object={location.object_id}"
        )
        lines.append(f"  {_quote(relation.relation_id)} [label={_quote(label)}, shape=diamond];")
        for role, identifiers in (
            ("source", relation.source_node_ids),
            ("service", relation.service_node_ids),
        ):
            for node_id in identifiers:
                lines.append(
                    f"  {_quote(node_id)} -> {_quote(relation.relation_id)} [label={_quote(role)}];"
                )
        for node_id in relation.destination_node_ids:
            lines.append(
                f"  {_quote(relation.relation_id)} -> {_quote(node_id)} [label=destination];"
            )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
