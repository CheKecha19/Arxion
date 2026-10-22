"""Общие для CLI и desktop экспорты аналитической карты ACL."""

import json

from firewall_compliance.domain.acl_map import AclMap


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
