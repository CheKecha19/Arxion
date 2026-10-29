"""Контракт карты объявленных ACL без вычисления эффективных разрешений."""

import json
import re
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError
from tests.policy_fixtures import endpoint, policy_revision, rule

from firewall_compliance.analysis.acl_map import build_acl_map, select_acl_relations
from firewall_compliance.application.acl_map import export_acl_map_dot, export_acl_map_json
from firewall_compliance.domain import (
    DataStatus,
    DeviceRevision,
    Endpoint,
    EndpointKind,
    IpRange,
    ParseCoverage,
    ParseIssue,
    ParseIssueLevel,
    ParseResult,
    PortRange,
    Protocol,
    RuleAction,
    Service,
    UnsupportedConstruct,
)
from firewall_compliance.domain.acl_map import AclMap


def make_graph(**changes: Any) -> AclMap:
    """Собрать карту одной синтетической политики в момент импорта."""
    revision = policy_revision(rule(10, **changes))
    return build_acl_map(revision, built_at=revision.imported_at)


def dot_node_labels(dot: str) -> dict[str, str]:
    """Прочитать строковые подписи объявлений узлов для проверки вида DOT."""
    pattern = r'  "([^"\n]+)" \[label=("(?:[^"\\]|\\.)*"), shape=(?:ellipse|box|diamond)\];'
    return {match[1]: json.loads(match[2]) for match in re.finditer(pattern, dot)}


@pytest.mark.parametrize("action", list(RuleAction))
@pytest.mark.parametrize("enabled", [True, False])
def test_should_preserve_every_action_and_disabled_rule(action: RuleAction, enabled: bool) -> None:
    """Каждое объявленное правило сохраняется независимо от действия и активности."""
    original = rule(10, action=action, enabled=enabled)
    revision = policy_revision(original)

    graph = build_acl_map(revision, built_at=revision.imported_at)

    assert len(graph.relations) == 1
    assert graph.relations[0].rule == original
    assert graph.relations[0].condition_status == "known"
    assert graph.mode == "declared_rules"


@pytest.mark.parametrize(
    "field", ["match_status", "source_status", "destination_status", "service_status"]
)
@pytest.mark.parametrize("status", [DataStatus.UNKNOWN, DataStatus.UNSUPPORTED])
def test_should_preserve_unknown_and_unsupported_conditions(field: str, status: DataStatus) -> None:
    """Неизвестное или неподдержанное условие не превращается в известное."""
    graph = make_graph(**{field: status})

    assert graph.relations[0].condition_status == status.value
    assert getattr(graph.relations[0].rule, field) == status
    assert len(graph.relations) == 1


@pytest.mark.parametrize("dimension", ["sources", "destinations", "services"])
@pytest.mark.parametrize("status", [DataStatus.UNKNOWN, DataStatus.UNSUPPORTED])
def test_should_use_value_resolution_status(dimension: str, status: DataStatus) -> None:
    """Статус вложенного адреса или сервиса влияет на статус связи."""
    original = rule(10)
    value = getattr(original, dimension)[0].model_copy(update={"resolution_status": status})

    graph = make_graph(**{dimension: (value,)})

    assert graph.relations[0].condition_status == status.value


def test_should_prioritize_unsupported_over_unknown() -> None:
    """Неподдержанное условие сохраняется при наличии другого неизвестного поля."""
    graph = make_graph(source_status=DataStatus.UNKNOWN, service_status=DataStatus.UNSUPPORTED)

    assert graph.relations[0].condition_status == "unsupported"


@pytest.mark.parametrize("dimension", ["source", "destination", "service"])
def test_should_replace_empty_condition_with_unknown_placeholder(dimension: str) -> None:
    """Пустое условие обозначается неизвестным узлом, а не значением any."""
    field = {"source": "sources", "destination": "destinations", "service": "services"}[dimension]
    graph = make_graph(**{field: (), f"{dimension}_status": DataStatus.UNKNOWN})
    identifiers = getattr(graph.relations[0], f"{dimension}_node_ids")
    nodes = {node.node_id: node for node in graph.nodes}

    assert len(identifiers) == 1
    placeholder = nodes[identifiers[0]]
    assert placeholder.kind == "unknown"
    assert placeholder.unknown_dimension == dimension
    assert placeholder.endpoint is None and placeholder.service is None
    assert graph.relations[0].condition_status == "unknown"


def test_should_keep_empty_rule_placeholders_distinct() -> None:
    """Неизвестные измерения разных правил не сливаются в общий any."""
    changes = dict(
        sources=(),
        destinations=(),
        services=(),
        source_status=DataStatus.UNKNOWN,
        destination_status=DataStatus.UNKNOWN,
        service_status=DataStatus.UNKNOWN,
    )
    revision = policy_revision(rule(10, **changes), rule(20, **changes))

    graph = build_acl_map(revision, built_at=revision.imported_at)

    assert len(graph.nodes) == 6
    assert all(node.kind == "unknown" for node in graph.nodes)
    assert {node.unknown_dimension for node in graph.nodes} == {"source", "destination", "service"}


@pytest.mark.parametrize(
    "changes",
    [
        {"policy_id": "OTHER"},
        {"policy_direction": "out"},
        {"source_zone": "inside"},
        {"destination_zone": "dmz"},
    ],
)
def test_should_not_share_nodes_across_policy_scopes(changes: dict[str, str]) -> None:
    """Одинаковые значения в разных политиках, направлениях и зонах имеют разные узлы."""
    revision = policy_revision(rule(10), rule(20, **changes))

    graph = build_acl_map(revision, built_at=revision.imported_at)

    first, second = graph.relations
    for dimension in ("source", "destination", "service"):
        assert set(getattr(first, f"{dimension}_node_ids")).isdisjoint(
            getattr(second, f"{dimension}_node_ids")
        )


def test_should_scope_identifiers_by_revision() -> None:
    """Новая ревизия отделяет узлы и связи даже при тех же правилах."""
    revision = policy_revision(rule(10))
    other = DeviceRevision.model_validate(
        {**revision.model_dump(), "revision_id": UUID("10000000-0000-0000-0000-000000000099")}
    )

    first = build_acl_map(revision, built_at=revision.imported_at)
    second = build_acl_map(other, built_at=other.imported_at)

    assert {node.node_id for node in first.nodes}.isdisjoint(node.node_id for node in second.nodes)
    assert first.relations[0].relation_id != second.relations[0].relation_id


@pytest.mark.parametrize("dimension", ["sources", "services"])
def test_should_not_merge_same_named_objects_with_different_values(dimension: str) -> None:
    """Имя и идентификатор объекта не заменяют проверку полного содержимого."""
    original = rule(10)
    first = getattr(original, dimension)[0]
    changes = (
        {"cidrs": ("198.51.100.0/24",)}
        if dimension == "sources"
        else {"port_ranges": (PortRange(start=8443, end=8443),)}
    )
    second = type(first).model_validate({**first.model_dump(), **changes})
    revision = policy_revision(rule(10, **{dimension: (first, second)}))

    graph = build_acl_map(revision, built_at=revision.imported_at)

    field = "source_node_ids" if dimension == "sources" else "service_node_ids"
    identifiers = getattr(graph.relations[0], field)
    assert len(set(identifiers)) == 2
    values = [
        node.endpoint if dimension == "sources" else node.service
        for node in graph.nodes
        if node.node_id in identifiers
    ]
    assert values == [first, second]


def test_should_share_equal_values_only_within_the_same_scope() -> None:
    """Повторные значения одной области используют общие узлы при отдельных связях."""
    revision = policy_revision(rule(10), rule(20))

    graph = build_acl_map(revision, built_at=revision.imported_at)

    assert len(graph.nodes) == 3
    assert len(graph.relations) == 2
    assert graph.relations[0].source_node_ids == graph.relations[1].source_node_ids
    assert graph.relations[0].relation_id != graph.relations[1].relation_id


def test_should_isolate_nodes_when_policy_scope_is_unknown() -> None:
    """Отсутствие policy_id не доказывает общую область разных правил."""
    revision = policy_revision(rule(10, policy_id=None), rule(20, policy_id=None))

    graph = build_acl_map(revision, built_at=revision.imported_at)

    assert len(graph.nodes) == 6
    first, second = graph.relations
    for dimension in ("source", "destination", "service"):
        assert set(getattr(first, f"{dimension}_node_ids")).isdisjoint(
            getattr(second, f"{dimension}_node_ids")
        )


@settings(max_examples=12, deadline=None)
@given(size=st.integers(min_value=2, max_value=25))
def test_should_grow_linearly_without_cartesian_relations(size: int) -> None:
    """Наборы адресов и сервисов не размножают правило декартовым произведением."""
    sources = tuple(endpoint(f"192.0.2.{index}/32") for index in range(size))
    destinations = tuple(endpoint(f"198.51.100.{index}/32") for index in range(size))
    services = tuple(
        Service(
            service_id=f"tcp-{index}",
            name=f"tcp-{index}",
            protocol=Protocol.TCP,
            port_ranges=(PortRange(start=1000 + index, end=1000 + index),),
        )
        for index in range(size)
    )
    graph = make_graph(sources=sources, destinations=destinations, services=services)

    assert len(graph.nodes) == 3 * size
    assert len(graph.relations) == 1
    relation = graph.relations[0]
    assert len(relation.source_node_ids) == size
    assert len(relation.destination_node_ids) == size
    assert len(relation.service_node_ids) == size
    assert export_acl_map_dot(graph).count(" -> ") == 3 * size


def test_should_build_deterministically_from_equal_revisions() -> None:
    """Одинаковые входные данные дают одинаковые идентификаторы и экспорты."""
    revision = policy_revision(rule(20), rule(10))
    copied = DeviceRevision.model_validate_json(revision.model_dump_json())

    first = build_acl_map(revision, built_at=revision.imported_at)
    second = build_acl_map(copied, built_at=copied.imported_at + timedelta(seconds=1))

    assert first.nodes == second.nodes
    assert first.relations == second.relations
    assert [relation.rule.sequence for relation in first.relations] == [20, 10]
    assert export_acl_map_dot(first) == export_acl_map_dot(second)
    assert export_acl_map_json(first) == export_acl_map_json(
        build_acl_map(copied, built_at=copied.imported_at)
    )


def test_should_preserve_revision_provenance_and_diagnostics() -> None:
    """Карта сохраняет ревизию, хеши, координаты и все виды диагностики."""
    original = rule(10)
    revision = policy_revision(
        original,
        warnings=(
            ParseIssue(
                code="SYNTHETIC_WARNING",
                level=ParseIssueLevel.WARNING,
                message="Синтетическое предупреждение",
                source_location=original.source_location,
            ),
        ),
        errors=(
            ParseIssue(
                code="SYNTHETIC_ERROR",
                level=ParseIssueLevel.ERROR,
                message="Синтетическая ошибка",
                source_location=original.source_location,
            ),
        ),
        unsupported_constructs=(
            UnsupportedConstruct(
                construct_type="synthetic",
                message="Неподдержанное условие",
                source_location=original.source_location,
            ),
        ),
        coverage=ParseCoverage(
            discovered_constructs=2, recognized_constructs=1, unsupported_constructs=1
        ),
    )

    graph = build_acl_map(revision, built_at=revision.imported_at)

    assert graph.revision == revision
    assert graph.revision is not revision
    assert graph.relations[0].rule.source_location == original.source_location
    assert graph.revision.parse_result.source_map[original.rule_id] == original.source_location
    assert graph.revision.sources[0].content_sha256 == revision.sources[0].content_sha256
    assert len(graph.limitations) > len(make_graph().limitations)


@pytest.mark.parametrize(
    "target", ["root", "rule", "endpoint", "port", "source_location", "source_map", "device"]
)
@pytest.mark.parametrize("entrypoint", ["build", "python", "json"])
def test_should_reject_mutation_of_every_snapshot_layer(target: str, entrypoint: str) -> None:
    """Неизменяемость распространяется на вложенные модели и source_map."""
    graph = make_graph()
    if entrypoint == "python":
        graph = AclMap.model_validate(graph.model_dump())
    elif entrypoint == "json":
        graph = AclMap.model_validate_json(export_acl_map_json(graph))
    before = export_acl_map_json(graph)
    relation = graph.relations[0]
    updates = {
        "root": (graph, "mode", "reachability"),
        "rule": (relation.rule, "enabled", False),
        "endpoint": (relation.rule.sources[0], "name", "changed"),
        "port": (relation.rule.services[0].port_ranges[0], "start", 80),
        "source_location": (relation.rule.source_location, "line_start", 999),
        "device": (graph.revision.device, "hostname", "changed"),
    }

    with pytest.raises((TypeError, ValidationError)):
        if target == "source_map":
            graph.revision.parse_result.source_map[relation.rule.rule_id] = rule(99).source_location
        else:
            obj, field, value = updates[target]
            setattr(obj, field, value)

    assert export_acl_map_json(graph) == before


def test_should_keep_snapshot_independent_of_input_mutations() -> None:
    """Изменение исходной ревизии после сборки не меняет карту."""
    original = policy_revision(rule(10))
    revision = DeviceRevision.model_construct(
        **{
            **original.__dict__,
            "parse_result": ParseResult.model_validate(original.parse_result.model_dump()),
        }
    )
    graph = build_acl_map(revision, built_at=revision.imported_at)
    before = export_acl_map_json(graph)

    revision.parse_result.rules[0].enabled = False
    revision.parse_result.rules[0].sources[0].name = "changed"
    revision.parse_result.source_map.clear()

    assert export_acl_map_json(graph) == before


def test_should_roundtrip_json_with_versions_and_limitations() -> None:
    """JSON сохраняет версионированный снимок и явные ограничения интерпретации."""
    graph = make_graph(action=RuleAction.UNKNOWN, match_status=DataStatus.UNKNOWN)

    encoded = export_acl_map_json(graph)
    restored = AclMap.model_validate_json(encoded)
    payload = json.loads(encoded)

    assert restored == graph
    assert isinstance(restored.limitations, tuple)
    assert payload["schema_version"] == "1.0.0"
    assert payload["analyzer_version"] == "0.1.0"
    assert payload["mode"] == "declared_rules"
    assert payload["limitations"] == list(graph.limitations)
    assert any("достижим" in limitation.lower() for limitation in graph.limitations)
    assert not {"effective_policy", "reachability", "allowed_paths"}.intersection(payload)


def test_should_reject_json_without_required_limitations() -> None:
    """Ограничения обязательны в JSON и не восстанавливаются неявно при чтении."""
    payload = json.loads(export_acl_map_json(make_graph()))
    del payload["limitations"]

    with pytest.raises(ValidationError, match="limitations"):
        AclMap.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("kind", ["naive", "before_import"])
def test_should_reject_invalid_build_time(kind: str) -> None:
    """Время сборки должно иметь часовой пояс и быть не раньше импорта."""
    revision = policy_revision(rule(10))
    built_at = (
        revision.imported_at.replace(tzinfo=None)
        if kind == "naive"
        else (revision.imported_at - timedelta(microseconds=1))
    )

    with pytest.raises(ValidationError):
        build_acl_map(revision, built_at=built_at)


@pytest.mark.parametrize(
    "exporter", [export_acl_map_json, export_acl_map_dot, select_acl_relations]
)
@pytest.mark.parametrize(
    "tamper", ["nodes", "relations", "rule", "status", "revision", "root", "limitations"]
)
def test_should_reject_stale_or_tampered_projection(exporter: Any, tamper: str) -> None:
    """Экспорт повторно проверяет корень и отказывает при подмене проекции."""
    graph = make_graph()
    updates: dict[str, Any]
    if tamper == "nodes":
        updates = {"nodes": graph.nodes[:-1]}
    elif tamper == "relations":
        updates = {"relations": ()}
    elif tamper == "rule":
        altered = graph.relations[0].rule.model_copy(update={"action": RuleAction.DENY})
        updates = {"relations": (graph.relations[0].model_copy(update={"rule": altered}),)}
    elif tamper == "status":
        updates = {
            "relations": (graph.relations[0].model_copy(update={"condition_status": "unknown"}),)
        }
    elif tamper == "revision":
        updates = {"revision": policy_revision(rule(10, action=RuleAction.DENY))}
    elif tamper == "limitations":
        updates = {"limitations": ()}
    else:
        updates = {"mode": "reachability"}
    tampered = graph.model_copy(update=updates)

    with pytest.raises(ValidationError):
        exporter(tampered)


@pytest.mark.parametrize(
    "filters,expected",
    [
        ({}, ["rule-10", "rule-20", "rule-30"]),
        ({"policy_id": "ACL"}, ["rule-10", "rule-20"]),
        ({"rule_id": "rule-20"}, ["rule-20"]),
        ({"action": RuleAction.DENY}, ["rule-20", "rule-30"]),
        ({"enabled": False}, ["rule-20"]),
        ({"enabled": True}, ["rule-10", "rule-30"]),
        (
            {"policy_id": "ACL", "action": RuleAction.DENY, "enabled": False, "rule_id": "rule-20"},
            ["rule-20"],
        ),
        ({"policy_id": "OTHER", "enabled": False}, []),
        ({"rule_id": "missing"}, []),
    ],
)
def test_should_filter_relations_without_changing_graph(
    filters: dict[str, Any], expected: list[str]
) -> None:
    """Фильтры пересекаются и возвращают tuple без изменения полной карты."""
    revision = policy_revision(
        rule(10),
        rule(20, action=RuleAction.DENY, enabled=False),
        rule(30, action=RuleAction.DENY, policy_id="OTHER"),
    )
    graph = build_acl_map(revision, built_at=revision.imported_at)
    before = export_acl_map_json(graph)

    selected = select_acl_relations(graph, **filters)

    assert isinstance(selected, tuple)
    assert [relation.rule.rule_id for relation in selected] == expected
    assert export_acl_map_json(graph) == before


@pytest.mark.parametrize(
    "label", ['x"]; evil -> target; //', 'x\\y\n"z"\r\tend', '<IMG SRC="file:///secret">']
)
def test_should_escape_untrusted_dot_labels(label: str) -> None:
    """Кавычки, переводы строк и HTML-подобный ввод остаются данными DOT."""
    source = endpoint("192.0.2.0/24").model_copy(update={"name": label})
    service = rule(10).services[0].model_copy(update={"name": label})
    graph = make_graph(rule_id=label, sources=(source,), services=(service,))

    dot = export_acl_map_dot(graph)

    labels = dot_node_labels(dot)
    assert len(labels) == len(graph.nodes) + len(graph.relations)
    relation = graph.relations[0]
    assert labels[relation.source_node_ids[0]].startswith(label + "\n")
    assert labels[relation.service_node_ids[0]].startswith(label + "\n")
    assert labels[relation.relation_id].startswith(label + " | ")
    assert "192.0.2.0/24" in labels[relation.source_node_ids[0]]
    assert "443-443" in labels[relation.service_node_ids[0]]
    assert "policy=ACL" in labels[relation.relation_id]
    assert "direction=in" in labels[relation.relation_id]
    assert "fixture.config" in labels[relation.relation_id]
    escaped = json.dumps(label, ensure_ascii=False)[1:-1]
    assert sum(escaped in line for line in dot.splitlines()) == 3


def test_should_describe_empty_map_without_proving_absence_of_policy() -> None:
    """Отсутствие разобранных правил не является доказательством отсутствия ACL."""
    revision = policy_revision()

    graph = build_acl_map(revision, built_at=revision.imported_at)

    assert graph.nodes == graph.relations == ()
    assert any("Нет разобранных правил" in limitation for limitation in graph.limitations)


@pytest.mark.parametrize("reason", ["warning", "unsupported", "coverage", "empty"])
def test_should_retain_diagnostic_limitations_and_provenance_in_dot(reason: str) -> None:
    """DOT сохраняет ограничения диагностики, неполноты и пустого результата."""
    original = rule(10)
    changes: dict[str, Any] = {}
    if reason == "warning":
        changes["warnings"] = (
            ParseIssue(
                code="SYNTHETIC",
                level=ParseIssueLevel.WARNING,
                message="Синтетическое предупреждение",
                source_location=original.source_location,
            ),
        )
    elif reason == "unsupported":
        changes["unsupported_constructs"] = (
            UnsupportedConstruct(
                construct_type="synthetic",
                message="Неподдержанная конструкция",
                source_location=original.source_location,
            ),
        )
        changes["coverage"] = ParseCoverage(
            discovered_constructs=2,
            recognized_constructs=1,
            unsupported_constructs=1,
        )
    elif reason == "coverage":
        changes["coverage"] = ParseCoverage(
            discovered_constructs=2,
            recognized_constructs=1,
            unsupported_constructs=0,
        )
    revision = policy_revision(*(() if reason == "empty" else (original,)), **changes)
    graph = build_acl_map(revision, built_at=revision.imported_at)

    dot = export_acl_map_dot(graph)
    graph_line = next(line for line in dot.splitlines() if "graph [label=" in line)
    graph_label = json.loads(graph_line.split("label=", 1)[1].removesuffix("];").strip())

    assert len(graph.limitations) > len(make_graph().limitations)
    for limitation in graph.limitations:
        assert limitation in graph_label
    assert str(revision.revision_id) in graph_label
    assert revision.device.device_id in graph_label
    assert revision.parse_result.configuration.source_name in graph_label
    assert revision.sources[0].content_sha256 in graph_label
    if reason == "empty":
        assert dot_node_labels(dot) == {}
        assert " -> " not in dot


def test_should_show_unknown_placeholders_in_dot() -> None:
    """Пустые измерения отображаются неизвестными, без подстановки any."""
    graph = make_graph(
        sources=(),
        destinations=(),
        services=(),
        source_status=DataStatus.UNKNOWN,
        destination_status=DataStatus.UNKNOWN,
        service_status=DataStatus.UNKNOWN,
    )

    labels = dot_node_labels(export_acl_map_dot(graph))

    for dimension in ("source", "destination", "service"):
        node_id = getattr(graph.relations[0], f"{dimension}_node_ids")[0]
        assert labels[node_id] == f"unknown:{dimension}"


@pytest.mark.parametrize("dimension", ["sources", "services"])
def test_should_display_distinct_values_for_identical_object_names_in_dot(dimension: str) -> None:
    """Одинаковые имена в DOT различаются адресными значениями или портами."""
    original = rule(10)
    first = getattr(original, dimension)[0]
    updates = (
        {"cidrs": ("198.51.100.0/24",)}
        if dimension == "sources"
        else {
            "port_ranges": (PortRange(start=8443, end=8443),),
        }
    )
    second = type(first).model_validate({**first.model_dump(), **updates})
    graph = make_graph(**{dimension: (first, second)})

    labels = dot_node_labels(export_acl_map_dot(graph))
    node_ids = getattr(
        graph.relations[0], "source_node_ids" if dimension == "sources" else "service_node_ids"
    )

    values = (
        ("192.0.2.0/24", "198.51.100.0/24")
        if dimension == "sources"
        else (
            "443-443",
            "8443-8443",
        )
    )
    assert len(node_ids) == 2
    for node_id, value in zip(node_ids, values, strict=True):
        assert labels[node_id].startswith(first.name + "\n")
        assert value in labels[node_id]
        assert "known" in labels[node_id]
    assert labels[node_ids[0]] != labels[node_ids[1]]


@pytest.mark.parametrize("kind", ["range", "fqdn"])
def test_should_retain_range_and_fqdn_values_in_dot(kind: str) -> None:
    """Подпись адресного узла сохраняет диапазон либо FQDN и статус разрешения."""
    source = Endpoint(
        endpoint_id="synthetic",
        name="synthetic",
        kind=EndpointKind(kind),
        ip_ranges=(IpRange(start="192.0.2.1", end="192.0.2.10"),) if kind == "range" else (),
        fqdn="synthetic.example.test" if kind == "fqdn" else None,
        resolution_status=DataStatus.UNKNOWN,
    )
    graph = make_graph(sources=(source,))

    labels = dot_node_labels(export_acl_map_dot(graph))
    label = labels[graph.relations[0].source_node_ids[0]]

    assert "unknown" in label
    assert ("192.0.2.1-192.0.2.10" if kind == "range" else "synthetic.example.test") in label
