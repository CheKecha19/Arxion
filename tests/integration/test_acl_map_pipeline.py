"""Синтетические HP/Aruba и Comware проходят путь парсер — карта — экспорт."""

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from uuid import UUID

import pytest

from firewall_compliance import __version__
from firewall_compliance.analysis.acl_map import build_acl_map, select_acl_relations
from firewall_compliance.application.acl_map import export_acl_map_dot, export_acl_map_json
from firewall_compliance.domain import (
    DataStatus,
    Device,
    DeviceRevision,
    ParseResult,
    RevisionSource,
    RuleAction,
    SourceDocumentKind,
)
from firewall_compliance.domain.acl_map import AclMap
from firewall_compliance.parsers.catalog import create_default_registry
from firewall_compliance.parsers.contracts import ParseRequest, SourceDocument

FIXTURES = Path(__file__).parents[1] / "fixtures" / "hp_aruba"
IMPORTED_AT = datetime(2026, 10, 11, 10, 0, tzinfo=UTC)
COMWARE = b"""version 7.1.045
sysname SYNTHETIC-ACL-MAP
acl number 3000
 rule 0 deny tcp source any destination any source-port eq 22
 rule 10 permit tcp source any destination 198.51.100.10 0 destination-port eq 443 logging
 rule 20 deny ip source any destination any
#
"""


def parse_revision(name: str, content: bytes) -> DeviceRevision:
    """Разобрать только явно переданный синтетический документ через реестр."""
    source = SourceDocument(source_name=name, content=content, captured_at=IMPORTED_AT)
    parsed = create_default_registry().parse(ParseRequest(source=source, imported_at=IMPORTED_AT))
    assert isinstance(parsed, ParseResult)
    config = parsed.configuration
    return DeviceRevision(
        revision_id=UUID("10000000-0000-0000-0000-000000000088"),
        device=Device(device_id=config.device_id, vendor=config.vendor, platform=config.platform),
        parse_result=parsed,
        sources=(
            RevisionSource(
                source_name=name,
                content_sha256=source.content_sha256,
                kind=SourceDocumentKind.CONFIGURATION,
                captured_at=IMPORTED_AT,
            ),
        ),
        imported_at=IMPORTED_AT,
        application_version=__version__,
    )


@pytest.fixture(params=["aos_cx.cfg", "aos_switch.cfg", "synthetic-comware.cfg"])
def synthetic_revision(request: pytest.FixtureRequest) -> tuple[DeviceRevision, bytes]:
    """Использовать только синтетические Aruba-файлы и встроенный Comware-текст."""
    name = str(request.param)
    content = COMWARE if name == "synthetic-comware.cfg" else (FIXTURES / name).read_bytes()
    return parse_revision(name, content), content


def test_should_preserve_parsed_rules_and_provenance_through_json(
    synthetic_revision: tuple[DeviceRevision, bytes],
) -> None:
    """Каждое правило, координаты, диагностика и хеш сохраняются после экспорта."""
    revision, content = synthetic_revision
    graph = build_acl_map(revision, built_at=IMPORTED_AT)

    restored = AclMap.model_validate_json(export_acl_map_json(graph))

    assert revision.parse_result.rules
    assert len(graph.relations) == len(revision.parse_result.rules)
    assert tuple(relation.rule for relation in restored.relations) == revision.parse_result.rules
    assert restored.revision == revision
    assert restored.revision.sources[0].content_sha256 == sha256(content).hexdigest()
    assert (
        restored.revision.parse_result.configuration.content_sha256 == sha256(content).hexdigest()
    )
    for relation in restored.relations:
        assert relation.rule.source_location.line_start is not None
        assert relation.rule.source_location.source_name == revision.sources[0].source_name
        assert (
            revision.parse_result.source_map[relation.rule.rule_id] == relation.rule.source_location
        )


def test_should_keep_partial_conditions_and_deny_rules_in_pipeline(
    synthetic_revision: tuple[DeviceRevision, bytes],
) -> None:
    """Неполные условия и запреты остаются видимыми в карте объявленных правил."""
    revision, _ = synthetic_revision
    graph = build_acl_map(revision, built_at=IMPORTED_AT)

    deny = select_acl_relations(graph, action=RuleAction.DENY)

    assert deny
    assert len(deny) == sum(rule.action == RuleAction.DENY for rule in revision.parse_result.rules)
    assert any(relation.condition_status != "known" for relation in graph.relations)
    if revision.sources[0].source_name == "synthetic-comware.cfg":
        assert any(relation.condition_status == "unsupported" for relation in graph.relations)
    else:
        assert any(relation.condition_status == "unknown" for relation in graph.relations)
    for relation in graph.relations:
        if relation.rule.match_status == DataStatus.UNSUPPORTED:
            assert relation.condition_status == "unsupported"
    assert len(graph.limitations) > 2
    payload = json.loads(export_acl_map_json(graph))
    assert payload["mode"] == "declared_rules"
    assert payload["limitations"] == list(graph.limitations)


def test_should_emit_linear_dot_with_all_declared_rules(
    synthetic_revision: tuple[DeviceRevision, bytes],
) -> None:
    """DOT содержит один узел на правило и отдельные ссылки наборов условий."""
    revision, _ = synthetic_revision
    graph = build_acl_map(revision, built_at=IMPORTED_AT)

    dot = export_acl_map_dot(graph)

    assert dot.startswith("digraph acl_map {\n")
    assert dot.endswith("}\n")
    assert "declared_rules; not reachability" in dot
    assert dot.count("shape=diamond") == len(revision.parse_result.rules)
    assert dot.count(" -> ") == sum(
        len(relation.source_node_ids)
        + len(relation.destination_node_ids)
        + len(relation.service_node_ids)
        for relation in graph.relations
    )
    assert export_acl_map_dot(build_acl_map(revision, built_at=IMPORTED_AT)) == dot


@pytest.mark.parametrize("filename", ["aos_cx.cfg", "aos_switch.cfg"])
def test_should_separate_repeated_aruba_bindings(filename: str) -> None:
    """Одна ACL на нескольких привязках сохраняет отдельные области узлов."""
    revision = parse_revision(filename, (FIXTURES / filename).read_bytes())
    graph = build_acl_map(revision, built_at=IMPORTED_AT)
    candidates = [relation for relation in graph.relations if relation.rule.sequence == 10]
    pairs = [
        (left, right)
        for index, left in enumerate(candidates)
        for right in candidates[index + 1 :]
        if left.rule.sources == right.rule.sources
        and left.rule.services == right.rule.services
        and (
            left.rule.policy_id,
            left.rule.policy_direction,
            left.rule.source_zone,
            left.rule.destination_zone,
        )
        != (
            right.rule.policy_id,
            right.rule.policy_direction,
            right.rule.source_zone,
            right.rule.destination_zone,
        )
    ]

    assert pairs, "Синтетическая фикстура должна содержать несколько привязок одной ACL"
    for left, right in pairs:
        assert set(left.source_node_ids).isdisjoint(right.source_node_ids)
        assert set(left.service_node_ids).isdisjoint(right.service_node_ids)
