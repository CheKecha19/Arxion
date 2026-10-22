"""Сравнение ревизий устройства без вывода о достижимости или NAT."""

from collections.abc import Callable
from typing import Any

from firewall_compliance.domain import (
    DeviceRevision,
    DeviceRevisionDiff,
    Evidence,
    Interface,
    NetworkSegment,
    RevisionChange,
    RevisionChangeKind,
    RevisionEntityKind,
    Route,
    TopologyLink,
)


def compare_device_revisions(before: DeviceRevision, after: DeviceRevision) -> DeviceRevisionDiff:
    """Сравнить два согласованных снимка одного устройства."""
    if before.device.device_id != after.device.device_id:
        raise ValueError("сравнивать можно только ревизии одного устройства")

    changes: list[RevisionChange] = []
    if (
        before.parse_result.configuration.content_sha256
        != after.parse_result.configuration.content_sha256
    ):
        changes.append(
            RevisionChange(
                entity_kind=RevisionEntityKind.CONFIGURATION,
                change_kind=RevisionChangeKind.MODIFIED,
                entity_id=before.device.device_id,
                evidence=Evidence(
                    summary="Изменилось содержимое импортированной конфигурации.",
                    facts={
                        "before_content_sha256": before.parse_result.configuration.content_sha256,
                        "after_content_sha256": after.parse_result.configuration.content_sha256,
                    },
                ),
            )
        )

    changes.extend(
        _compare_facts(
            before.interfaces,
            after.interfaces,
            lambda fact: fact.interface_id,
            RevisionEntityKind.INTERFACE,
        )
    )
    changes.extend(
        _compare_facts(
            before.routes,
            after.routes,
            lambda fact: fact.route_id,
            RevisionEntityKind.ROUTE,
        )
    )
    changes.extend(
        _compare_facts(
            before.network_segments,
            after.network_segments,
            lambda fact: fact.segment_id,
            RevisionEntityKind.NETWORK_SEGMENT,
        )
    )
    changes.extend(
        _compare_facts(
            before.topology_links,
            after.topology_links,
            lambda fact: fact.link_id,
            RevisionEntityKind.TOPOLOGY_LINK,
        )
    )

    normalization_changed = (
        before.parse_result.configuration.parser_version
        != after.parse_result.configuration.parser_version
    )
    limitations = (
        ("Смена версии парсера отмечена отдельно и не доказывает изменение устройства.",)
        if normalization_changed
        else ()
    )
    return DeviceRevisionDiff(
        before_revision_id=before.revision_id,
        after_revision_id=after.revision_id,
        device_id=before.device.device_id,
        changes=tuple(changes),
        normalization_changed=normalization_changed,
        limitations=limitations,
    )


def _compare_facts[Fact: (Interface, Route, NetworkSegment, TopologyLink)](
    before: tuple[Fact, ...],
    after: tuple[Fact, ...],
    identifier: Callable[[Fact], str],
    entity_kind: RevisionEntityKind,
) -> list[RevisionChange]:
    """Вернуть добавленные, удалённые и изменённые факты одного типа."""
    before_by_id = {identifier(fact): fact for fact in before}
    after_by_id = {identifier(fact): fact for fact in after}
    changes: list[RevisionChange] = []
    for entity_id in sorted(before_by_id.keys() - after_by_id.keys()):
        changes.append(
            _fact_change(
                entity_kind, RevisionChangeKind.REMOVED, entity_id, before_by_id[entity_id], None
            )
        )
    for entity_id in sorted(after_by_id.keys() - before_by_id.keys()):
        changes.append(
            _fact_change(
                entity_kind, RevisionChangeKind.ADDED, entity_id, None, after_by_id[entity_id]
            )
        )
    for entity_id in sorted(before_by_id.keys() & after_by_id.keys()):
        if before_by_id[entity_id] != after_by_id[entity_id]:
            changes.append(
                _fact_change(
                    entity_kind,
                    RevisionChangeKind.MODIFIED,
                    entity_id,
                    before_by_id[entity_id],
                    after_by_id[entity_id],
                )
            )
    return changes


def _fact_change[Fact: (Interface, Route, NetworkSegment, TopologyLink)](
    entity_kind: RevisionEntityKind,
    change_kind: RevisionChangeKind,
    entity_id: str,
    before: Fact | None,
    after: Fact | None,
) -> RevisionChange:
    """Собрать одно изменение с минимально достаточным Evidence."""
    facts: dict[str, Any] = {}
    locations = []
    for label, fact in (("before", before), ("after", after)):
        if fact is not None:
            facts[label] = fact.model_dump(mode="json")
            if fact.source_location is not None:
                locations.append(fact.source_location)
    return RevisionChange(
        entity_kind=entity_kind,
        change_kind=change_kind,
        entity_id=entity_id,
        evidence=Evidence(
            summary=f"{entity_kind.value}: {change_kind.value} ({entity_id}).",
            source_locations=tuple(locations),
            facts=facts,
        ),
    )
