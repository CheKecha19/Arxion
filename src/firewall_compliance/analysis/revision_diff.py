"""Separate network values from provenance, normalization and evidence availability."""

import json
from ipaddress import ip_network
from typing import Any, Literal

from firewall_compliance.domain import (
    DataStatus,
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
from firewall_compliance.domain.revision import RevisionComparisonDetail

type Fact = Interface | Route | NetworkSegment | TopologyLink
type DetailCode = Literal[
    "provenance_changed",
    "normalization_changed",
    "normalization_dependent",
    "availability_changed",
    "not_observed",
    "first_observed",
    "scope_incomparable",
]

_FIELDS = {
    RevisionEntityKind.INTERFACE: ("name", "addresses", "zone", "enabled"),
    RevisionEntityKind.ROUTE: (
        "destination",
        "next_hop",
        "outgoing_interface_id",
        "metric",
        "administrative_distance",
        "route_kind",
        "table_id",
        "is_blackhole",
    ),
    RevisionEntityKind.NETWORK_SEGMENT: ("name", "cidrs", "zone"),
    RevisionEntityKind.TOPOLOGY_LINK: ("left_endpoint_id", "right_endpoint_id"),
}


def _identifier(fact: Fact) -> str:
    if isinstance(fact, Interface):
        return fact.interface_id
    if isinstance(fact, Route):
        return fact.route_id
    if isinstance(fact, NetworkSegment):
        return fact.segment_id
    return fact.link_id


def _values(fact: Fact, kind: RevisionEntityKind) -> dict[str, Any]:
    values = fact.model_dump(mode="json", include=set(_FIELDS[kind]))
    for field in ("addresses", "cidrs"):
        if field in values:
            values[field] = sorted(values[field])
    return values


def _known(fact: Fact, field: str) -> bool:
    if fact.data_status != DataStatus.KNOWN:
        return False
    value = getattr(fact, field)
    if isinstance(fact, Interface):
        if field == "addresses":
            return fact.addresses_status in {DataStatus.KNOWN, DataStatus.ABSENT}
        if field in {"enabled", "zone"}:
            return value is not None
    if isinstance(fact, Route):
        if field in {"metric", "administrative_distance"}:
            return value is not None
        if field == "route_kind":
            return fact.route_kind != "unknown"
    if isinstance(fact, NetworkSegment):
        if field == "zone":
            return value is not None
        if field == "cidrs":
            return bool(value)
    return True


def _provenance(fact: Fact, kind: RevisionEntityKind) -> dict[str, Any]:
    return fact.model_dump(mode="json", exclude={*_FIELDS[kind], "data_status", "addresses_status"})


def _changed(before: dict[str, Any], after: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        key for key in sorted(before.keys() | after.keys()) if before.get(key) != after.get(key)
    )


def _evidence(summary: str, before: Fact | None, after: Fact | None, **extra: Any) -> Evidence:
    facts: dict[str, Any] = dict(extra)
    locations = []
    for label, fact in (("before", before), ("after", after)):
        if fact is not None:
            facts[label] = fact.model_dump(mode="json")
            if fact.source_location is not None:
                locations.append(fact.source_location)
    return Evidence(summary=summary, source_locations=tuple(locations), facts=facts)


def _detail(
    kind: RevisionEntityKind,
    entity_id: str,
    code: DetailCode,
    fields: tuple[str, ...],
    evidence: Evidence,
) -> RevisionComparisonDetail:
    return RevisionComparisonDetail(
        entity_kind=kind,
        entity_id=entity_id,
        code=code,
        changed_fields=fields,
        evidence=evidence,
    )


def _inventory(revision: DeviceRevision, collection: str) -> dict[str, Any]:
    evidence = getattr(revision, collection + "_evidence")
    return {
        "status": str(getattr(revision, collection + "_status")),
        "scope": evidence.scope if evidence is not None else None,
        "complete": evidence.complete if evidence is not None else False,
        "observation_available": revision.observed_at is not None,
    }


def _complete(revision: DeviceRevision, collection: str) -> bool:
    inventory = _inventory(revision, collection)
    return (
        inventory["status"] in {DataStatus.KNOWN, DataStatus.ABSENT}
        and inventory["complete"] is True
        and inventory["observation_available"] is True
    )


def _observed_fact(revision: DeviceRevision, fact: Fact) -> bool:
    if revision.observed_at is None:
        return False
    observation = fact.observation
    if fact.source_document_id is not None:
        source = next(
            (
                source
                for source in revision.sources
                if source.source_document_id == fact.source_document_id
            ),
            None,
        )
        observation = source.observation if source is not None else None
    if observation is None:
        return False
    window = revision.observation_window
    return (
        window.start <= observation.observed_at <= window.end
        if window is not None
        else observation.observed_at == revision.observed_at
    )


def _same_scope(
    before: DeviceRevision, after: DeviceRevision, collection: str, facts: tuple[Fact, ...]
) -> bool:
    left, right = _inventory(before, collection), _inventory(after, collection)
    if left["scope"] is None or left["scope"] != right["scope"]:
        return False
    # CollectionEvidence lacks family/table dimensions. Do not extend its
    # supported IPv4/default routing scope to IPv6 or other routing tables.
    return collection != "routes" or all(
        isinstance(fact, Route)
        and fact.table_id == "default"
        and ip_network(fact.destination).version == 4
        for fact in facts
    )


def _pair_facts(
    before: tuple[Fact, ...],
    after: tuple[Fact, ...],
    kind: RevisionEntityKind,
    *,
    comparable: bool,
) -> tuple[list[tuple[Fact, Fact]], list[Fact], list[Fact]]:
    left, right = ({_identifier(fact): fact for fact in facts} for facts in (before, after))
    pairs = [(left.pop(key), right.pop(key)) for key in sorted(left.keys() & right.keys())]
    if kind == RevisionEntityKind.ROUTE and comparable:
        # ASA IDs include source UUID/line. Equal values can be reconciled as a
        # multiset; this never identifies changed routes or invents identity.
        buckets: dict[str, list[str]] = {}
        for key, fact in sorted(right.items()):
            buckets.setdefault(json.dumps(_values(fact, kind), sort_keys=True), []).append(key)
        for key, fact in sorted(tuple(left.items())):
            matches = buckets.get(json.dumps(_values(fact, kind), sort_keys=True), [])
            if matches:
                pairs.append((left.pop(key), right.pop(matches.pop(0))))
    return pairs, list(left.values()), list(right.values())


def _revision_metadata(revision: DeviceRevision) -> dict[str, Any]:
    return {
        "configuration": revision.parse_result.configuration.model_dump(
            mode="json", exclude={"parser_version"}
        ),
        "sources": [source.model_dump(mode="json") for source in revision.sources],
        "imported_at": revision.imported_at.isoformat(),
        "application_version": revision.application_version,
        "legacy_observed_at": (
            revision.legacy_observed_at.isoformat() if revision.legacy_observed_at else None
        ),
        "migration_limitations": list(revision.migration_limitations),
        "observed_at": revision.observed_at.isoformat() if revision.observed_at else None,
        "observation_window": revision.observation_window.model_dump(mode="json")
        if revision.observation_window
        else None,
        "collection_evidence": {
            collection: evidence.model_dump(mode="json") if evidence is not None else None
            for collection in ("interfaces", "routes", "network_segments", "topology")
            for evidence in [getattr(revision, collection + "_evidence")]
        },
    }


def compare_device_revisions(before: DeviceRevision, after: DeviceRevision) -> DeviceRevisionDiff:
    """Compare recorded values; absence requires complete comparable observation.

    Unknown fields, incomplete enumeration and parser changes retain evidence
    separately. This result makes no claim about effective access or causality.
    """
    if before.device.device_id != after.device.device_id:
        raise ValueError("сравнивать можно только ревизии одного устройства")
    if (before.device.vendor, before.device.platform, before.device.context) != (
        after.device.vendor,
        after.device.platform,
        after.device.context,
    ):
        raise ValueError("ревизии должны иметь одну платформу и контекст устройства")
    changes: list[RevisionChange] = []
    provenance: list[RevisionComparisonDetail] = []
    normalization: list[RevisionComparisonDetail] = []
    completeness: list[RevisionComparisonDetail] = []
    config_before, config_after = (
        before.parse_result.configuration,
        after.parse_result.configuration,
    )
    parser_changed = config_before.parser_version != config_after.parser_version
    if parser_changed:
        normalization.append(
            _detail(
                RevisionEntityKind.CONFIGURATION,
                before.device.device_id,
                "normalization_changed",
                ("parser_version",),
                Evidence(
                    summary="Версия парсера изменилась; причинность различий не установлена.",
                    facts={
                        "before_parser_version": config_before.parser_version,
                        "after_parser_version": config_after.parser_version,
                    },
                ),
            )
        )
    metadata = _revision_metadata(before), _revision_metadata(after)
    fields = _changed(*metadata)
    if fields:
        provenance.append(
            _detail(
                RevisionEntityKind.CONFIGURATION,
                before.device.device_id,
                "provenance_changed",
                fields,
                Evidence(
                    summary="Изменилось происхождение или представление источников.",
                    facts={"before": metadata[0], "after": metadata[1]},
                ),
            )
        )
    collections: tuple[tuple[RevisionEntityKind, str, tuple[Fact, ...], tuple[Fact, ...]], ...] = (
        (RevisionEntityKind.INTERFACE, "interfaces", before.interfaces, after.interfaces),
        (RevisionEntityKind.ROUTE, "routes", before.routes, after.routes),
        (
            RevisionEntityKind.NETWORK_SEGMENT,
            "network_segments",
            before.network_segments,
            after.network_segments,
        ),
        (RevisionEntityKind.TOPOLOGY_LINK, "topology", before.topology_links, after.topology_links),
    )
    for kind, collection, left, right in collections:
        inventories = _inventory(before, collection), _inventory(after, collection)
        fields = _changed(*inventories)
        comparable = _same_scope(before, after, collection, (*left, *right))
        if fields:
            completeness.append(
                _detail(
                    kind,
                    collection,
                    "availability_changed",
                    fields,
                    Evidence(
                        summary="Изменились доступность, область или полнота набора.",
                        facts={"before": inventories[0], "after": inventories[1]},
                    ),
                )
            )
        pairs, missing, added = _pair_facts(left, right, kind, comparable=comparable)
        for old, new in pairs:
            entity_id = _identifier(new)
            fields = _changed(_provenance(old, kind), _provenance(new, kind))
            if fields:
                provenance.append(
                    _detail(
                        kind,
                        entity_id,
                        "provenance_changed",
                        fields,
                        _evidence(
                            "Изменилось происхождение факта; это не изменение сетевых значений.",
                            old,
                            new,
                        ),
                    )
                )
            value_fields = _changed(_values(old, kind), _values(new, kind))
            known = tuple(
                field for field in value_fields if _known(old, field) and _known(new, field)
            )
            unknown = tuple(field for field in value_fields if field not in known)
            statuses = {"data_status": str(old.data_status)}, {"data_status": str(new.data_status)}
            if isinstance(old, Interface) and isinstance(new, Interface):
                statuses[0]["addresses_status"] = str(old.addresses_status)
                statuses[1]["addresses_status"] = str(new.addresses_status)
            availability = tuple(sorted({*_changed(*statuses), *unknown}))
            if availability:
                completeness.append(
                    _detail(
                        kind,
                        entity_id,
                        "availability_changed",
                        availability,
                        _evidence(
                            "Изменились неизвестные значения или достоверность факта.", old, new
                        ),
                    )
                )
            if known:
                evidence = _evidence(
                    "Различаются известные сетевые значения снимков.",
                    old,
                    new,
                    changed_fields=known,
                )
                if kind == RevisionEntityKind.ROUTE and not comparable:
                    completeness.append(
                        _detail(kind, entity_id, "scope_incomparable", known, evidence)
                    )
                elif parser_changed:
                    normalization.append(
                        _detail(
                            kind,
                            entity_id,
                            "normalization_dependent",
                            known,
                            evidence,
                        )
                    )
                else:
                    changes.append(
                        RevisionChange(
                            entity_kind=kind,
                            change_kind=RevisionChangeKind.MODIFIED,
                            entity_id=entity_id,
                            evidence=evidence,
                        )
                    )
        cases: tuple[
            tuple[list[Fact], DeviceRevision, DeviceRevision, RevisionChangeKind, DetailCode], ...
        ] = (
            (missing, after, before, RevisionChangeKind.REMOVED, "not_observed"),
            (added, before, after, RevisionChangeKind.ADDED, "first_observed"),
        )
        for candidates, absent, present, change_kind, code in cases:
            for fact in sorted(candidates, key=_identifier):
                old_fact, new_fact = (
                    (fact, None) if change_kind == RevisionChangeKind.REMOVED else (None, fact)
                )
                proven = (
                    comparable
                    and _complete(absent, collection)
                    and _observed_fact(present, fact)
                    and fact.data_status == DataStatus.KNOWN
                )
                summary = (
                    "Наличие отличается; отсутствие подтверждено в полной сравнимой области."
                    if proven
                    else "Факт наблюдается только в одном снимке; изменение не доказано."
                )
                evidence = _evidence(
                    summary,
                    old_fact,
                    new_fact,
                    before_inventory=inventories[0],
                    after_inventory=inventories[1],
                )
                if proven and not parser_changed:
                    changes.append(
                        RevisionChange(
                            entity_kind=kind,
                            entity_id=_identifier(fact),
                            change_kind=change_kind,
                            evidence=evidence,
                        )
                    )
                elif proven:
                    normalization.append(
                        _detail(
                            kind,
                            _identifier(fact),
                            "normalization_dependent",
                            (),
                            evidence,
                        )
                    )
                else:
                    completeness.append(_detail(kind, _identifier(fact), code, (), evidence))
        if not comparable and (missing or added):
            completeness.append(
                _detail(
                    kind,
                    collection,
                    "scope_incomparable",
                    ("scope",),
                    Evidence(
                        summary="Полнота отсутствия не сопоставима в заданных областях.",
                        facts={"before": inventories[0], "after": inventories[1]},
                    ),
                )
            )
    return DeviceRevisionDiff(
        schema_version="2.0.0",
        before_revision_id=before.revision_id,
        after_revision_id=after.revision_id,
        device_id=before.device.device_id,
        changes=tuple(changes),
        normalization_changed=parser_changed,
        provenance_changes=tuple(provenance),
        normalization_changes=tuple(normalization),
        completeness_changes=tuple(completeness),
        limitations=(
            "Сравниваются записанные значения; доступ и изменения на устройстве не доказываются.",
            "Неполное перечисление и неизвестные значения не доказывают добавление или удаление.",
            "Различия при смене парсера выделены как зависимые от нормализации.",
            "Маршруты с разными ID сопоставляются по равным значениям с сохранением кратности.",
        ),
    )
