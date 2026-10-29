"""Bounded comparison of captured declarations, never of effective access."""

import json
from collections import defaultdict, deque
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Literal, TypedDict, cast

from pydantic import BaseModel, JsonValue

from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import DataStatus, EndpointKind, RuleAction
from firewall_compliance.domain.network import Endpoint, Service
from firewall_compliance.domain.policy_matching import (
    resolve_addresses,
    resolve_rule,
    resolve_services,
)
from firewall_compliance.domain.policy_revision_diff import (
    ConfiguredNatRecord,
    PolicyDiffChange,
    PolicyDiffComputation,
    PolicyDiffInput,
    PolicyDiffLimitation,
    PolicyDiffOptions,
    PolicyEntityFamily,
)
from firewall_compliance.domain.source import SourceLocation

type Entity = Rule | Endpoint | Service | ConfiguredNatRecord
type Basis = Literal["explicit_correspondence", "stable_namespace", "equivalent_multiset"]


class _ChangeReferences(TypedDict):
    before_ids: tuple[str, ...]
    after_ids: tuple[str, ...]
    locations: tuple[SourceLocation, ...]


def _value(**values: Any) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], json.loads(json.dumps(values, allow_nan=False)))


def _payload(value: BaseModel) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], value.model_dump(mode="json"))


def _canonical(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


class _Exhausted(Exception):
    pass


@dataclass
class _Budget:
    maximum: int
    used: int = 0

    def spend(self, count: int = 1) -> None:
        if self.used + count > self.maximum:
            raise _Exhausted
        self.used += count


@dataclass(frozen=True)
class _Row:
    key: str
    value: Entity
    match: dict[str, JsonValue] | None
    semantic: dict[str, JsonValue] | None
    representation: dict[str, JsonValue]
    provenance: dict[str, JsonValue]
    knowledge: dict[str, JsonValue]
    locations: tuple[SourceLocation, ...]
    order_scope: str | None = None
    sequence: int | None = None


def _cost(value: Entity) -> int:
    if isinstance(value, Rule):
        endpoints = (*value.sources, *value.destinations)
        services = value.services
    elif isinstance(value, ConfiguredNatRecord):
        endpoints = (
            *value.original_sources,
            *value.original_destinations,
            *value.translated_sources,
            *value.translated_destinations,
        )
        services = (*value.original_services, *value.translated_services)
    elif isinstance(value, Endpoint):
        endpoints, services = (value,), ()
    else:
        endpoints, services = (), (value,)
    return (
        1
        + len(endpoints)
        + len(services)
        + sum(len(item.cidrs) + len(item.ip_ranges) for item in endpoints)
        + sum(len(item.port_ranges) for item in services)
    )


def _rule_values(rule: Rule) -> tuple[dict[str, JsonValue] | None, dict[str, JsonValue]]:
    match = resolve_rule(rule)
    knowledge = _value(
        match_status=rule.match_status,
        source_status=rule.source_status,
        destination_status=rule.destination_status,
        service_status=rule.service_status,
        zone_status=rule.zone_status,
        logging_status=rule.logging_status,
        description_status=rule.description_status,
        owner_known=rule.owner is not None,
    )
    if match is None or rule.action == RuleAction.UNKNOWN:
        return None, knowledge
    values = _value(
        action=rule.action,
        enabled=rule.enabled,
        sources=match.sources,
        destinations=match.destinations,
        services=match.services,
        policy_id=rule.policy_id,
        policy_direction=rule.policy_direction,
        policy_semantics=rule.policy_semantics,
    )
    if rule.zone_status == DataStatus.KNOWN:
        values.update(source_zone=rule.source_zone, destination_zone=rule.destination_zone)
    return values, knowledge


def _nat_values(record: ConfiguredNatRecord) -> dict[str, JsonValue] | None:
    if (
        record.data_status != DataStatus.KNOWN
        or record.kind == "unknown"
        or record.processing_family == "unknown"
        or record.processing_stage is None
        or record.direction == "unknown"
        or record.enabled is None
    ):
        return None
    addresses = (
        resolve_addresses(record.original_sources),
        resolve_addresses(record.original_destinations),
        resolve_addresses(record.translated_sources),
        resolve_addresses(record.translated_destinations),
    )
    services = (
        resolve_services(record.original_services),
        resolve_services(record.translated_services),
    )
    if any(value is None for value in (*addresses, *services)):
        return None
    family_index = 0 if record.processing_family == "ipv4" else 1
    # ANY is restricted by the explicit processing family, never expanded across families.
    if any(value is not None and not value[family_index] for value in addresses):
        return None
    return _value(
        kind=record.kind,
        scope_reference=record.scope_reference,
        processing_family=record.processing_family,
        processing_stage=record.processing_stage,
        direction=record.direction,
        enabled=record.enabled,
        addresses=[value[family_index] for value in addresses if value is not None],
        original_services=services[0],
        translated_services=services[1],
    )


def _rows(source: PolicyDiffInput, family: PolicyEntityFamily, budget: _Budget) -> list[_Row]:
    parsed = source.revision.parse_result
    collections: dict[PolicyEntityFamily, tuple[Entity, ...]] = {
        "rule": parsed.rules,
        "endpoint": parsed.endpoints,
        "service": parsed.services,
        "nat": source.configured_nat or (),
    }
    result = []
    for value in collections[family]:
        budget.spend(_cost(value))
        raw = _payload(value)
        semantic: dict[str, JsonValue] | None
        order_scope = None
        sequence = None
        locations: tuple[SourceLocation, ...]
        if isinstance(value, Rule):
            key = value.rule_id
            match, knowledge = _rule_values(value)
            semantic = dict(match) if match is not None else None
            if semantic is not None:
                if value.logging_status in {DataStatus.KNOWN, DataStatus.ABSENT}:
                    semantic["logging_enabled"] = value.logging_enabled
                if value.description_status in {DataStatus.KNOWN, DataStatus.ABSENT}:
                    semantic["description"] = value.description
                if value.owner is not None:
                    semantic["owner"] = value.owner
            if (
                value.policy_id is not None
                and value.policy_direction is not None
                and value.policy_semantics == "first_match"
                and value.zone_status == DataStatus.KNOWN
            ):
                order_scope = _canonical(
                    [
                        value.policy_id,
                        value.policy_direction,
                        value.source_zone,
                        value.destination_zone,
                    ]
                )
            sequence = value.sequence
            locations = (value.source_location,)
        elif isinstance(value, Endpoint):
            key = value.endpoint_id
            knowledge = _value(resolution_status=value.resolution_status)
            addresses = resolve_addresses((value,))
            semantic = _value(addresses=addresses) if addresses is not None else None
            if value.resolution_status == DataStatus.KNOWN and value.kind == EndpointKind.FQDN:
                semantic = _value(fqdn=value.fqdn.casefold() if value.fqdn else None)
            if value.resolution_status == DataStatus.KNOWN and value.kind == EndpointKind.ZONE:
                semantic = _value(zone=value.zone) if value.zone is not None else None
            match = semantic
            location = parsed.source_map.get(key)
            locations = (location,) if location else ()
        elif isinstance(value, Service):
            key = value.service_id
            knowledge = _value(resolution_status=value.resolution_status)
            services = resolve_services((value,))
            semantic = _value(services=services) if services is not None else None
            match = semantic
            location = parsed.source_map.get(key)
            locations = (location,) if location else ()
        else:
            key = value.nat_id
            semantic = _nat_values(value)
            match = semantic
            knowledge = _value(data_status=value.data_status, resolved=semantic is not None)
            locations = (value.source_location,)
            sequence = value.sequence
            if semantic is not None:
                order_scope = _canonical(
                    [
                        value.scope_reference,
                        value.processing_family,
                        value.processing_stage,
                        value.direction,
                    ]
                )
        representation = {
            name: item
            for name, item in raw.items()
            if name not in {"configuration_id", "source_document_id", "source_location", "sequence"}
        }
        provenance = _value(
            revision_id=str(source.revision.revision_id),
            configuration_id=str(parsed.configuration.configuration_id),
            source_locations=[item.model_dump(mode="json") for item in locations],
            source_document_id=raw.get("source_document_id"),
        )
        result.append(
            _Row(
                key,
                value,
                match,
                semantic,
                representation,
                provenance,
                knowledge,
                locations,
                order_scope,
                sequence,
            )
        )
    return result


def _change(
    before: PolicyDiffInput,
    after: PolicyDiffInput,
    family: Literal["rule", "endpoint", "service", "nat", "configuration"],
    kind: Literal[
        "added",
        "removed",
        "modified",
        "first_observed",
        "not_observed",
        "order_changed",
        "representation_changed",
        "evidence_changed",
        "coverage_changed",
    ],
    basis: Literal[
        "explicit_correspondence",
        "stable_namespace",
        "equivalent_multiset",
        "collection_evidence",
        "source_metadata",
        "order_evidence",
    ],
    *,
    old: dict[str, JsonValue] | None,
    new: dict[str, JsonValue] | None,
    before_ids: tuple[str, ...] = (),
    after_ids: tuple[str, ...] = (),
    fields: tuple[str, ...] = (),
    locations: tuple[SourceLocation, ...] = (),
) -> PolicyDiffChange:
    payload = {
        "family": family,
        "kind": kind,
        "basis": basis,
        "before_value": old,
        "after_value": new,
        "before_ids": before_ids,
        "after_ids": after_ids,
        "changed_fields": fields,
        "source_locations": [location.model_dump(mode="json") for location in locations],
    }
    identifier = sha256(
        _canonical(
            [str(before.revision.revision_id), str(after.revision.revision_id), payload]
        ).encode("utf-8")
    ).hexdigest()
    return PolicyDiffChange.model_validate({"change_id": identifier, **payload})


def _known_complete(source: PolicyDiffInput, family: PolicyEntityFamily, rows: list[_Row]) -> bool:
    evidence = source.collection(family)
    if (
        evidence is None
        or not evidence.enumeration_complete
        or any(row.semantic is None for row in rows)
    ):
        return False
    sources = {
        item.source_document_id: item for item in (*source.revision.sources, *source.nat_sources)
    }
    for key in evidence.source_document_ids:
        observation = sources[key].observation
        if observation is None or observation.observed_at != evidence.observation.observed_at:
            return False
    if family != "nat":
        parsed = source.revision.parse_result
        if (
            parsed.warnings
            or parsed.errors
            or parsed.unsupported_constructs
            or parsed.coverage.discovered_constructs != parsed.coverage.recognized_constructs
        ):
            return False
        config = parsed.configuration
        if not any(
            item.source_document_id in evidence.source_document_ids
            and item.source_name == config.source_name
            and item.content_sha256.lower() == config.content_sha256.lower()
            for item in source.revision.sources
        ):
            return False
    return True


def _matches(
    before: PolicyDiffInput,
    after: PolicyDiffInput,
    family: PolicyEntityFamily,
    old: list[_Row],
    new: list[_Row],
    options: PolicyDiffOptions,
    budget: _Budget,
) -> tuple[list[tuple[_Row, _Row, Basis, bool]], list[_Row], list[_Row]]:
    left, right = {row.key: row for row in old}, {row.key: row for row in new}
    pairs: list[tuple[_Row, _Row, Basis, bool]] = []
    for evidence in options.correspondences:
        if evidence.family != family:
            continue
        budget.spend()
        if evidence.before_id not in left or evidence.after_id not in right:
            raise ValueError("correspondence does not target captured entities")
        names = {
            item.source_name
            for item in (
                *before.revision.sources,
                *before.nat_sources,
                *after.revision.sources,
                *after.nat_sources,
            )
        }
        if any(location.source_name not in names for location in evidence.source_locations):
            raise ValueError("correspondence source must identify a retained source")
        pairs.append(
            (
                left.pop(evidence.before_id),
                right.pop(evidence.after_id),
                "explicit_correspondence",
                False,
            )
        )
    first, second = before.collection(family), after.collection(family)
    if (
        first is not None
        and second is not None
        and first.identity_namespace is not None
        and first.identity_namespace == second.identity_namespace
        and first.scope_reference == second.scope_reference
    ):
        for identifier in sorted(left.keys() & right.keys()):
            budget.spend()
            pairs.append((left.pop(identifier), right.pop(identifier), "stable_namespace", False))
    old_groups: dict[str, deque[_Row]] = defaultdict(deque)
    new_groups: dict[str, deque[_Row]] = defaultdict(deque)
    for rows, groups in ((left.values(), old_groups), (right.values(), new_groups)):
        for row in sorted(rows, key=lambda item: item.key):
            budget.spend()
            if row.match is not None:
                groups[_canonical(row.match)].append(row)
    for fingerprint in sorted(old_groups.keys() & new_groups.keys()):
        a, b = old_groups[fingerprint], new_groups[fingerprint]
        ambiguous = len(a) > 1 or len(b) > 1
        while a and b:
            budget.spend()
            first_row, second_row = a.popleft(), b.popleft()
            left.pop(first_row.key)
            right.pop(second_row.key)
            pairs.append((first_row, second_row, "equivalent_multiset", ambiguous))
    return (
        pairs,
        sorted(left.values(), key=lambda item: item.key),
        sorted(right.values(), key=lambda item: item.key),
    )


def _different(old: dict[str, JsonValue], new: dict[str, JsonValue]) -> tuple[str, ...]:
    return tuple(
        key
        for key in sorted(old.keys() | new.keys())
        if _canonical(old.get(key)) != _canonical(new.get(key))
    )


def compare_policy_declarations(
    before: PolicyDiffInput,
    after: PolicyDiffInput,
    options: PolicyDiffOptions | None = None,
) -> PolicyDiffComputation:
    """Compare exact declarations; four channels retain independent uncertainty."""
    before = PolicyDiffInput.model_validate(before)
    after = PolicyDiffInput.model_validate(after)
    options = PolicyDiffOptions.model_validate(options or PolicyDiffOptions())
    budget = _Budget(options.max_operations)
    channels: list[list[PolicyDiffChange]] = [[], [], [], []]
    semantic, provenance, normalization, completeness = channels
    limitations: list[PolicyDiffLimitation] = []

    def limit(
        code: str, message: str, family: PolicyEntityFamily | None = None, ids: tuple[str, ...] = ()
    ) -> None:
        limitations.append(
            PolicyDiffLimitation(code=code, message=message, family=family, entity_ids=ids)
        )

    device_a, device_b = before.revision.device, after.revision.device
    same_scope = before.scope_reference == after.scope_reference and (
        device_a.device_id,
        device_a.vendor,
        device_a.platform,
        device_a.context,
    ) == (device_b.device_id, device_b.vendor, device_b.platform, device_b.context)
    parser_a = before.revision.parse_result.configuration.parser_version
    parser_b = after.revision.parse_result.configuration.parser_version
    comparable = parser_a == parser_b or options.normalization_comparability_reference is not None
    if parser_a != parser_b:
        normalization.append(
            _change(
                before,
                after,
                "configuration",
                "representation_changed",
                "source_metadata",
                old=_value(parser_version=parser_a),
                new=_value(parser_version=parser_b),
                fields=("parser_version",),
            )
        )
        if not comparable:
            limit(
                "PARSER_COMPARABILITY_UNKNOWN",
                "Изменился парсер; различия не приписываются устройству.",
            )
    old_sources = _value(
        sources=[_payload(item) for item in (*before.revision.sources, *before.nat_sources)],
        nat_inventory_context=before.nat_inventory_context,
    )
    new_sources = _value(
        sources=[_payload(item) for item in (*after.revision.sources, *after.nat_sources)],
        nat_inventory_context=after.nat_inventory_context,
    )
    if _canonical(old_sources) != _canonical(new_sources):
        provenance.append(
            _change(
                before,
                after,
                "configuration",
                "evidence_changed",
                "source_metadata",
                old=old_sources,
                new=new_sources,
                fields=_different(old_sources, new_sources),
            )
        )
    if not same_scope:
        limit(
            "COMPARISON_SCOPE_MISMATCH", "Устройство, контекст или область интеграции не совпадают."
        )
        return PolicyDiffComputation(
            provenance_changes=tuple(provenance),
            normalization_changes=tuple(normalization),
            limitations=tuple(limitations),
            operations_used=0,
        )
    total = sum(
        len(value.revision.parse_result.rules)
        + len(value.revision.parse_result.endpoints)
        + len(value.revision.parse_result.services)
        + len(value.configured_nat or ())
        for value in (before, after)
    )
    if total > options.max_entities:
        limit("ENTITY_BUDGET", "Число входных сущностей превышает бюджет; сравнение не выполнено.")
        return PolicyDiffComputation(
            provenance_changes=tuple(provenance),
            normalization_changes=tuple(normalization),
            limitations=tuple(limitations),
            operations_used=0,
        )
    for family in ("rule", "endpoint", "service", "nat"):
        local: list[list[PolicyDiffChange]] = [[], [], [], []]
        try:
            old, new = _rows(before, family, budget), _rows(after, family, budget)
            first, second = before.collection(family), after.collection(family)
            evidence_a = _payload(first) if first is not None else {}
            evidence_b = _payload(second) if second is not None else {}
            coverage_keys = {
                "scope_reference",
                "enumeration_complete",
                "identity_namespace",
                "order_complete",
                "order_semantics",
            }
            coverage_a = {key: value for key, value in evidence_a.items() if key in coverage_keys}
            coverage_b = {key: value for key, value in evidence_b.items() if key in coverage_keys}
            if _canonical(coverage_a) != _canonical(coverage_b):
                local[3].append(
                    _change(
                        before,
                        after,
                        family,
                        "coverage_changed",
                        "collection_evidence",
                        old=coverage_a,
                        new=coverage_b,
                        fields=_different(coverage_a, coverage_b),
                    )
                )
            if _canonical(evidence_a) != _canonical(evidence_b):
                local[1].append(
                    _change(
                        before,
                        after,
                        family,
                        "evidence_changed",
                        "collection_evidence",
                        old=evidence_a,
                        new=evidence_b,
                        fields=_different(evidence_a, evidence_b),
                    )
                )
            complete = _known_complete(before, family, old) and _known_complete(after, family, new)
            observed_order = (
                first is not None
                and second is not None
                and second.observation.observed_at >= first.observation.observed_at
            )
            collection_scope = (
                first is not None
                and second is not None
                and first.scope_reference == second.scope_reference
            )
            certain_absence = complete and observed_order and collection_scope and comparable
            if not complete or not observed_order or not collection_scope:
                limit(
                    "COLLECTION_COMPARABILITY_UNKNOWN",
                    "Нет полного наблюдаемого сопоставимого инвентаря; "
                    "отсутствие не означает удаление.",
                    family,
                )
            if family == "nat" and (before.configured_nat is None or after.configured_nat is None):
                limit(
                    "NAT_TRANSLATIONS_NOT_OBSERVED",
                    "Счётчики NAT не задают типизированные трансляции.",
                    family,
                )
            unknown = tuple(row.key for row in (*old, *new) if row.semantic is None)
            if unknown:
                limit(
                    "UNKNOWN_VALUES",
                    "Условия части сущностей неизвестны или неподдержаны.",
                    family,
                    unknown,
                )
            if family == "endpoint" and any(
                isinstance(row.value, Endpoint) and row.value.kind == EndpointKind.GROUP
                for row in (*old, *new)
            ):
                limit(
                    "GROUP_MEMBERSHIP_NOT_CAPTURED",
                    "Сравниваются раскрытые значения; "
                    "исходный состав вложенных групп не представлен.",
                    family,
                )
            pairs, disappeared, appeared = _matches(
                before, after, family, old, new, options, budget
            )
            for a, b, basis, ambiguous in pairs:
                budget.spend()
                if ambiguous:
                    limit(
                        "AMBIGUOUS_OCCURRENCE_IDENTITY",
                        "Равные условия сопоставлены только по кратности; "
                        "идентичность и порядок не доказаны.",
                        family,
                        (a.key, b.key),
                    )
                    continue
                locations = (*a.locations, *b.locations)
                keywords: _ChangeReferences = {
                    "before_ids": (a.key,),
                    "after_ids": (b.key,),
                    "locations": locations,
                }
                if a.semantic is not None and b.semantic is not None:
                    fields = tuple(
                        key
                        for key in sorted(a.semantic.keys() & b.semantic.keys())
                        if _canonical(a.semantic[key]) != _canonical(b.semantic[key])
                    )
                    if fields:
                        local[0 if comparable else 2].append(
                            _change(
                                before,
                                after,
                                family,
                                "modified" if comparable else "representation_changed",
                                basis,
                                old=a.semantic,
                                new=b.semantic,
                                fields=fields,
                                **keywords,
                            )
                        )
                if _canonical(a.knowledge) != _canonical(b.knowledge) or (a.semantic is None) != (
                    b.semantic is None
                ):
                    local[3].append(
                        _change(
                            before,
                            after,
                            family,
                            "coverage_changed",
                            basis,
                            old=a.knowledge,
                            new=b.knowledge,
                            fields=_different(a.knowledge, b.knowledge),
                            **keywords,
                        )
                    )
                if _canonical(a.provenance) != _canonical(b.provenance):
                    local[1].append(
                        _change(
                            before,
                            after,
                            family,
                            "evidence_changed",
                            basis,
                            old=a.provenance,
                            new=b.provenance,
                            fields=_different(a.provenance, b.provenance),
                            **keywords,
                        )
                    )
                if (
                    a.semantic is not None
                    and b.semantic is not None
                    and _canonical(a.semantic) == _canonical(b.semantic)
                    and _canonical(a.representation) != _canonical(b.representation)
                ):
                    local[2].append(
                        _change(
                            before,
                            after,
                            family,
                            "representation_changed",
                            basis,
                            old=a.representation,
                            new=b.representation,
                            fields=_different(a.representation, b.representation),
                            **keywords,
                        )
                    )
            for row, added in [(row, False) for row in disappeared] + [
                (row, True) for row in appeared
            ]:
                budget.spend()
                proven = certain_absence and row.semantic is not None
                kind: Literal["added", "removed", "first_observed", "not_observed"] = (
                    ("added" if added else "removed")
                    if proven
                    else ("first_observed" if added else "not_observed")
                )
                local[0].append(
                    _change(
                        before,
                        after,
                        family,
                        kind,
                        "collection_evidence",
                        old=None if added else row.semantic or row.representation,
                        new=(row.semantic or row.representation) if added else None,
                        before_ids=() if added else (row.key,),
                        after_ids=(row.key,) if added else (),
                        locations=row.locations,
                    )
                )
            if family in {"rule", "nat"} and pairs:
                order_proven = (
                    complete
                    and collection_scope
                    and observed_order
                    and first is not None
                    and second is not None
                    and first.order_complete
                    and second.order_complete
                    and first.order_semantics == second.order_semantics == "first_match"
                    and all(
                        not ambiguous
                        and a.order_scope is not None
                        and a.order_scope == b.order_scope
                        for a, b, _, ambiguous in pairs
                    )
                )
                scopes = {a.order_scope for a, _, _, _ in pairs}
                for scope in sorted(value for value in scopes if value is not None):
                    budget.spend()
                    selected = [(a, b) for a, b, _, _ in pairs if a.order_scope == scope]
                    all_old = [row for row in old if row.order_scope == scope]
                    all_new = [row for row in new if row.order_scope == scope]
                    if len({row.sequence for row in all_old}) != len(all_old) or len(
                        {row.sequence for row in all_new}
                    ) != len(all_new):
                        order_proven = False
                    if not order_proven:
                        continue
                    before_order = [
                        a.key
                        for a, _ in sorted(selected, key=lambda pair: cast(int, pair[0].sequence))
                    ]
                    after_order = [
                        a.key
                        for a, _ in sorted(selected, key=lambda pair: cast(int, pair[1].sequence))
                    ]
                    if before_order != after_order:
                        local[0 if comparable else 2].append(
                            _change(
                                before,
                                after,
                                family,
                                "order_changed",
                                "order_evidence",
                                old=_value(scope=scope, order=before_order),
                                new=_value(scope=scope, order=after_order),
                                before_ids=tuple(before_order),
                                after_ids=tuple(
                                    b.key
                                    for _, b in sorted(
                                        selected, key=lambda pair: cast(int, pair[1].sequence)
                                    )
                                ),
                                fields=("relative_order",),
                                locations=tuple(
                                    location
                                    for a, b in selected
                                    for location in (*a.locations, *b.locations)
                                ),
                            )
                        )
                    elif any(a.sequence != b.sequence for a, b in selected):
                        local[2].append(
                            _change(
                                before,
                                after,
                                family,
                                "representation_changed",
                                "order_evidence",
                                old=_value(sequences={a.key: a.sequence for a, _ in selected}),
                                new=_value(sequences={a.key: b.sequence for a, b in selected}),
                                before_ids=tuple(a.key for a, _ in selected),
                                after_ids=tuple(b.key for _, b in selected),
                                fields=("sequence",),
                            )
                        )
                if not order_proven:
                    limit(
                        "ORDER_NOT_PROVEN",
                        "Общий порядок, семантика first-match "
                        "или идентичность вхождений не подтверждены.",
                        family,
                    )
            for target, values in zip(channels, local, strict=True):
                target.extend(values)
        except _Exhausted:
            limit(
                "OPERATION_BUDGET",
                "Бюджет исчерпан; незавершённая область не выдана как завершённое сравнение.",
                family,
            )
            break
    return PolicyDiffComputation(
        semantic_changes=tuple(semantic),
        provenance_changes=tuple(provenance),
        normalization_changes=tuple(normalization),
        completeness_changes=tuple(completeness),
        limitations=tuple(limitations),
        operations_used=budget.used,
    )
