"""Расчёт покрытия области объявленными условиями или локальным ACL."""

from __future__ import annotations

from collections import Counter, OrderedDict, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal

from firewall_compliance.analysis.policy_coverage import (
    CoverageBudget, CoverageLimitError, PacketBox, UnsupportedCoverageError,
    packet_boxes, subtract_boxes,
)
from firewall_compliance.application.cloud_sg_policy import advanced_sg_policy
from firewall_compliance.application.matrix_attachment_scope import AttachmentScopeAssessment, matrix_attachment_interface_key
from firewall_compliance.application.matrix_packet_index import PacketCandidateIndex
from firewall_compliance.domain.access_matrix import MatrixZonePair
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import DataStatus, RuleAction
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.policy_matching import AddressSet, RuleMatch, resolve_addresses, resolve_rule, resolve_services
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.domain.switch_facts import SwitchInterface
from firewall_compliance.domain.switch_policy import AclBinding

type PolicyMode = Literal["declared_rules", "local_policy"]
type Boxes = tuple[PacketBox, ...]
type ZoneBucket = tuple[str | None, str | None]
type GroupAddressKey = tuple[tuple[str, str, AddressSet | tuple[str, ...] | None], ...]
_DENIALS = {RuleAction.DENY, RuleAction.DROP, RuleAction.REJECT}
_OUTSIDE_ZONE_DECLARATIONS = {"usergate-nat", "ideco-nat", "ideco-policy-scope"}


class MatrixCancelled(Exception):
    """Отмена между шагами расчёта."""


class MatrixBudget(CoverageBudget):
    def __init__(self, guard: Callable[[], None]) -> None:
        super().__init__()
        self._guard = guard

    def charge(self, fragments: int = 0) -> None:
        if self.operations % 128 == 0:
            self._guard()
        super().charge(fragments)

    def charge_cached(self, operations: int) -> None:
        self._guard()
        self.operations += operations
        if self.operations > self.max_operations:
            raise CoverageLimitError("Packet-set complexity limit exceeded.")


def matrix_binding_policy_id(binding: AclBinding) -> str:
    return (
        f"acl:{binding.acl_id.removeprefix('ipv4:')}@"
        f"{binding.subject}:{binding.direction}"
    )


def matrix_transit_binding(revision: DeviceRevision, policy_id: str) -> AclBinding | None:
    policies = revision.parse_result.switch_policies
    if policies is None:
        return None
    bindings = [
        item for item in policies.bindings
        if item.purpose == "transit" and matrix_binding_policy_id(item) == policy_id
        and item.direction in {"in", "out", "routed-in", "routed-out"}
    ]
    return bindings[0] if len(bindings) == 1 else None


def matrix_policy_contexts(revision: DeviceRevision) -> dict[str, str | None]:
    parsed = revision.parse_result
    if parsed.switch_policies is None:
        return {}
    interface_contexts: dict[str, list[str | None]] = {}
    interfaces = parsed.switch_facts.interfaces if parsed.switch_facts is not None else ()
    for interface in interfaces:
        if interface.kind != "management":
            key = matrix_attachment_interface_key(interface.name)
            interface_contexts.setdefault(key, []).append(interface.vrf)
    contexts: dict[str, list[str | None]] = {}
    for binding in parsed.switch_policies.bindings:
        if binding.purpose != "transit":
            continue
        subject = matrix_attachment_interface_key(binding.subject)
        matches = interface_contexts.get(subject, [])
        context = matches[0] if len(matches) == 1 else None
        if binding.vrf is not None and binding.vrf != context:
            context = None
        contexts.setdefault(matrix_binding_policy_id(binding), []).append(context)
    return {key: values[0] if len(values) == 1 else None for key, values in contexts.items()}


def matrix_catalog_switch_policy_contexts(revision: DeviceRevision) -> dict[str, str]:
    """Связать адресный каталог с подтверждённым VRF конкретной VLAN-привязки."""
    parsed = revision.parse_result
    facts, policies = parsed.switch_facts, parsed.switch_policies
    platform = revision.device.platform
    if (
        facts is None or policies is None or facts.platform != platform
        or platform not in {"aos-cx", "comware"} or parsed.errors
    ):
        return {}

    interfaces: dict[str, list[SwitchInterface]] = defaultdict(list)
    for interface in facts.interfaces:
        if interface.kind == "vlan":
            interfaces[matrix_attachment_interface_key(interface.name)].append(interface)

    bindings = [
        (matrix_attachment_interface_key(binding.subject), binding)
        for binding in policies.bindings if binding.subject.startswith("interface:")
    ]
    points = Counter((subject, binding.direction) for subject, binding in bindings)
    unresolved = {subject for subject, binding in bindings if binding.direction is None}
    declarations = {item.acl_id for item in policies.declarations}
    confirmed: dict[str, str] = {}
    for subject, binding in bindings:
        if (
            binding.purpose != "transit" or binding.direction not in {"routed-in", "routed-out"}
            or not binding.acl_id.startswith("ipv4:") or binding.acl_id not in declarations
            or not binding.source_locations
        ):
            continue
        matches = interfaces.get(subject, [])
        if len(matches) != 1 or points[subject, binding.direction] != 1 or subject in unresolved:
            continue
        interface = matches[0]
        vrf = interface.vrf
        if not vrf or interface.mode != "l3" or interface.admin_state == "disabled":
            continue
        anchor = binding.source_locations[0]
        if anchor.line_start is None or not any(
            location.source_name == anchor.source_name and location.line_start == anchor.line_start
            for location in interface.source_locations
        ):
            continue
        if not any(item.status == "known" and item.cidr and ":" not in item.cidr for item in interface.addresses):
            continue
        if platform == "comware":
            if binding.configured_profile is None or binding.vrf != vrf:
                continue
        else:
            provenance = interface.vrf_source_location
            if provenance is None or provenance.source_name != anchor.source_name or binding.vrf not in (None, vrf):
                continue
        confirmed[matrix_binding_policy_id(binding)] = vrf
    return confirmed


def matrix_policy_supports_zones(revision: DeviceRevision) -> bool:
    device = revision.device
    return (
        (device.vendor == "usergate" and device.platform.startswith("ugos-"))
        or (device.vendor == "ideco" and device.platform.startswith("ideco-classic-"))
    )


def matrix_policy_zones(
    revision: DeviceRevision, policy_id: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Предложить имена зон, разрешённые парсером в сохранённых правилах."""
    if not matrix_policy_supports_zones(revision):
        return (), ()
    sources: set[str] = set()
    destinations: set[str] = set()
    for rule in revision.parse_result.rules:
        if rule.policy_id != policy_id or rule.zone_status != DataStatus.KNOWN:
            continue
        if rule.source_zone is not None:
            sources.add(rule.source_zone)
        if rule.destination_zone is not None:
            destinations.add(rule.destination_zone)
    return tuple(sorted(sources)), tuple(sorted(destinations))


def _outside_zone_pair(rule: Rule, pair: MatrixZonePair) -> bool:
    return (
        rule.match_status == DataStatus.KNOWN and rule.zone_status == DataStatus.KNOWN
        and (
            rule.source_zone not in (None, pair.source_zone)
            or rule.destination_zone not in (None, pair.destination_zone)
        )
    )


def _unbound_declarations(revision: DeviceRevision, policy_id: str) -> set[str]:
    policies = revision.parse_result.switch_policies
    if policies is None:
        return set()
    matches = [
        acl for acl in policies.declarations
        if policy_id == (
            f"acl:{acl.name}" if revision.device.platform == "comware"
            else f"acl:{acl.name}:unbound"
        )
    ]
    if len(matches) != 1:
        return set()
    return {
        rule_id for entry in matches[0].entries if entry.valid for rule_id in entry.rule_ids
    }


def matrix_binding_zones(binding: AclBinding) -> tuple[str | None, str | None]:
    zone = f"{binding.subject}:{binding.direction}"
    return (zone, None) if binding.direction in {"in", "routed-in"} else (None, zone)


def _fragment_evidence(
    boxes: Boxes, direction: str | None, attachment: str | None,
) -> dict[str, Any]:
    box = boxes[0]
    witness = box.witness()
    witness["direction"] = direction
    address = IPv4Address if box.family == 4 else IPv6Address
    source, destination, protocols, ports, _ = box.axes
    return {
        "witness": witness,
        "fragment": {
            "source": [str(address(item)) for item in source],
            "destination": [str(address(item)) for item in destination],
            "protocol_numbers": list(protocols),
            "destination_ports": list(ports) if protocols in {(6, 6), (17, 17)} else None,
        },
        "fragment_count": len(boxes),
        "attachment": attachment,
    }


def _local_binding(
    revision: DeviceRevision, binding: AclBinding | None, rules: tuple[Rule, ...], guard: Callable[[], None],
) -> AclBinding | None:
    policies = revision.parse_result.switch_policies
    if (
        policies is None or binding is None or binding.semantics != "first_match" or not rules
        or revision.parse_result.errors
    ):
        return None
    aruba = revision.device.platform in {"aos-cx", "aos-switch"}
    comware = (
        revision.device.platform == "comware" and revision.device.vendor == "hp-h3c"
        and binding.configured_profile == "hpe-flexfabric-5944-5945-r6622" and binding.direction == "routed-in"
    )
    if not (aruba or comware) or (
        aruba and any(
            issue.code in {"POLICY_TOKENIZATION", "ACL_REDECLARED", "BINDING_UNRESOLVED"}
            for issue in policies.issues
        )
    ):
        return None
    direction = "in" if binding.direction in {"in", "routed-in"} else "out"
    competing = [
        item for item in policies.bindings
        if item.subject == binding.subject and item.direction == binding.direction
    ]
    if len(competing) != 1:
        return None
    if len({rule.sequence for rule in rules}) != len(rules) or any(
        rule.policy_purpose != "transit" or rule.policy_semantics != "first_match"
        or rule.policy_direction != direction or rule.zone_status != DataStatus.KNOWN
        or (rule.source_zone, rule.destination_zone) != matrix_binding_zones(binding)
        for rule in rules
    ):
        return None
    declarations = [item for item in policies.declarations if item.acl_id == binding.acl_id]
    if len(declarations) != 1 or (comware and declarations[0].match_order != "config"):
        return None
    entries = declarations[0].entries
    by_id = {rule.rule_id: rule for rule in rules}
    represented: set[str] = set()
    for entry in entries:
        guard()
        matching = [by_id[key] for key in entry.rule_ids if key in by_id]
        if (
            not entry.valid or len(matching) != 1
            or entry.action not in {"permit", "deny"}
            or matching[0].sequence != entry.sequence
            or matching[0].action != (RuleAction.ALLOW if entry.action == "permit" else RuleAction.DENY)
            or matching[0].rule_id in represented
        ):
            return None
        rule = matching[0]
        if comware:
            source = resolve_addresses(entry.sources)
            destination = resolve_addresses(entry.destinations)
            match = resolve_rule(rule)
            if (
                source is None or destination is None or match is None
                or not source[0] or not destination[0]
                or rule.source_location not in entry.source_locations
                or match.sources[0] != source[0] or match.destinations[0] != destination[0]
                or match.services != resolve_services(entry.services)
            ):
                return None
        represented.add(rule.rule_id)
    return binding if represented == by_id.keys() else None


@dataclass(frozen=True)
class PolicyCoverage:
    any_allowed: bool
    any_denied: bool
    all_allowed: bool
    all_denied: bool
    unknown: bool
    complete: bool
    limited: bool
    evidence: tuple[Evidence, ...]


class MatrixCoverageCache:
    """Short-lived reuse for sequential evaluations of one immutable snapshot."""

    def __init__(
        self, revision: DeviceRevision, *, budget: int = 100_000, prepared_budget: int | None = None,
    ) -> None:
        self.revision = revision
        self._budget = budget
        self._weight = 0
        self._entries: OrderedDict[
            tuple[str, MatrixZonePair | None, Boxes],
            tuple[PolicyMode, PolicyCoverage, AttachmentScopeAssessment, int],
        ] = OrderedDict()
        self._prepared_budget = budget if prepared_budget is None else prepared_budget
        self._prepared_weight = 0
        self._prepared: OrderedDict[str, MatrixPolicy] = OrderedDict()
        self._row_weight = 0
        self._rows: OrderedDict[RuleMatch, tuple[Boxes, int]] = OrderedDict()
        self._residual_weight = 0
        self._residuals: OrderedDict[tuple[Boxes, Boxes, int], tuple[Boxes, int, int]] = OrderedDict()
        self._group_weight = 0
        self._groups: OrderedDict[GroupAddressKey, tuple[AddressSet | None, int]] = OrderedDict()

    def resize(self, budget: int, prepared_budget: int) -> None:
        self._budget = budget
        self._prepared_budget = prepared_budget
        while self._weight > budget:
            _, (_, _, _, weight) = self._entries.popitem(last=False)
            self._weight -= weight
        while self._prepared_weight > prepared_budget:
            _, policy = self._prepared.popitem(last=False)
            self._prepared_weight -= policy.prepared_weight
        while self._row_weight > budget:
            _, (_, weight) = self._rows.popitem(last=False)
            self._row_weight -= weight
        while self._residual_weight > budget // 2:
            _, (_, _, weight) = self._residuals.popitem(last=False)
            self._residual_weight -= weight
        while self._group_weight > budget // 2:
            _, (_, weight) = self._groups.popitem(last=False)
            self._group_weight -= weight

    def group_addresses(
        self, key: GroupAddressKey, weight: int, calculate: Callable[[], AddressSet | None],
    ) -> AddressSet | None:
        limit = self._budget // 2
        if weight > limit:
            return calculate()
        cached = self._groups.get(key)
        if cached is not None:
            self._groups.move_to_end(key)
            return cached[0]
        addresses = calculate()
        weight += sum(map(len, addresses)) if addresses is not None else 0
        if weight <= limit:
            while self._group_weight + weight > limit:
                _, (_, evicted) = self._groups.popitem(last=False)
                self._group_weight -= evicted
            self._groups[key] = addresses, weight
            self._group_weight += weight
        return addresses

    def row_boxes(self, match: RuleMatch, budget: MatrixBudget) -> Boxes:
        cached = self._rows.get(match)
        if cached is not None:
            self._rows.move_to_end(match)
            return cached[0]
        boxes = packet_boxes(match, "global", budget)
        weight = 1 + len(boxes) + sum(map(len, (*match.sources, *match.destinations)))
        weight += sum(1 + len(ports) for _, ports in match.services)
        if weight <= self._budget:
            while self._row_weight + weight > self._budget:
                _, (_, removed) = self._rows.popitem(last=False)
                self._row_weight -= removed
            self._rows[match] = boxes, weight
            self._row_weight += weight
        return boxes

    def subtract_exception(self, region: Boxes, permitted: Boxes, budget: MatrixBudget) -> Boxes:
        if not region or not permitted:
            return region
        limit = self._budget // 2
        weight = 1 + len(region) + len(permitted)
        if weight > limit:
            return subtract_boxes(region, permitted, budget)[0]
        key = region, permitted, budget.max_fragments
        cached = self._residuals.get(key)
        if cached is not None:
            remaining, operations, _ = cached
            budget.charge_cached(operations)
            self._residuals.move_to_end(key)
            return remaining
        start = budget.operations
        remaining, _ = subtract_boxes(region, permitted, budget)
        weight += len(remaining)
        if weight <= limit:
            while self._residual_weight + weight > limit:
                _, (_, _, evicted) = self._residuals.popitem(last=False)
                self._residual_weight -= evicted
            self._residuals[key] = remaining, budget.operations - start, weight
            self._residual_weight += weight
        return remaining

    def prepare_policy(
        self, policy_id: str, rules: tuple[Rule, ...], guard: Callable[[], None],
    ) -> MatrixPolicy:
        guard()
        cached = self._prepared.get(policy_id)
        if cached is not None:
            self._prepared.move_to_end(policy_id)
            return cached
        policy = MatrixPolicy(self.revision, policy_id, rules, guard)
        weight = policy.prepared_weight
        if weight <= self._prepared_budget:
            while self._prepared_weight + weight > self._prepared_budget:
                _, evicted = self._prepared.popitem(last=False)
                self._prepared_weight -= evicted.prepared_weight
            self._prepared[policy_id] = policy
            self._prepared_weight += weight
        return policy

    def get(
        self, policy_id: str, boxes: Boxes, *, zone_pair: MatrixZonePair | None = None,
    ) -> tuple[PolicyMode, PolicyCoverage, AttachmentScopeAssessment] | None:
        key = policy_id, zone_pair, boxes
        cached = self._entries.get(key)
        if cached is None:
            return None
        self._entries.move_to_end(key)
        mode, coverage, attachment, _ = cached
        return mode, coverage, attachment

    def put(
        self, policy_id: str, boxes: Boxes, mode: PolicyMode, coverage: PolicyCoverage,
        attachment: AttachmentScopeAssessment, *,
        zone_pair: MatrixZonePair | None = None,
    ) -> None:
        weight = 1 + len(boxes) + sum(1 + len(item.source_locations) for item in coverage.evidence)
        weight += len(attachment.source_locations) + len(attachment.reasons)
        if not coverage.complete or weight > self._budget:
            return
        key = policy_id, zone_pair, boxes
        previous = self._entries.pop(key, None)
        if previous is not None:
            self._weight -= previous[3]
        while self._weight + weight > self._budget:
            _, (_, _, _, removed_weight) = self._entries.popitem(last=False)
            self._weight -= removed_weight
        self._entries[key] = mode, coverage, attachment, weight
        self._weight += weight


class MatrixPolicy:
    """Неизменяемый подготовленный набор условий одной явно выбранной политики."""

    def __init__(
        self, revision: DeviceRevision, policy_id: str, rules: tuple[Rule, ...],
        guard: Callable[[], None],
    ) -> None:
        binding = matrix_transit_binding(revision, policy_id)
        zones = matrix_binding_zones(binding) if binding else (None, None)
        self.binding = _local_binding(revision, binding, rules, guard)
        self._rules = tuple(sorted(rules, key=lambda rule: rule.sequence))
        self._boxes: dict[int, Boxes] = {}
        self._unknown: set[int] = set()
        self._legacy_zone_unknown: set[int] = set()
        parsed = revision.parse_result
        facts = parsed.switch_facts
        self._advanced = revision.device.platform == "cloud-ru-advanced-sg"
        unbound = _unbound_declarations(revision, policy_id)
        self._unbound = bool(unbound)
        self._configured_application_available = bool(
            self._unbound and revision.device.platform == "comware" and parsed.switch_policies is not None
            and any(
                item.configured_profile is not None and item.acl_id == f"ipv4:{policy_id.removeprefix('acl:')}"
                for item in parsed.switch_policies.bindings
            )
        )
        self._supports_zone_pairs = matrix_policy_supports_zones(revision)
        inconsistent_directions = len({rule.policy_direction for rule in rules}) > 1
        configured_acl = self.binding is not None and self.binding.configured_profile is not None
        self.incomplete = bool(parsed.errors or (
            not configured_acl and (parsed.unsupported_constructs
                                    or parsed.coverage.recognized_constructs != parsed.coverage.discovered_constructs)
        ))
        outside_declarations = 0
        if self._supports_zone_pairs:
            for construct in parsed.unsupported_constructs:
                guard()
                outside_declarations += int(construct.construct_type in _OUTSIDE_ZONE_DECLARATIONS)
        self._zone_declarations_incomplete = bool(
            parsed.errors or outside_declarations != len(parsed.unsupported_constructs)
            or parsed.coverage.recognized_constructs + outside_declarations != parsed.coverage.discovered_constructs
        )
        self._implicit_deny = bool(
            self.binding and self.binding.implicit_action == "deny"
            and self.binding.implicit_action_reference and facts and facts.configuration_complete
            and not self.incomplete
        )
        for index, rule in enumerate(self._rules):
            guard()
            zoned = (rule.source_zone, rule.destination_zone) != zones
            if zoned and self._supports_zone_pairs:
                self._legacy_zone_unknown.add(index)
            match = resolve_rule(rule)
            if (
                match is None or rule.action not in _DENIALS | {RuleAction.ALLOW}
                or inconsistent_directions
                or (rule.zone_status != DataStatus.KNOWN and rule.rule_id not in unbound)
                or (zoned and not self._supports_zone_pairs)
            ):
                self._unknown.add(index)
                continue
            try:
                boxes = packet_boxes(match, "global", MatrixBudget(guard))
            except (CoverageLimitError, UnsupportedCoverageError):
                self._unknown.add(index)
            else:
                self._boxes[index] = tuple(
                    box for box in boxes if parsed.switch_policies is None or box.family == 4
                )
        self._cloud = None if self._unknown else advanced_sg_policy(revision, policy_id, self._rules)
        self.mode: PolicyMode = "local_policy" if self.binding or self._cloud else "declared_rules"
        # Правило индексируется один раз. Явная пара читает только точную и три общие области.
        buckets: dict[ZoneBucket, list[tuple[int, PacketBox]]] = defaultdict(list)
        for index, boxes in self._boxes.items():
            guard()
            rule = self._rules[index]
            key = (rule.source_zone, rule.destination_zone) if self._supports_zone_pairs else (None, None)
            buckets[key].extend((index, box) for box in boxes)
        self._indexes = {key: PacketCandidateIndex(entries, guard) for key, entries in buckets.items()}
        self.prepared_weight = 1 + len(self._rules) + 6 * sum(len(entries) for entries in buckets.values())

    def cover(
        self, boxes: Boxes, budget: CoverageBudget, *, guard: Callable[[], None],
        zone_pair: MatrixZonePair | None = None,
    ) -> PolicyCoverage:
        """Сохранить покрытие и контрпримеры, учитывая порядок только в локальном режиме."""
        if zone_pair is not None and not self._supports_zone_pairs:
            return PolicyCoverage(
                any_allowed=False, any_denied=False, all_allowed=False, all_denied=False,
                unknown=True, complete=False, limited=False, evidence=(),
            )
        keys: tuple[ZoneBucket, ...] = ((None, None),)
        candidate_ids = self._unknown.copy()
        if zone_pair is None:
            candidate_ids.update(self._legacy_zone_unknown)
        else:
            source, destination = zone_pair.source_zone, zone_pair.destination_zone
            keys += ((source, destination), (source, None), (None, destination))
        for key in keys:
            if (packet_index := self._indexes.get(key)) is not None:
                candidate_ids.update(packet_index.overlapping(boxes, guard))
        candidates = sorted(candidate_ids)
        allowed_remaining = denied_remaining = pending = boxes
        any_allowed = any_denied = uncertain = limited = False
        evidence: list[Evidence] = []
        ordered = self.mode == "local_policy"
        locations: tuple[SourceLocation, ...] = ()
        direction: str | None = None
        attachment: str | None = None
        summary = "Условие правила пересекает область оценки"
        limitations = ("Порядок применения, маршрут и сквозной доступ не оценены.",)
        if self.binding:
            locations = self.binding.source_locations
            direction, attachment = self.binding.direction, self.binding.subject
            summary = "Первое совпадение в представленном ACL"
            limitations = (
                "Локальное решение относится к пакету, поступившему на указанное применение ACL.",
                "Маршрут и сквозной доступ не оценены.",
            )
            if self.binding.configured_profile is not None:
                summary = "Первое совпадение в настроенном IPv4 ACL Comware"
                limitations += ("Применение ACL в оборудовании не подтверждено конфигурационным снимком.",)
        elif self._cloud:
            locations = self._cloud.source_locations
            direction, attachment = self._cloud.direction, self._cloud.interface_id
            summary = (
                "Совпадение по наблюдённому порядку групп и приоритету правила Advanced"
                if self._cloud.order_evidence is not None
                else "Совпадение по приоритету единственной назначенной группы Advanced"
            )
            limitations = (
                "Решение фильтра для нового соединения на указанных IP интерфейса и в выбранном направлении.",
                "Отслеживаемые соединения, обратное направление, маршруты и другие фильтры не оценены.",
            )
        elif self._advanced:
            limitations += (
                "Для расчёта порядка Advanced нужны подтверждённая фильтрация, полные правила "
                "и единственная назначенная группа или наблюдённый входящий порядок всех назначенных групп.",
            )
        if self._configured_application_available:
            limitations += ("Выбрано объявление ACL. Для расчёта порядка выберите его привязку к VLAN.",)
        elif self._unbound:
            limitations += ("Место применения ACL не подтверждено.",)
        if zone_pair is not None:
            limitations += (
                "Сопоставлены объявленные условия для указанной пары зон. Системные правила и NAT не оценены.",
            )
        for index in candidates:
            guard()
            if ordered and not pending:
                break
            rule = self._rules[index]
            if zone_pair is not None and _outside_zone_pair(rule, zone_pair):
                continue
            if index in self._unknown or (zone_pair is None and index in self._legacy_zone_unknown):
                uncertain = True
                if ordered:
                    break
                continue
            allows = rule.action == RuleAction.ALLOW
            target = pending if ordered else (allowed_remaining if allows else denied_remaining)
            try:
                residual, hits = subtract_boxes(target, self._boxes[index], budget)
            except CoverageLimitError:
                limited = True
                break
            if not hits:
                continue
            if ordered:
                pending = residual
            if allows:
                any_allowed = True
                if not ordered:
                    allowed_remaining = residual
            else:
                any_denied = True
                if not ordered:
                    denied_remaining = residual
            facts = {
                "action": rule.action.value, "policy_id": rule.policy_id,
                "mode": self.mode, **_fragment_evidence(hits, direction, attachment),
            }
            if self.binding:
                facts["sequence"] = rule.sequence
                if self.binding.configured_profile is not None:
                    facts["configured_profile"] = self.binding.configured_profile
            if self._cloud:
                facts.update(self._cloud.rule_facts(rule))
            if zone_pair is not None:
                facts.update(
                    source_zone=zone_pair.source_zone, destination_zone=zone_pair.destination_zone,
                    rule_source_zone=rule.source_zone, rule_destination_zone=rule.destination_zone,
                )
            evidence.append(Evidence(
                summary=summary,
                related_rule_ids=(rule.rule_id,),
                source_locations=(
                    rule.source_location, *(self._cloud.rule_locations(rule) if self._cloud else locations),
                ),
                facts=facts,
                limitations=limitations,
            ))
        if self._implicit_deny and pending and not uncertain and not limited and self.binding:
            remaining_ipv4 = tuple(box for box in pending if box.family == 4)
            if remaining_ipv4:
                pending = tuple(box for box in pending if box.family != 4)
                any_denied = True
                evidence.append(Evidence(
                    summary="Остаток совпадает с документированным неявным запретом ACL",
                    source_locations=self.binding.source_locations,
                    facts={
                        "action": "deny", "mode": self.mode,
                        "reference": self.binding.implicit_action_reference,
                        **_fragment_evidence(remaining_ipv4, direction, attachment),
                    },
                    limitations=limitations,
                ))
        if self.binding and self.binding.configured_profile is not None and not uncertain and not limited:
            unmatched_ipv4 = tuple(box for box in pending if box.family == 4)
            if unmatched_ipv4:
                uncertain = True
                evidence.append(Evidence(
                    summary="Для части IPv4-условий в ACL нет явного совпадения",
                    source_locations=locations,
                    facts={
                        "mode": self.mode, "configured_profile": self.binding.configured_profile,
                        **_fragment_evidence(unmatched_ipv4, direction, attachment),
                    },
                    limitations=(*limitations, "Действие по умолчанию для этого снимка не использовано."),
                ))
        if self._cloud and pending and not uncertain and not limited:
            try:
                pending, denied = subtract_boxes(pending, self._cloud.domain, budget)
            except CoverageLimitError:
                limited = True
            else:
                uncertain = bool(pending)
                if denied:
                    any_denied = True
                    evidence.append(Evidence(
                        summary=(
                            "В полном снимке назначенных групп Advanced нет совпадения для нового соединения"
                            if self._cloud.order_evidence is not None
                            else "В полном снимке группы Advanced нет совпадения для нового соединения"
                        ),
                        source_locations=locations,
                        facts={
                            "action": "deny", "mode": self.mode, "reference": self._cloud.matching_reference,
                            **_fragment_evidence(denied, direction, attachment),
                        },
                        limitations=limitations,
                    ))
        all_allowed = not (pending or any_denied) if ordered else not allowed_remaining
        all_denied = not (pending or any_allowed) if ordered else not denied_remaining
        incomplete = self._zone_declarations_incomplete if zone_pair is not None else self.incomplete
        unknown = uncertain or limited or incomplete
        complete = not unknown and (not pending if ordered else all_allowed or all_denied)
        return PolicyCoverage(
            any_allowed, any_denied, all_allowed, all_denied,
            unknown, complete, limited, tuple(evidence),
        )
