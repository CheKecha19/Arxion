"""Bounded checks of declared ALLOW conditions against explicit organizational policy."""

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import IPv4Address, IPv6Address, ip_network
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from firewall_compliance.analysis.policy_checks import PolicyCheckContext
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult, CheckStatus
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import FindingCategory, RuleAction, Severity
from firewall_compliance.domain.finding import Evidence, Finding
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile, PolicyServiceSelector
from firewall_compliance.domain.policy_matching import (
    AddressSet,
    Interval,
    RuleMatch,
    merge_intervals,
    resolve_rule,
)

CHECK_VERSION = "1.0.0"


class _BudgetExceeded(Exception):
    pass


@dataclass
class _Budget:
    remaining: int

    def spend(self, amount: int = 1) -> None:
        self.remaining -= amount
        if self.remaining < 0:
            raise _BudgetExceeded


def _intersection(
    left: tuple[Interval, ...], right: tuple[Interval, ...], budget: _Budget
) -> tuple[Interval, ...]:
    values = []
    for first, last in left:
        for start, end in right:
            budget.spend()
            if max(first, start) <= min(last, end):
                values.append((max(first, start), min(last, end)))
    return merge_intervals(values)


def _subtract(
    values: tuple[Interval, ...], trusted: tuple[Interval, ...], budget: _Budget
) -> tuple[Interval, ...]:
    remaining = list(values)
    for start, end in trusted:
        updated = []
        for first, last in remaining:
            budget.spend()
            if last < start or first > end:
                updated.append((first, last))
            else:
                if first < start:
                    updated.append((first, start - 1))
                if last > end:
                    updated.append((end + 1, last))
        remaining = updated
    return merge_intervals(remaining)


def _addresses(values: tuple[str, ...]) -> AddressSet:
    families: tuple[list[Interval], list[Interval]] = ([], [])
    for value in values:
        network = ip_network(value)
        families[0 if network.version == 4 else 1].append(
            (int(network.network_address), int(network.broadcast_address))
        )
    return merge_intervals(families[0]), merge_intervals(families[1])


def _charge_rule(rule: Rule, budget: _Budget) -> None:
    """Bound resolution/serialization as well as subsequent interval comparisons."""
    budget.spend(len(rule.sources) + len(rule.destinations) + len(rule.services))
    for endpoint in (*rule.sources, *rule.destinations):
        budget.spend(len(endpoint.cidrs) + len(endpoint.ip_ranges))
    for service in rule.services:
        budget.spend(len(service.port_ranges))


def _ports(
    match: RuleMatch, selector: PolicyServiceSelector, budget: _Budget
) -> tuple[Interval, ...]:
    services = dict(match.services)
    permitted = services.get(selector.protocol, services.get("ip", ()))
    wanted = (
        tuple((value.start, value.end) for value in selector.port_ranges)
        if selector.port_ranges
        else ((0, 65535),)
    )
    return _intersection(permitted, wanted, budget)


def _serialize_addresses(values: AddressSet) -> list[dict[str, Any]]:
    return [
        {
            "ip_version": version,
            "ranges": [
                {"start": str(IPv4Address(start)), "end": str(IPv4Address(end))}
                if version == 4
                else {"start": str(IPv6Address(start)), "end": str(IPv6Address(end))}
                for start, end in intervals
            ],
        }
        for version, intervals in zip((4, 6), values, strict=True)
        if intervals
    ]


def _witness_flow(
    rule: Rule,
    selector: PolicyServiceSelector,
    sources: AddressSet,
    destinations: AddressSet,
    ports: tuple[Interval, ...],
    profile: PolicyExposureProfile,
    fingerprint: str,
) -> dict[str, Any]:
    """Choose one actual member of the proven intersection, with its policy basis."""
    family_index = 0 if sources[0] and destinations[0] else 1
    address = IPv4Address if family_index == 0 else IPv6Address
    return {
        "basis": "declared_allow_condition",
        "family": 4 if family_index == 0 else 6,
        "source_ip": str(address(sources[family_index][0][0])),
        "destination_ip": str(address(destinations[family_index][0][0])),
        "protocol": selector.protocol,
        "protocol_number": {"tcp": 6, "udp": 17, "icmp": 1}[selector.protocol],
        "destination_port": ports[0][0] if selector.protocol in {"tcp", "udp"} else None,
        "rule_id": rule.rule_id,
        "selector_id": selector.selector_id,
        "profile_id": profile.profile_id,
        "profile_version": profile.version,
        "profile_sha256": fingerprint,
    }


class _ExposureCheck:
    check_id: str

    def __init__(
        self,
        profile: PolicyExposureProfile | None = None,
        *,
        max_operations: int = 100_000,
        evidence_version: Literal["1.0.0", "1.1.0"] = "1.1.0",
    ) -> None:
        if type(max_operations) is not int or not 1 <= max_operations <= 10_000_000:
            raise ValueError("max_operations must be an integer in 1..10000000")
        self.profile = PolicyExposureProfile.model_validate(
            (profile or PolicyExposureProfile()).model_dump(mode="python")
        ).as_snapshot()
        self.max_operations = max_operations
        if evidence_version not in {"1.0.0", "1.1.0"}:
            raise ValueError("Unsupported exposure evidence version.")
        self.evidence_version = evidence_version

    def _finding(
        self,
        context: PolicyCheckContext,
        rule: Rule,
        selector: PolicyServiceSelector,
        sources: AddressSet,
        destinations: AddressSet,
        ports: tuple[Interval, ...],
    ) -> Finding:
        administrative = isinstance(self, UntrustedAdministrativeAccessCheck)
        title = (
            "Разрешённое условие административного доступа вне доверенных сетей."
            if administrative
            else "Разрешённое условие содержит запрещённый организацией сервис."
        )
        fingerprint = sha256(self.profile.model_dump_json().encode()).hexdigest()
        finding = Finding(
            finding_id=uuid5(
                NAMESPACE_URL,
                f"{context.revision.revision_id}:{self.check_id}:{CHECK_VERSION}:"
                f"{fingerprint}:{rule.rule_id}:{selector.selector_id}",
            ),
            check_id=self.check_id,
            category=FindingCategory.POLICY,
            severity=Severity.HIGH if administrative else Severity.MEDIUM,
            title=title,
            description=f"{selector.name}: пересечение заданного ALLOW с организационным профилем.",
            configuration_id=rule.configuration_id,
            revision_id=context.revision.revision_id,
            device_id=context.revision.device.device_id,
            affected_rule_ids=(rule.rule_id,),
            evidence=Evidence(
                summary=title,
                source_locations=(rule.source_location,),
                related_rule_ids=(rule.rule_id,),
                facts={
                    "basis": "declared_allow_condition",
                    "profile_id": self.profile.profile_id,
                    "profile_version": self.profile.version,
                    "profile_sha256": fingerprint,
                    "selector": selector.model_dump(mode="json"),
                    "source_ranges": _serialize_addresses(sources),
                    "destination_ranges": _serialize_addresses(destinations),
                    "protocol": selector.protocol,
                    "destination_port_ranges": [list(value) for value in ports]
                    if selector.protocol in {"tcp", "udp"}
                    else [],
                    "administrative_targets": self.profile.administrative_targets
                    if administrative
                    else None,
                    "trusted_admin_networks": self.profile.trusted_admin_networks
                    if administrative
                    else None,
                    "rule": rule.model_dump(mode="json"),
                },
                limitations=(
                    "Проверены заданные условия ALLOW, а не эффективное решение first-match.",
                    "Предыдущие правила, NAT, маршруты, runtime и фактическая достижимость "
                    "не вычислялись; порт сам по себе не подтверждает работу сервиса.",
                ),
            ),
            recommendation=(
                "Проверить назначение правила и согласовать его с организационным профилем."
            ),
            confidence=1.0,
            first_seen=context.analyzed_at,
            last_seen=context.analyzed_at,
        )
        if self.evidence_version == "1.1.0":
            facts = {
                **finding.evidence.facts,
                "witness_flow": _witness_flow(
                    rule, selector, sources, destinations, ports, self.profile, fingerprint
                ),
            }
            finding = finding.model_copy(
                update={"evidence": finding.evidence.model_copy(update={"facts": facts})}
            )
        return finding

    def _result(
        self,
        context: PolicyCheckContext,
        findings: list[Finding],
        limitations: list[CheckLimitation],
        *,
        executed: bool,
    ) -> CheckResult:
        parsed = context.revision.parse_result
        if (
            parsed.errors
            or parsed.warnings
            or parsed.unsupported_constructs
            or (parsed.coverage.coverage_ratio < 1)
        ):
            limitations.append(
                CheckLimitation(
                    code="INCOMPLETE_PARSE", message="Источник содержит ограничения разбора."
                )
            )
        if not executed and limitations:
            limitations.append(
                CheckLimitation(
                    code="CHECK_NOT_EXECUTED",
                    message="Нет достаточных данных для выполнения проверки.",
                )
            )
        return CheckResult(
            check_id=self.check_id,
            check_version=self.evidence_version,
            status=CheckStatus.PARTIAL if limitations else CheckStatus.COMPLETE,
            findings=tuple(findings),
            limitations=tuple(limitations),
        )

    def _evaluate(
        self,
        context: PolicyCheckContext,
        selectors: tuple[PolicyServiceSelector, ...] | None,
        *,
        administrative: bool,
    ) -> CheckResult:
        if selectors == () or administrative and self.profile.administrative_targets == ():
            return CheckResult(
                check_id=self.check_id,
                check_version=self.evidence_version,
                status=CheckStatus.NOT_APPLICABLE,
            )
        required = (
            (
                selectors,
                self.profile.administrative_targets,
                self.profile.trusted_admin_networks,
            )
            if administrative
            else (selectors,)
        )
        if selectors is None or any(value is None for value in required):
            return self._result(
                context,
                [],
                [
                    CheckLimitation(
                        code="EXPOSURE_POLICY_UNKNOWN",
                        message=(
                            "Не задан явный организационный профиль сервисов, целей "
                            "или доверенных сетей."
                        ),
                    )
                ],
                executed=False,
            )
        findings: list[Finding] = []
        limitations: list[CheckLimitation] = []
        executed = False
        budget = _Budget(self.max_operations)
        targets = _addresses(self.profile.administrative_targets or ())
        trusted = _addresses(self.profile.trusted_admin_networks or ())
        try:
            for rule in context.revision.parse_result.rules:
                budget.spend()
                if not rule.enabled:
                    continue
                if rule.action == RuleAction.UNKNOWN:
                    limitations.append(
                        CheckLimitation(
                            code="UNKNOWN_ACTION",
                            message="Действие правила неизвестно.",
                            rule_ids=(rule.rule_id,),
                        )
                    )
                    continue
                if rule.action != RuleAction.ALLOW:
                    continue
                _charge_rule(rule, budget)
                match = resolve_rule(rule)
                if match is None:
                    limitations.append(
                        CheckLimitation(
                            code="UNKNOWN_MATCH",
                            message="Условия правила не полностью известны.",
                            rule_ids=(rule.rule_id,),
                        )
                    )
                    continue
                sources, destinations = match.sources, match.destinations
                if administrative:
                    sources = (
                        _subtract(sources[0], trusted[0], budget),
                        _subtract(sources[1], trusted[1], budget),
                    )
                    destinations = (
                        _intersection(destinations[0], targets[0], budget),
                        _intersection(destinations[1], targets[1], budget),
                    )
                    sources = (
                        sources[0] if destinations[0] else (),
                        sources[1] if destinations[1] else (),
                    )
                    destinations = (
                        destinations[0] if sources[0] else (),
                        destinations[1] if sources[1] else (),
                    )
                for selector in selectors:
                    budget.spend()
                    ports = _ports(match, selector, budget)
                    selected_sources, selected_destinations = sources, destinations
                    if (
                        self.evidence_version == "1.1.0"
                        and ports
                        and selector.protocol == "icmp"
                        and sources[1]
                        and destinations[1]
                    ):
                        limitations.append(
                            CheckLimitation(
                                code="UNSUPPORTED_ICMPV6",
                                message="Неоднозначный ICMP не доказывает условия ICMPv6.",
                                rule_ids=(rule.rule_id,),
                            )
                        )
                        selected_sources = (sources[0], ())
                        selected_destinations = (destinations[0], ())
                    if ports and any(selected_sources) and any(selected_destinations):
                        _charge_rule(rule, budget)
                        findings.append(
                            self._finding(
                                context,
                                rule,
                                selector,
                                selected_sources,
                                selected_destinations,
                                ports,
                            )
                        )
                executed = True
        except _BudgetExceeded:
            limitations.append(
                CheckLimitation(
                    code="EXPOSURE_LIMIT_REACHED",
                    message="Достигнут заданный предел операций; оставшиеся условия не проверены.",
                )
            )
        return self._result(context, findings, limitations, executed=executed)


class DangerousServicesCheck(_ExposureCheck):
    """Review declared ALLOW intersections with an explicitly forbidden service catalogue."""

    check_id = "FW-DANGEROUS-SERVICES"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        return self._evaluate(context, self.profile.dangerous_services, administrative=False)


class UntrustedAdministrativeAccessCheck(_ExposureCheck):
    """Review explicit administrative targets/services outside explicit trusted sources."""

    check_id = "FW-ADMIN-UNTRUSTED"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        return self._evaluate(context, self.profile.administrative_services, administrative=True)
