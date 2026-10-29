"""Bounded CHECKS-003/005 evaluation over explicit policy and attachment inputs."""

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import ip_network
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from firewall_compliance.checks.policy_quality.rules import PolicyCheckContext
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult, CheckStatus
from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import FindingCategory, Severity
from firewall_compliance.domain.finding import Evidence, Finding
from firewall_compliance.domain.policy_matching import (
    AddressSet,
    Interval,
    RuleMatch,
    intervals_cover,
    merge_intervals,
)
from firewall_compliance.domain.policy_scope import PolicyScopeProfile, RoleAccessRequirement

CHECK_VERSION = "1.0.0"


class _LimitReached(Exception):
    pass


@dataclass
class _Budget:
    remaining: int

    def spend(self, amount: int = 1) -> None:
        self.remaining -= amount
        if self.remaining < 0:
            raise _LimitReached


def _interval_count(values: tuple[Interval, ...]) -> int:
    return sum(end - start + 1 for start, end in values)


def _address_count(values: AddressSet) -> int:
    return _interval_count(values[0]) + _interval_count(values[1])


def _networks(values: tuple[str, ...]) -> AddressSet:
    families: tuple[list[Interval], list[Interval]] = ([], [])
    for value in values:
        network = ip_network(value)
        families[network.version - 4 if network.version == 4 else 1].append(
            (int(network.network_address), int(network.broadcast_address))
        )
    return merge_intervals(families[0]), merge_intervals(families[1])


def _intersects(left: AddressSet, right: AddressSet, budget: _Budget) -> bool:
    for first_family, second_family in zip(left, right, strict=True):
        for first_start, first_end in first_family:
            for second_start, second_end in second_family:
                budget.spend()
                if max(first_start, second_start) <= min(first_end, second_end):
                    return True
    return False


def _addresses_covered(allowed: AddressSet, actual: AddressSet) -> bool:
    return all(intervals_cover(outer, inner) for outer, inner in zip(allowed, actual, strict=True))


def _approved_services(requirement: RoleAccessRequirement) -> dict[str, tuple[Interval, ...]]:
    values: dict[str, list[Interval]] = {}
    for selector in requirement.approved_services:
        values.setdefault(selector.protocol, []).extend(
            [(item.start, item.end) for item in selector.port_ranges] or [(0, 65535)]
        )
    return {key: merge_intervals(value) for key, value in values.items()}


def _services_covered(
    requirement: RoleAccessRequirement, match: RuleMatch, budget: _Budget
) -> bool:
    approved = _approved_services(requirement)
    for protocol, ports in match.services:
        budget.spend()
        if protocol == "ip":
            return False
        if not intervals_cover(approved.get(protocol, ()), ports):
            return False
    return True


def _parse_limitations(context: PolicyCheckContext) -> list[CheckLimitation]:
    parsed = context.revision.parse_result
    if (
        parsed.errors
        or parsed.warnings
        or parsed.unsupported_constructs
        or parsed.coverage.coverage_ratio < 1
    ):
        return [
            CheckLimitation(
                code="INCOMPLETE_PARSE",
                message=(
                    "Источник содержит ограничения разбора; вывод относится только "
                    "к известной части."
                ),
            )
        ]
    return []


def _result(
    check_id: str,
    context: PolicyCheckContext,
    findings: list[Finding],
    limitations: list[CheckLimitation],
    *,
    applicable: bool = True,
) -> CheckResult:
    if not applicable:
        return CheckResult(
            check_id=check_id, check_version=CHECK_VERSION, status=CheckStatus.NOT_APPLICABLE
        )
    unique = {value.model_dump_json(): value for value in limitations}
    return CheckResult(
        check_id=check_id,
        check_version=CHECK_VERSION,
        status=CheckStatus.PARTIAL if unique else CheckStatus.COMPLETE,
        findings=tuple(findings),
        limitations=tuple(unique.values()),
    )


class _ProfileCheck:
    check_id: str

    def __init__(
        self, profile: PolicyScopeProfile | None = None, *, max_operations: int = 100_000
    ) -> None:
        if type(max_operations) is not int or not 1 <= max_operations <= 10_000_000:
            raise ValueError("max_operations must be an integer in 1..10000000")
        self.profile = (profile or PolicyScopeProfile()).as_snapshot()
        self.max_operations = max_operations

    def _finding(
        self,
        context: PolicyCheckContext,
        *,
        key: str,
        title: str,
        facts: dict[str, Any],
        rules: tuple[Rule, ...] = (),
        extra_locations: tuple[Any, ...] = (),
    ) -> Finding:
        profile_sha256 = sha256(self.profile.model_dump_json().encode()).hexdigest()
        configuration = context.revision.parse_result.configuration
        locations = []
        for location in (*[rule.source_location for rule in rules], *extra_locations):
            if location not in locations:
                locations.append(location)
        rule_ids = tuple(rule.rule_id for rule in rules)
        return Finding(
            finding_id=uuid5(
                NAMESPACE_URL,
                f"{context.revision.revision_id}:{self.check_id}:{CHECK_VERSION}:"
                f"{profile_sha256}:{key}",
            ),
            check_id=self.check_id,
            category=FindingCategory.POLICY,
            severity=Severity.MEDIUM,
            title=title,
            description=title,
            configuration_id=configuration.configuration_id,
            revision_id=context.revision.revision_id,
            device_id=context.revision.device.device_id,
            affected_rule_ids=rule_ids,
            evidence=Evidence(
                summary=title,
                source_locations=tuple(locations),
                related_rule_ids=rule_ids,
                facts={
                    "profile_id": self.profile.profile_id,
                    "profile_version": self.profile.version,
                    "profile_sha256": profile_sha256,
                    **facts,
                },
                limitations=(
                    "Вывод относится к объявленной конфигурации; фактическая достижимость, "
                    "NAT и runtime не вычислялись.",
                ),
            ),
            recommendation=(
                "Сверить правило или привязку с утверждённым профилем и "
                "согласованными исключениями."
            ),
            confidence=1.0,
            first_seen=context.analyzed_at,
            last_seen=context.analyzed_at,
        )
