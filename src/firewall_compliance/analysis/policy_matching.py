"""Совместимый импорт доменной алгебры условий правил."""

from firewall_compliance.domain.policy_matching import (
    AddressSet,
    Interval,
    RuleMatch,
    ScopeKey,
    ServiceSet,
    intervals_cover,
    matches_query,
    merge_intervals,
    resolve_addresses,
    resolve_rule,
    resolve_services,
    scope_key,
)

__all__ = [
    "AddressSet",
    "Interval",
    "RuleMatch",
    "ScopeKey",
    "ServiceSet",
    "intervals_cover",
    "matches_query",
    "merge_intervals",
    "resolve_addresses",
    "resolve_rule",
    "resolve_services",
    "scope_key",
]
