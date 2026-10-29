"""Внутренний промежуточный результат узких текстовых грамматик ASA."""

from dataclasses import dataclass, field

from firewall_compliance.domain import (
    Interface,
    ParseCoverage,
    ParseIssue,
    Route,
    UnsupportedConstruct,
)
from firewall_compliance.parsers.network_contracts import InterfaceSettings


@dataclass
class ParsedNetworkFacts:
    interfaces: tuple[Interface, ...] = ()
    routes: tuple[Route, ...] = ()
    interface_labels: dict[str, str] = field(default_factory=dict)
    interface_settings: tuple[InterfaceSettings, ...] = ()
    warnings: tuple[ParseIssue, ...] = ()
    errors: tuple[ParseIssue, ...] = ()
    unsupported_constructs: tuple[UnsupportedConstruct, ...] = ()
    coverage: ParseCoverage = field(
        default_factory=lambda: ParseCoverage(
            discovered_constructs=0, recognized_constructs=0, unsupported_constructs=0
        )
    )
