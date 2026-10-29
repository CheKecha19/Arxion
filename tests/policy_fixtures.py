"""Обезличенные нормализованные политики для проверки Firewall Assurance."""

from typing import Any

from firewall_compliance.domain import (
    DataStatus,
    DeviceRevision,
    Endpoint,
    EndpointKind,
    ParseCoverage,
    PortRange,
    Protocol,
    Rule,
    RuleAction,
    Service,
    SourceLocation,
)
from tests.revision_fixtures import make_revision


def endpoint(cidr: str | None = None) -> Endpoint:
    """Создать явную сеть или any."""
    return Endpoint(
        endpoint_id=cidr or "any",
        name=cidr or "any",
        kind=EndpointKind.SUBNET if cidr else EndpointKind.ANY,
        cidrs=(cidr,) if cidr else (),
    )


def rule(sequence: int, **changes: Any) -> Rule:
    """Создать полностью известное разрешение TCP 443 в одной first-match ACL."""
    return Rule(
        **{
            "rule_id": f"rule-{sequence}",
            "configuration_id": make_revision().parse_result.configuration.configuration_id,
            "name": f"Правило {sequence}",
            "sequence": sequence,
            "action": RuleAction.ALLOW,
            "enabled": True,
            "sources": (endpoint("192.0.2.0/24"),),
            "destinations": (endpoint("203.0.113.10/32"),),
            "services": (
                Service(
                    service_id="https",
                    name="https",
                    protocol=Protocol.TCP,
                    port_ranges=(PortRange(start=443, end=443),),
                ),
            ),
            "policy_id": "ACL",
            "policy_direction": "in",
            "policy_semantics": "first_match",
            "match_status": DataStatus.KNOWN,
            "zone_status": DataStatus.KNOWN,
            "source_zone": "outside",
            "logging_enabled": True,
            "logging_status": DataStatus.KNOWN,
            "description_status": DataStatus.ABSENT,
            "source_location": SourceLocation(source_name="fixture.config", line_start=sequence),
            **changes,
        }
    )


def policy_revision(*rules: Rule, **parse_changes: Any) -> DeviceRevision:
    """Собрать валидированную ревизию с заданной политикой и диагностикой."""
    revision = make_revision()
    values = revision.model_dump()
    values["parse_result"] = {
        **revision.parse_result.model_dump(),
        "rules": rules,
        "source_map": {value.rule_id: value.source_location for value in rules},
        "coverage": ParseCoverage(
            discovered_constructs=len(rules),
            recognized_constructs=len(rules),
            unsupported_constructs=0,
        ),
        **parse_changes,
    }
    return DeviceRevision.model_validate(values)
