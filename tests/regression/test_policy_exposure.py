"""Synthetic organizational service exposure contracts; no ports imply asset roles."""

from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import UUID

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from firewall_compliance.checks.access.exposure import (
    DangerousServicesCheck,
    UntrustedAdministrativeAccessCheck,
)
from firewall_compliance.checks.policy_quality.rules import PolicyCheckContext
from firewall_compliance.domain import (
    Configuration,
    DataStatus,
    Device,
    DeviceRevision,
    Endpoint,
    EndpointKind,
    ParseCoverage,
    ParseResult,
    PortRange,
    Protocol,
    RevisionSource,
    Rule,
    RuleAction,
    Service,
    SourceDocumentKind,
    SourceLocation,
)
from firewall_compliance.domain.assurance import CheckStatus
from firewall_compliance.domain.enums import ParseIssueLevel
from firewall_compliance.domain.parse_result import ParseIssue
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile, PolicyServiceSelector

AT = datetime(2026, 10, 27, tzinfo=UTC)
CONFIG_ID = UUID("00000000-1111-2222-3333-444444444444")
REVISION_ID = UUID("00000000-1111-2222-3333-555555555555")


def endpoint(value="any"):
    return Endpoint(
        endpoint_id=value,
        name=value,
        kind=EndpointKind.ANY if value == "any" else EndpointKind.SUBNET,
        cidrs=() if value == "any" else (value,),
    )


def rule(
    identifier="r1",
    *,
    source="any",
    destination="any",
    protocol=Protocol.TCP,
    start=22,
    end=23,
    **changes,
):
    return Rule(
        rule_id=identifier,
        configuration_id=CONFIG_ID,
        name=identifier,
        sequence=1,
        action=changes.pop("action", RuleAction.ALLOW),
        enabled=changes.pop("enabled", True),
        sources=(endpoint(source),),
        destinations=(endpoint(destination),),
        services=(
            Service(
                service_id="service",
                name="service",
                protocol=protocol,
                port_ranges=(PortRange(start=start, end=end),)
                if protocol in {Protocol.TCP, Protocol.UDP}
                else (),
            ),
        ),
        match_status=changes.pop("match_status", DataStatus.KNOWN),
        source_location=SourceLocation(
            source_name="synthetic", object_path=f"$.rules.{identifier}"
        ),
        **changes,
    )


def context(*rules, warnings=()):
    config = Configuration(
        configuration_id=CONFIG_ID,
        source_name="synthetic",
        device_id="device",
        vendor="synthetic",
        platform="synthetic",
        parser_version="1",
        content_sha256="a" * 64,
        captured_at=AT,
        imported_at=AT,
    )
    revision = DeviceRevision(
        revision_id=REVISION_ID,
        device=Device(device_id="device", vendor="synthetic", platform="synthetic"),
        application_version="0.4.0",
        imported_at=AT,
        parse_result=ParseResult(
            configuration=config,
            rules=rules,
            source_map={value.rule_id: value.source_location for value in rules},
            warnings=warnings,
            coverage=ParseCoverage(
                discovered_constructs=len(rules),
                recognized_constructs=len(rules),
                unsupported_constructs=0,
            ),
        ),
        sources=(
            RevisionSource(
                source_name="synthetic",
                content_sha256="a" * 64,
                kind=SourceDocumentKind.CONFIGURATION,
                captured_at=AT,
            ),
        ),
    )
    return PolicyCheckContext(revision, AT)


def selector(identifier="service-policy", *, protocol="tcp", start=23, end=23):
    return PolicyServiceSelector(
        selector_id=identifier,
        name="Explicit organization requirement",
        protocol=protocol,
        port_ranges=(PortRange(start=start, end=end),) if protocol != "icmp" else (),
    )


def profile(**changes):
    return PolicyExposureProfile(
        dangerous_services=(selector(),),
        administrative_services=(selector("admin", start=22, end=22),),
        administrative_targets=("192.0.2.0/24",),
        trusted_admin_networks=("10.0.0.0/8",),
        **changes,
    )


def codes(result):
    return {value.code for value in result.limitations}


def test_unknown_profile_does_not_claim_checks_executed():
    for check in (DangerousServicesCheck(), UntrustedAdministrativeAccessCheck()):
        result = check.evaluate(context(rule()))
        assert not result.findings and result.status == CheckStatus.PARTIAL
        assert {"CHECK_NOT_EXECUTED", "EXPOSURE_POLICY_UNKNOWN"} <= codes(result)


def test_explicit_empty_catalogue_or_admin_targets_is_not_applicable():
    cases = (
        DangerousServicesCheck(PolicyExposureProfile(dangerous_services=())),
        UntrustedAdministrativeAccessCheck(PolicyExposureProfile(administrative_services=())),
        UntrustedAdministrativeAccessCheck(PolicyExposureProfile(administrative_targets=())),
    )
    for check in cases:
        result = check.evaluate(context(rule()))
        assert result.status == CheckStatus.NOT_APPLICABLE and not result.findings


def test_service_intersection_keeps_ports_and_original_source():
    result = DangerousServicesCheck(profile()).evaluate(context(rule()))
    assert result.status == CheckStatus.COMPLETE and len(result.findings) == 1
    finding = result.findings[0]
    assert finding.evidence.facts["destination_port_ranges"] == [[23, 23]]
    assert finding.evidence.facts["basis"] == "declared_allow_condition"
    assert finding.evidence.source_locations[0].object_path == "$.rules.r1"
    assert finding.evidence.related_rule_ids == ("r1",)
    assert finding.configuration_id == CONFIG_ID and finding.revision_id == REVISION_ID
    assert finding.evidence.facts["rule"]["logging_enabled"] is None


@pytest.mark.parametrize(
    "action,enabled",
    [
        (RuleAction.DENY, True),
        (RuleAction.ALLOW, False),
        (RuleAction.REJECT, True),
        (RuleAction.DROP, True),
        (RuleAction.LOG, True),
    ],
)
def test_disabled_or_non_allow_rule_is_not_a_permit_exposure(action, enabled):
    result = DangerousServicesCheck(profile()).evaluate(
        context(rule(action=action, enabled=enabled))
    )
    assert result.status == CheckStatus.COMPLETE and not result.findings


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"action": RuleAction.UNKNOWN}, "UNKNOWN_ACTION"),
        ({"match_status": DataStatus.UNKNOWN}, "UNKNOWN_MATCH"),
        ({"service_status": DataStatus.UNSUPPORTED}, "UNKNOWN_MATCH"),
        ({"protocol": Protocol.OTHER}, "UNKNOWN_MATCH"),
    ],
)
def test_unknown_conditions_are_not_promoted_to_any(changes, code):
    result = DangerousServicesCheck(profile()).evaluate(context(rule(**changes)))
    assert not result.findings and {code, "CHECK_NOT_EXECUTED"} <= codes(result)


def test_ip_service_explicitly_includes_tcp_selector_and_two_address_families():
    result = DangerousServicesCheck(profile()).evaluate(context(rule(protocol=Protocol.IP)))
    facts = result.findings[0].evidence.facts
    assert facts["protocol"] == "tcp" and facts["destination_port_ranges"] == [[23, 23]]
    assert {value["ip_version"] for value in facts["source_ranges"]} == {4, 6}
    assert (
        next(value for value in facts["source_ranges"] if value["ip_version"] == 6)["ranges"][0][
            "start"
        ]
        == "::"
    )


def test_other_protocol_does_not_match_selector():
    result = DangerousServicesCheck(profile()).evaluate(context(rule(protocol=Protocol.UDP)))
    assert not result.findings and result.status == CheckStatus.COMPLETE


def test_icmp_selector_has_no_invented_ports():
    configured = PolicyExposureProfile(dangerous_services=(selector(protocol="icmp"),))
    result = DangerousServicesCheck(configured).evaluate(context(rule(protocol=Protocol.ICMP)))
    assert len(result.findings) == 1
    assert result.findings[0].evidence.facts["destination_port_ranges"] == []


def test_missing_targets_or_trusted_networks_never_infers_admin_role():
    service = selector("web-port", start=443, end=443)
    for missing in ("administrative_targets", "trusted_admin_networks", "administrative_services"):
        config = profile().model_dump(mode="python")
        config["administrative_services"] = (service,)
        config[missing] = None
        result = UntrustedAdministrativeAccessCheck(
            PolicyExposureProfile.model_validate(config)
        ).evaluate(context(rule(start=443, end=443)))
        assert not result.findings and "CHECK_NOT_EXECUTED" in codes(result)


def test_trusted_union_covers_source_without_false_finding():
    config = profile().model_dump(mode="python")
    config["trusted_admin_networks"] = ("198.51.100.0/25", "198.51.100.128/25")
    result = UntrustedAdministrativeAccessCheck(
        PolicyExposureProfile.model_validate(config)
    ).evaluate(context(rule(source="198.51.100.0/24", destination="192.0.2.9/32")))
    assert result.status == CheckStatus.COMPLETE and not result.findings


def test_untrusted_difference_and_target_intersection_are_exact():
    config = profile().model_dump(mode="python")
    config["trusted_admin_networks"] = ("198.51.100.64/26",)
    result = UntrustedAdministrativeAccessCheck(
        PolicyExposureProfile.model_validate(config)
    ).evaluate(context(rule(source="198.51.100.0/24", destination="192.0.0.0/16")))
    assert result.status == CheckStatus.COMPLETE
    facts = result.findings[0].evidence.facts
    assert facts["source_ranges"] == [
        {
            "ip_version": 4,
            "ranges": [
                {"start": "198.51.100.0", "end": "198.51.100.63"},
                {"start": "198.51.100.128", "end": "198.51.100.255"},
            ],
        }
    ]
    assert facts["destination_ranges"] == [
        {
            "ip_version": 4,
            "ranges": [
                {"start": "192.0.2.0", "end": "192.0.2.255"},
            ],
        }
    ]


def test_explicit_empty_trust_does_not_treat_private_network_as_trusted():
    config = profile().model_dump(mode="python")
    config["trusted_admin_networks"] = ()
    result = UntrustedAdministrativeAccessCheck(
        PolicyExposureProfile.model_validate(config)
    ).evaluate(context(rule(source="10.0.0.1/32", destination="192.0.2.2/32")))
    assert len(result.findings) == 1


def test_ipv6_source_and_target_are_kept_in_ipv6_even_for_low_addresses():
    config = profile().model_dump(mode="python")
    config.update(administrative_targets=("::/120",), trusted_admin_networks=("::/121",))
    result = UntrustedAdministrativeAccessCheck(
        PolicyExposureProfile.model_validate(config)
    ).evaluate(context(rule(source="::/120", destination="::2/128")))
    facts = result.findings[0].evidence.facts
    assert facts["source_ranges"] == [
        {"ip_version": 6, "ranges": [{"start": "::80", "end": "::ff"}]}
    ]
    assert facts["destination_ranges"][0]["ranges"][0]["start"] == "::2"


def test_cross_family_source_target_does_not_create_access():
    config = profile().model_dump(mode="python")
    config.update(administrative_targets=("2001:db8::/32",), trusted_admin_networks=())
    result = UntrustedAdministrativeAccessCheck(
        PolicyExposureProfile.model_validate(config)
    ).evaluate(context(rule(source="192.0.2.1/32", destination="any")))
    assert not result.findings


def test_declared_allow_review_does_not_claim_first_match_effective_access():
    first = rule("deny", action=RuleAction.DENY)
    second = rule("allow")
    result = DangerousServicesCheck(profile()).evaluate(context(first, second))
    assert len(result.findings) == 1
    assert result.findings[0].affected_rule_ids == ("allow",)
    assert any("first-match" in value for value in result.findings[0].evidence.limitations)


def test_incomplete_parse_keeps_supported_finding_and_partial_result():
    warning = ParseIssue(
        code="UNRESOLVED_SCOPE",
        level=ParseIssueLevel.WARNING,
        message="Synthetic incomplete source",
    )
    result = DangerousServicesCheck(profile()).evaluate(context(rule(), warnings=(warning,)))
    assert result.status == CheckStatus.PARTIAL and len(result.findings) == 1
    assert "INCOMPLETE_PARSE" in codes(result) and "CHECK_NOT_EXECUTED" not in codes(result)


def test_operation_budget_is_explicit_and_never_claims_complete():
    result = DangerousServicesCheck(profile(), max_operations=1).evaluate(context(rule()))
    assert result.status == CheckStatus.PARTIAL and not result.findings
    assert "EXPOSURE_LIMIT_REACHED" in codes(result)
    for invalid in (0, -1, True, 10_000_001):
        with pytest.raises(ValueError):
            DangerousServicesCheck(profile(), max_operations=invalid)


def test_profile_is_frozen_snapshot_and_finding_identity_covers_configuration():
    original = profile()
    check = DangerousServicesCheck(original)
    original.dangerous_services[0].port_ranges[0].end = 24
    first = check.evaluate(context(rule()))
    again = check.evaluate(context(rule()))
    assert first.model_dump(mode="json") == again.model_dump(mode="json")
    assert first.findings[0].evidence.facts["destination_port_ranges"] == [[23, 23]]
    changed = profile(version="2")
    assert DangerousServicesCheck(changed).evaluate(context(rule())).findings[0].finding_id != (
        first.findings[0].finding_id
    )


def test_profile_json_roundtrip_and_validation():
    original = profile()
    assert PolicyExposureProfile.model_validate_json(original.model_dump_json()) == original
    normalized = PolicyExposureProfile(administrative_targets=("192.0.2.5/24", "192.0.2.0/24"))
    assert normalized.administrative_targets == ("192.0.2.0/24",)
    for invalid in (
        {"administrative_targets": ("any",)},
        {"trusted_admin_networks": ("host.example",)},
        {"dangerous_services": (selector(), selector())},
        {"unknown_field": True},
        {"schema_version": "2.0.0"},
    ):
        with pytest.raises(ValidationError):
            PolicyExposureProfile.model_validate(invalid)
    for invalid in (
        {"selector_id": "x", "name": "x", "protocol": "tcp"},
        {
            "selector_id": "x",
            "name": "x",
            "protocol": "icmp",
            "port_ranges": ({"start": 1, "end": 2},),
        },
        {"selector_id": "x", "name": "x", "protocol": "ip"},
    ):
        with pytest.raises(ValidationError):
            PolicyServiceSelector.model_validate(invalid)


@settings(max_examples=60)
@given(st.integers(1, 100), st.integers(1, 100), st.integers(1, 100), st.integers(1, 100))
def test_port_intersection_matches_finite_set_oracle(a, b, c, d):
    lower, upper = sorted((a, b))
    forbidden_lower, forbidden_upper = sorted((c, d))
    configured = PolicyExposureProfile(
        dangerous_services=(selector(start=forbidden_lower, end=forbidden_upper),)
    )
    result = DangerousServicesCheck(configured).evaluate(context(rule(start=lower, end=upper)))
    expected = set(range(lower, upper + 1)) & set(range(forbidden_lower, forbidden_upper + 1))
    assert bool(result.findings) == bool(expected)
    if expected:
        actual = result.findings[0].evidence.facts["destination_port_ranges"]
        assert actual == [[min(expected), max(expected)]]


@settings(max_examples=50)
@given(st.integers(0, 255), st.integers(0, 255))
def test_trust_subtraction_matches_host_oracle(source_host, trusted_host):
    config = profile().model_dump(mode="python")
    config["trusted_admin_networks"] = (f"198.51.100.{trusted_host}/32",)
    result = UntrustedAdministrativeAccessCheck(
        PolicyExposureProfile.model_validate(config)
    ).evaluate(context(rule(source=f"198.51.100.{source_host}/32", destination="192.0.2.1/32")))
    assert bool(result.findings) == (source_host != trusted_host)
    if result.findings:
        actual = result.findings[0].evidence.facts["source_ranges"][0]["ranges"][0]["start"]
        assert int(ip_address(actual)) == int(ip_address(f"198.51.100.{source_host}"))
