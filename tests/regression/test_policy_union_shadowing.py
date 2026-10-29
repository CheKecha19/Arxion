"""Exact first-match coverage with deterministic cases and independent finite oracles."""

from datetime import UTC, datetime
from ipaddress import IPv4Address
from itertools import product
from uuid import UUID

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from firewall_compliance.analysis.firewall_assurance import analyze_firewall
from firewall_compliance.analysis.policy_coverage import (
    CoverageBudget,
    CoverageLimitError,
    PacketBox,
    subtract_boxes,
)
from firewall_compliance.checks.policy_quality.rules import (
    PartialShadowedRulesCheck,
    PolicyCheckContext,
    UnionShadowedRulesCheck,
)
from firewall_compliance.domain.configuration import Configuration, Device, Rule
from firewall_compliance.domain.enums import (
    DataStatus,
    EndpointKind,
    ParseIssueLevel,
    Protocol,
    RuleAction,
    SourceDocumentKind,
)
from firewall_compliance.domain.network import Endpoint, IpRange, PortRange, Service
from firewall_compliance.domain.parse_result import ParseCoverage, ParseIssue, ParseResult
from firewall_compliance.domain.policy_matching import scope_key
from firewall_compliance.domain.revision import DeviceRevision, RevisionSource
from firewall_compliance.domain.source import SourceLocation

NOW = datetime(2026, 10, 27, tzinfo=UTC)
CONFIG_ID = UUID("11111111-1111-1111-1111-111111111111")


def rule(
    identifier, sequence, *, src=(0, 3), dst=(0, 3), ports=(1, 8), protocol=Protocol.TCP, **changes
):
    def endpoint(side, interval):
        return Endpoint(
            endpoint_id=identifier + side,
            name=side,
            kind=EndpointKind.RANGE,
            ip_ranges=(
                IpRange(start=str(IPv4Address(interval[0])), end=str(IPv4Address(interval[1]))),
            ),
        )

    return Rule(
        rule_id=identifier,
        configuration_id=CONFIG_ID,
        name=identifier,
        sequence=sequence,
        action=changes.pop("action", RuleAction.ALLOW),
        enabled=changes.pop("enabled", True),
        sources=changes.pop("sources", (endpoint("src", src),)),
        destinations=changes.pop("destinations", (endpoint("dst", dst),)),
        services=changes.pop(
            "services",
            (
                Service(
                    service_id=identifier + ":service",
                    name="service",
                    protocol=protocol,
                    port_ranges=(PortRange(start=ports[0], end=ports[1]),)
                    if protocol in {Protocol.TCP, Protocol.UDP}
                    else (),
                ),
            ),
        ),
        policy_id=changes.pop("policy_id", "policy"),
        policy_direction=changes.pop("policy_direction", "in"),
        policy_semantics="first_match",
        match_status=changes.pop("match_status", DataStatus.KNOWN),
        zone_status=DataStatus.KNOWN,
        logging_status=DataStatus.KNOWN,
        logging_enabled=True,
        source_location=changes.pop(
            "source_location",
            SourceLocation(source_name="synthetic.cfg", object_path=f"/rules/{identifier}"),
        ),
        **changes,
    )


def revision(*rules, warnings=(), errors=(), coverage=None):
    configuration = Configuration(
        configuration_id=CONFIG_ID,
        source_name="synthetic.cfg",
        device_id="synthetic",
        vendor="synthetic",
        platform="synthetic",
        parser_version="1.0.0",
        content_sha256="a" * 64,
        captured_at=NOW,
        imported_at=NOW,
    )
    return DeviceRevision(
        revision_id=UUID("22222222-2222-2222-2222-222222222222"),
        device=Device(device_id="synthetic", vendor="synthetic", platform="synthetic"),
        parse_result=ParseResult(
            configuration=configuration,
            rules=rules,
            source_map={item.rule_id: item.source_location for item in rules},
            warnings=warnings,
            errors=errors,
            coverage=coverage
            or ParseCoverage(
                discovered_constructs=len(rules),
                recognized_constructs=len(rules),
                unsupported_constructs=0,
            ),
        ),
        sources=(
            RevisionSource(
                source_name="synthetic.cfg",
                content_sha256="a" * 64,
                kind=SourceDocumentKind.CONFIGURATION,
                captured_at=NOW,
            ),
        ),
        application_version="0.3.0",
        imported_at=NOW,
    )


def evaluate(check, *rules, **fields):
    return check.evaluate(PolicyCheckContext(revision(*rules, **fields), NOW))


def target_findings(result, target="target"):
    return [
        finding for finding in result.findings if finding.evidence.facts["target_rule_id"] == target
    ]


def test_partial_shadow_has_nonempty_residual_and_full_source_evidence():
    result = evaluate(
        PartialShadowedRulesCheck(),
        rule("before", 1, ports=(1, 4), action=RuleAction.DROP),
        rule("target", 2),
    )
    finding = target_findings(result)[0]
    assert result.status.value == "complete"
    assert finding.affected_rule_ids == ("before", "target")
    assert len(finding.evidence.source_locations) == 2
    assert finding.evidence.facts["covered_witness"]["destination_port"] == 1
    assert finding.evidence.facts["residual_witness"]["destination_port"] == 5
    assert finding.revision_id == revision().revision_id


def test_adjacent_port_union_is_full_without_expanding_other_axes():
    rules = (
        rule("low", 1, ports=(1, 4)),
        rule("high", 2, ports=(5, 8), action=RuleAction.DENY),
        rule("target", 3),
    )
    finding = target_findings(evaluate(UnionShadowedRulesCheck(), *rules))[0]
    assert finding.evidence.facts["covering_rule_ids"] == ["low", "high"]
    assert finding.evidence.facts["residual_witness"] is None
    assert not target_findings(evaluate(PartialShadowedRulesCheck(), *rules))


def test_union_preserves_cartesian_correlation_in_diagonal_rules():
    rules = (
        rule("left", 1, src=(0, 1), dst=(0, 1)),
        rule("right", 2, src=(2, 3), dst=(2, 3)),
        rule("target", 3),
    )
    assert not target_findings(evaluate(UnionShadowedRulesCheck(), *rules))
    assert target_findings(evaluate(PartialShadowedRulesCheck(), *rules))


def test_disabled_and_already_covered_predecessors_do_not_become_contributors():
    rules = (
        rule("disabled", 1, enabled=False),
        rule("low", 2, ports=(1, 4)),
        rule("redundant", 3, ports=(1, 4)),
        rule("high", 4, ports=(5, 8)),
        rule("target", 5),
    )
    finding = target_findings(evaluate(UnionShadowedRulesCheck(), *rules))[0]
    assert finding.evidence.facts["covering_rule_ids"] == ["low", "high"]


def test_single_rule_full_shadow_is_left_to_existing_check():
    rules = (rule("all", 1), rule("target", 2))
    assert not target_findings(evaluate(UnionShadowedRulesCheck(), *rules))
    assert not target_findings(evaluate(PartialShadowedRulesCheck(), *rules))


@pytest.mark.parametrize("direction", ["in", "out"])
def test_one_direction_only_partially_covers_global(direction):
    result = evaluate(
        PartialShadowedRulesCheck(),
        rule("one", 1, policy_direction=direction),
        rule("target", 2, policy_direction="global"),
    )
    finding = target_findings(result)[0]
    assert finding.evidence.facts["residual_witness"]["direction"] != direction


def test_in_and_out_union_covers_global_but_distinct_policies_do_not_mix():
    rules = (
        rule("in", 1),
        rule("out", 2, policy_direction="out"),
        rule("target", 3, policy_direction="global"),
    )
    assert target_findings(evaluate(UnionShadowedRulesCheck(), *rules))
    changed = (rules[0], rule("out", 2, policy_direction="out", policy_id="other"), rules[2])
    assert not target_findings(evaluate(UnionShadowedRulesCheck(), *changed))


def test_equal_sequences_are_safe_only_for_disjoint_directions():
    rules = (
        rule("in", 1),
        rule("out", 1, policy_direction="out"),
        rule("target", 2, policy_direction="global"),
    )
    result = evaluate(UnionShadowedRulesCheck(), *rules)
    assert target_findings(result) and result.status.value == "complete"
    assert (
        target_findings(evaluate(UnionShadowedRulesCheck(), rules[1], rules[0], rules[2]))[
            0
        ].finding_id
        == target_findings(result)[0].finding_id
    )
    ambiguous = evaluate(
        UnionShadowedRulesCheck(), rules[0], rule("global", 1, policy_direction="global"), rules[2]
    )
    assert not ambiguous.findings and "AMBIGUOUS_ORDER" in {
        item.code for item in ambiguous.limitations
    }


def test_tcp_and_udp_do_not_cover_any_protocol():
    result = evaluate(
        UnionShadowedRulesCheck(),
        rule("tcp", 1),
        rule("udp", 2, protocol=Protocol.UDP),
        rule("target", 3, protocol=Protocol.IP),
    )
    assert not target_findings(result)
    partial = evaluate(
        PartialShadowedRulesCheck(), rule("tcp", 1), rule("target", 2, protocol=Protocol.IP)
    )
    assert target_findings(partial)[0].evidence.facts["residual_witness"]["protocol_number"] != 6


def test_ipv4_and_ipv6_are_distinct_and_dual_stack_needs_both():
    v4 = Endpoint(endpoint_id="v4", name="v4", kind=EndpointKind.SUBNET, cidrs=("0.0.0.0/0",))
    v6 = Endpoint(endpoint_id="v6", name="v6", kind=EndpointKind.SUBNET, cidrs=("::/0",))
    rules = (
        rule("v4", 1, sources=(v4,), destinations=(v4,)),
        rule("v6", 2, sources=(v6,), destinations=(v6,)),
        rule("target", 3, sources=(v4, v6), destinations=(v4, v6)),
    )
    assert target_findings(evaluate(UnionShadowedRulesCheck(), *rules))
    assert target_findings(evaluate(PartialShadowedRulesCheck(), rules[0], rules[2]))


def test_unknown_predecessor_cannot_prove_partial_but_known_union_still_proves_full():
    unknown = rule("unknown", 1, match_status=DataStatus.UNKNOWN)
    low = rule("low", 2, ports=(1, 4))
    high = rule("high", 3, ports=(5, 8))
    target = rule("target", 4)
    partial = evaluate(PartialShadowedRulesCheck(), unknown, low, target)
    assert not target_findings(partial)
    assert "UNKNOWN_EARLIER_MATCH" in {item.code for item in partial.limitations}
    full = evaluate(UnionShadowedRulesCheck(), unknown, low, high, target)
    finding = target_findings(full)[0]
    assert not finding.evidence.facts["first_match_owners_known"]
    assert finding.evidence.facts["uncertain_predecessor_ids"] == ["unknown"]


def test_unknown_disjoint_direction_does_not_suppress_known_partial_proof():
    result = evaluate(
        PartialShadowedRulesCheck(),
        rule("unknown", 1, match_status=DataStatus.UNKNOWN, policy_direction="out"),
        rule("low", 2, ports=(1, 4)),
        rule("target", 3),
    )
    assert target_findings(result)


def test_localized_diagnostic_blocks_only_its_predicate_and_preserves_independent_full_proof():
    unknown = rule("unknown", 1)
    warning = ParseIssue(
        code="UNSUPPORTED",
        level=ParseIssueLevel.WARNING,
        message="synthetic unsupported",
        source_location=unknown.source_location,
    )
    result = evaluate(
        UnionShadowedRulesCheck(),
        unknown,
        rule("low", 2, ports=(1, 4)),
        rule("high", 3, ports=(5, 8)),
        rule("target", 4),
        warnings=(warning,),
    )
    assert target_findings(result) and result.status.value == "partial"


@pytest.mark.parametrize(
    "case", ["global-warning", "parse-error", "unknown-scope", "order", "coverage"]
)
def test_unproven_scope_order_or_source_cannot_claim_full_coverage(case):
    rules = [rule("low", 1, ports=(1, 4)), rule("high", 2, ports=(5, 8)), rule("target", 3)]
    fields = {}
    issue = ParseIssue(
        code="UNSUPPORTED", level=ParseIssueLevel.WARNING, message="synthetic unsupported"
    )
    if case == "global-warning":
        fields["warnings"] = (issue,)
    elif case == "parse-error":
        fields["errors"] = (issue,)
    elif case == "unknown-scope":
        rules[0] = rule("low", 1, ports=(1, 4), policy_direction=None)
    elif case == "order":
        rules[1] = rule("high", 1, ports=(5, 8))
    else:
        fields["coverage"] = ParseCoverage(
            discovered_constructs=4, recognized_constructs=3, unsupported_constructs=0
        )
    result = evaluate(UnionShadowedRulesCheck(), *rules, **fields)
    assert not result.findings and result.status.value == "partial"
    assert "CHECK_NOT_EXECUTED" in {limit.code for limit in result.limitations}


@pytest.mark.parametrize("options", [{"max_fragments": 1}, {"max_operations": 1}])
def test_complexity_limit_never_looks_like_empty_residual_or_safe_policy(options):
    result = evaluate(
        UnionShadowedRulesCheck(**options),
        rule("low", 1, ports=(1, 4)),
        rule("high", 2, ports=(5, 8)),
        rule("target", 3, protocol=Protocol.IP),
    )
    assert not result.findings and result.status.value == "partial"
    assert "COVERAGE_LIMIT" in {item.code for item in result.limitations}


def test_optional_scope_restriction_cannot_bypass_unknown_source_and_defaults_work():
    rules = (rule("low", 1, ports=(1, 4)), rule("high", 2, ports=(5, 8)), rule("target", 3))
    assert target_findings(evaluate(UnionShadowedRulesCheck(), *rules))
    assert not evaluate(UnionShadowedRulesCheck(complete_scopes=frozenset()), *rules).findings
    scopes = frozenset({scope_key(rules[0])})
    assert target_findings(evaluate(UnionShadowedRulesCheck(complete_scopes=scopes), *rules))


def test_existing_default_catalog_is_unchanged_and_new_checks_are_reproducible():
    source = revision(
        rule("low", 1, ports=(1, 4)), rule("high", 2, ports=(5, 8)), rule("target", 3)
    )
    original = source.model_dump(mode="json")
    assert len(analyze_firewall(source).checks) == 7
    checks = (PartialShadowedRulesCheck(), UnionShadowedRulesCheck())
    one = analyze_firewall(source, checks=checks)
    two = analyze_firewall(source, checks=checks)
    assert one.model_dump(mode="json") == two.model_dump(mode="json")
    assert source.model_dump(mode="json") == original


@st.composite
def boxes(draw):
    axes = []
    for _ in range(5):
        start = draw(st.integers(0, 3))
        end = draw(st.integers(start, 3))
        axes.append((start, end))
    return PacketBox(draw(st.sampled_from([4, 6])), tuple(axes))


def points(box):
    return {
        (box.family, *point)
        for point in product(*(range(start, end + 1) for start, end in box.axes))
    }


@given(boxes(), boxes())
@settings(max_examples=100, deadline=None, database=None)
def test_subtraction_matches_independent_finite_set_oracle(left, right):
    fragments = left.subtract(right)
    expected = points(left) - points(right)
    assert set().union(*(points(box) for box in fragments)) == expected
    assert sum(len(points(box)) for box in fragments) == len(expected)


@given(boxes(), st.lists(boxes(), max_size=5))
@settings(max_examples=80, deadline=None, database=None)
def test_union_subtraction_preserves_exact_covered_and_residual_sets(target, earlier):
    remaining, covered = subtract_boxes((target,), tuple(earlier), CoverageBudget())
    union = set().union(*(points(box) for box in earlier))
    assert set().union(*(points(box) for box in remaining)) == points(target) - union
    assert set().union(*(points(box) for box in covered)) == points(target) & union
    assert sum(len(points(box)) for box in covered) == len(points(target) & union)


def test_budget_exception_is_explicit():
    with pytest.raises(CoverageLimitError):
        subtract_boxes(
            (PacketBox(4, ((0, 3),) * 5),),
            (PacketBox(4, ((1, 2),) * 5),),
            CoverageBudget(max_fragments=1),
        )


def test_object_id_source_mapping_supports_evidence_and_localized_diagnostics():
    low = rule(
        "low",
        1,
        ports=(1, 4),
        source_location=SourceLocation(source_name="synthetic.cfg", object_id="object-low"),
    )
    high, target = rule("high", 2, ports=(5, 8)), rule("target", 3)
    result = evaluate(UnionShadowedRulesCheck(), low, high, target)
    assert target_findings(result)[0].evidence.source_locations[0].object_id == "object-low"
    warning = ParseIssue(
        code="UNSUPPORTED",
        level=ParseIssueLevel.WARNING,
        message="synthetic",
        source_location=low.source_location,
    )
    limited = evaluate(UnionShadowedRulesCheck(), low, high, target, warnings=(warning,))
    assert not target_findings(limited)
    assert "UNKNOWN_EARLIER_MATCH" in {item.code for item in limited.limitations}


def test_preanalysis_limit_explicitly_marks_check_not_executed():
    result = evaluate(UnionShadowedRulesCheck(max_operations=1), rule("low", 1), rule("target", 2))
    assert "CHECK_NOT_EXECUTED" in {item.code for item in result.limitations}


def test_ipv6_icmp_is_unknown_instead_of_guessing_icmpv6_number():
    v6 = Endpoint(endpoint_id="v6", name="v6", kind=EndpointKind.SUBNET, cidrs=("::/0",))
    result = evaluate(
        UnionShadowedRulesCheck(),
        rule("first", 1, sources=(v6,), destinations=(v6,), protocol=Protocol.ICMP),
        rule("target", 2, sources=(v6,), destinations=(v6,), protocol=Protocol.ICMP),
    )
    assert not result.findings
    assert "UNKNOWN_MATCH" in {item.code for item in result.limitations}


def test_one_localized_warning_cannot_explain_extra_missing_constructs():
    later = rule("later", 3)
    warning = ParseIssue(
        code="UNSUPPORTED",
        level=ParseIssueLevel.WARNING,
        message="synthetic",
        source_location=later.source_location,
    )
    result = evaluate(
        PartialShadowedRulesCheck(),
        rule("low", 1, ports=(1, 4)),
        rule("target", 2),
        later,
        warnings=(warning,),
        coverage=ParseCoverage(
            discovered_constructs=5, recognized_constructs=3, unsupported_constructs=0
        ),
    )
    assert not result.findings
    assert "CHECK_NOT_EXECUTED" in {item.code for item in result.limitations}


@given(
    st.lists(
        st.tuples(
            st.tuples(st.integers(0, 3), st.integers(0, 3)),
            st.tuples(st.integers(0, 3), st.integers(0, 3)),
            st.tuples(st.integers(1, 4), st.integers(1, 4)),
            st.sampled_from([Protocol.TCP, Protocol.UDP]),
            st.sampled_from(["in", "out", "global"]),
            st.booleans(),
        ),
        max_size=5,
    )
)
@settings(max_examples=100, deadline=None, database=None)
def test_checks_match_independent_finite_first_match_oracle(specifications):
    target = set(product(range(4), range(4), [6], range(1, 5), [0, 1]))
    remaining = target.copy()
    contributors = []
    rules = []
    for index, (src, dst, ports, protocol, direction, enabled) in enumerate(specifications):
        src, dst, ports = tuple(sorted(src)), tuple(sorted(dst)), tuple(sorted(ports))
        rules.append(
            rule(
                str(index),
                index,
                src=src,
                dst=dst,
                ports=ports,
                protocol=protocol,
                policy_direction=direction,
                enabled=enabled,
            )
        )
        if enabled:
            predicate = set(
                product(
                    range(src[0], src[1] + 1),
                    range(dst[0], dst[1] + 1),
                    [6 if protocol == Protocol.TCP else 17],
                    range(ports[0], ports[1] + 1),
                    [0, 1] if direction == "global" else [0 if direction == "in" else 1],
                )
            )
            if remaining & predicate:
                contributors.append(str(index))
            remaining -= predicate
    rules.append(rule("target", len(rules), ports=(1, 4), policy_direction="global"))
    partial = target_findings(evaluate(PartialShadowedRulesCheck(), *rules))
    full = target_findings(evaluate(UnionShadowedRulesCheck(), *rules))
    assert bool(partial) == bool(remaining and remaining != target)
    assert bool(full) == (not remaining and len(contributors) > 1)
    if full:
        assert full[0].evidence.facts["covering_rule_ids"] == contributors
