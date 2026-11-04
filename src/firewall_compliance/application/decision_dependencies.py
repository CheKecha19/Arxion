"""Conservative decision retention for explicit declared-policy dependencies.

Fingerprints identify recorded inputs, not proof of a device's effective access.
They cannot replace source/identity evidence or validate an arbitrary caller's
assertion that the supplied dependency scope is complete.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Literal
from uuid import UUID

from pydantic import Field

from firewall_compliance.domain.enums import DataStatus, EndpointKind
from firewall_compliance.domain.policy_matching import resolve_rule
from firewall_compliance.domain.policy_revision_diff import PolicyDiffModel
from firewall_compliance.domain.revision import DeviceRevision


class DecisionDependencies(PolicyDiffModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    revision_id: UUID
    scope_reference: str = Field(min_length=1)
    rule_ids: tuple[str, ...]
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    parser_version: str
    profile_fingerprint: str | None = None
    matrix_fingerprint: str | None = None
    check_version: str | None = None
    identity_reference: str | None = None
    complete: bool = False
    reasons: tuple[str, ...] = ()


class DependencyComparison(PolicyDiffModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    state: Literal["retained", "review_required"]
    before_fingerprint: str
    after_fingerprint: str
    reasons: tuple[str, ...]


def capture_decision_dependencies(
    revision: DeviceRevision,
    rule_ids: tuple[str, ...],
    *,
    scope_reference: str,
    profile_fingerprint: str | None = None,
    matrix_fingerprint: str | None = None,
    check_version: str | None = None,
    identity_reference: str | None = None,
    dependencies_complete: bool = False,
) -> DecisionDependencies:
    """Capture resolved conditions, referenced objects and the full related order.

    dependencies_complete is an explicit statement by the finding's dependency
    producer; default False prevents a legacy finding from silently inheriting
    a decision. identity_reference must describe proven stable rule/policy
    identity. None matrix means no matrix was involved; a matrix-dependent
    producer must supply its captured fingerprint. Profile/check identity is
    required for retention. This function does not discover user/AD membership.
    """
    if not isinstance(scope_reference, str) or not scope_reference.strip():
        raise ValueError("An explicit dependency scope is required")
    if isinstance(rule_ids, (str, bytes)) or not rule_ids:
        raise ValueError("Decision dependencies require explicit rule IDs")
    if any(not isinstance(value, str) or not value.strip() for value in rule_ids):
        raise ValueError("Rule IDs must be nonempty strings")
    if type(dependencies_complete) is not bool:
        raise TypeError("dependencies_complete must be boolean")
    for value in (profile_fingerprint, matrix_fingerprint, check_version, identity_reference):
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError("Dependency references must be nonempty strings or None")
    selected_ids = tuple(sorted(set(rule_ids)))
    rules = revision.parse_result.rules
    selected = tuple(rule for rule in rules if rule.rule_id in selected_ids)
    reasons: list[str] = []
    if not dependencies_complete:
        reasons.append("dependency_scope_unconfirmed")
    if len(selected) != len(selected_ids) or {rule.rule_id for rule in selected} != set(selected_ids):
        reasons.append("referenced_rule_missing_or_ambiguous")
    if not identity_reference:
        reasons.append("stable_identity_unconfirmed")
    if not profile_fingerprint:
        reasons.append("profile_unknown")
    if not check_version:
        reasons.append("check_version_unknown")
    if revision.parse_result.errors or revision.parse_result.unsupported_constructs:
        reasons.append("normalization_incomplete")
    policies = {
        (rule.policy_id, rule.policy_direction, rule.policy_semantics) for rule in selected
    }
    if any(
        not policy_id or not direction or not semantics
        for policy_id, direction, semantics in policies
    ):
        reasons.append("policy_identity_or_order_unknown")
    related = tuple(
        rule
        for rule in rules
        if (rule.policy_id, rule.policy_direction, rule.policy_semantics) in policies
    )
    positions = [
        (rule.policy_id, rule.policy_direction, rule.policy_semantics, rule.sequence)
        for rule in related
    ]
    if len(set(positions)) != len(positions):
        reasons.append("policy_order_ambiguous")
    if any(
        resolve_rule(rule) is None
        or rule.match_status != DataStatus.KNOWN
        or rule.source_status != DataStatus.KNOWN
        or rule.destination_status != DataStatus.KNOWN
        or rule.service_status != DataStatus.KNOWN
        or any(
            value.resolution_status != DataStatus.KNOWN
            for value in (*rule.sources, *rule.destinations, *rule.services)
        )
        for rule in related
    ):
        reasons.append("resolved_conditions_incomplete")
    endpoints = {
        value.endpoint_id for rule in related for value in (*rule.sources, *rule.destinations)
    }
    if any(
        value.kind == EndpointKind.GROUP
        for rule in related for value in (*rule.sources, *rule.destinations)
    ):
        reasons.append("group_membership_not_captured")
    services = {value.service_id for rule in related for value in rule.services}
    parser_version = revision.parse_result.configuration.parser_version
    payload = {
        "schema_version": "1.0.0",
        "scope": scope_reference,
        "device": revision.device.model_dump(
            mode="json", include={"device_id", "vendor", "platform", "context"}
        ),
        "selected_rule_ids": selected_ids,
        "rules": [
            rule.model_dump(mode="json", exclude={"configuration_id", "source_location"})
            for rule in related
        ],
        "endpoints": [
            value.model_dump(mode="json")
            for value in revision.parse_result.endpoints
            if value.endpoint_id in endpoints
        ],
        "services": [
            value.model_dump(mode="json")
            for value in revision.parse_result.services
            if value.service_id in services
        ],
        "parser_version": parser_version,
        "profile": profile_fingerprint,
        "matrix": matrix_fingerprint,
        "check_version": check_version,
        "identity_reference": identity_reference,
    }
    canonical = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    )
    fingerprint = sha256(canonical.encode()).hexdigest()
    return DecisionDependencies(
        revision_id=revision.revision_id,
        scope_reference=scope_reference,
        rule_ids=selected_ids,
        fingerprint=fingerprint,
        parser_version=parser_version,
        profile_fingerprint=profile_fingerprint,
        matrix_fingerprint=matrix_fingerprint,
        check_version=check_version,
        identity_reference=identity_reference,
        complete=not reasons,
        reasons=tuple(reasons),
    )


def compare_decision_dependencies(
    before: DecisionDependencies, after: DecisionDependencies
) -> DependencyComparison:
    """Retain only a complete, proven, identical dependency scope."""
    before = DecisionDependencies.model_validate(before)
    after = DecisionDependencies.model_validate(after)
    reasons = list(dict.fromkeys((*before.reasons, *after.reasons)))
    if not before.complete or not after.complete:
        reasons.append("dependency_scope_incomplete")
    if before.scope_reference != after.scope_reference:
        reasons.append("scope_changed")
    if before.parser_version != after.parser_version:
        reasons.append("normalization_changed")
    if before.profile_fingerprint != after.profile_fingerprint:
        reasons.append("profile_changed")
    if before.matrix_fingerprint != after.matrix_fingerprint:
        reasons.append("matrix_changed")
    if before.check_version != after.check_version:
        reasons.append("check_version_changed")
    if before.identity_reference != after.identity_reference:
        reasons.append("identity_evidence_changed")
    if before.fingerprint != after.fingerprint:
        reasons.append("declared_dependencies_changed")
    return DependencyComparison(
        state="review_required" if reasons else "retained",
        before_fingerprint=before.fingerprint,
        after_fingerprint=after.fingerprint,
        reasons=tuple(dict.fromkeys(reasons)),
    )
