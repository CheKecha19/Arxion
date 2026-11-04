"""Desktop-ready adapter for declared-policy comparisons, never reachability."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from firewall_compliance.analysis.policy_revision_diff import compare_policy_declarations
from firewall_compliance.domain.policy_revision_diff import (
    PolicyCollectionEvidence,
    PolicyDiffComputation,
    PolicyDiffInput,
    PolicyDiffLimitation,
    PolicyDiffModel,
    PolicyDiffOptions,
)
from firewall_compliance.domain.revision import DeviceRevision


class PolicyComparison(PolicyDiffModel):
    """Versioned envelope retaining the existing four independent diff channels."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    mode: Literal["declared_rules"] = "declared_rules"
    before_revision_id: UUID
    after_revision_id: UUID
    computation: PolicyDiffComputation


def compare_policy_revisions(
    before: DeviceRevision,
    after: DeviceRevision,
    *,
    scope_reference: str,
    before_collections: tuple[PolicyCollectionEvidence, ...] = (),
    after_collections: tuple[PolicyCollectionEvidence, ...] = (),
    options: PolicyDiffOptions | None = None,
) -> PolicyComparison:
    """Compare snapshots through the existing bounded declaration engine.

    scope_reference must come from the caller's captured device/integration
    context. Matching rule IDs alone do not prove stable correspondence. Supply
    existing typed collection/identity evidence where available; absent evidence
    deliberately leaves additions, removals and identity uncertain. Parser
    changes remain normalization-dependent. No collection evidence is fabricated
    from successful parsing or a configuration-complete checkbox.
    """
    if not isinstance(scope_reference, str) or not scope_reference.strip():
        raise ValueError("An explicit comparison scope is required")
    first = PolicyDiffInput(
        revision=before, scope_reference=scope_reference, collections=before_collections
    )
    second = PolicyDiffInput(
        revision=after, scope_reference=scope_reference, collections=after_collections
    )
    old_rules = {rule.rule_id: rule for rule in before.parse_result.rules}
    new_rules = {rule.rule_id: rule for rule in after.parse_result.rules}
    pairs = [(key, key) for key in old_rules.keys() & new_rules.keys()]
    if options is not None:
        pairs.extend(
            (value.before_id, value.after_id)
            for value in options.correspondences
            if value.family == "rule"
        )
    uncertain = set()
    for old_id, new_id in pairs:
        old, new = old_rules.get(old_id), new_rules.get(new_id)
        old_policy = (
            (old.policy_id, old.policy_direction, old.policy_semantics) if old else ()
        )
        new_policy = (
            (new.policy_id, new.policy_direction, new.policy_semantics) if new else ()
        )
        if not old_policy or not all(old_policy) or old_policy != new_policy:
            uncertain.update((old_id, new_id))
    if uncertain:
        # Stable vendor IDs cannot bridge changed or unknown policy scopes.
        # Disable the whole family's identity shortcut conservatively, retaining
        # known equivalent conditions and independent endpoint/service evidence.
        for source in (first, second):
            collections = tuple(
                value.model_copy(update={"identity_namespace": None, "identity_reference": None})
                if value.family == "rule" else value
                for value in source.collections
            )
            if source is first:
                first = source.model_copy(update={"collections": collections})
            else:
                second = source.model_copy(update={"collections": collections})
        if options is not None:
            options = options.model_copy(
                update={
                    "correspondences": tuple(
                        value for value in options.correspondences if value.family != "rule"
                    )
                }
            )
    computation = compare_policy_declarations(first, second, options)
    if uncertain:
        limitation = PolicyDiffLimitation(
            code="RULE_POLICY_IDENTITY_UNKNOWN",
            message=(
                "Область политики изменилась или неизвестна; "
                "идентичность правил не доказана."
            ),
            family="rule",
            entity_ids=tuple(sorted(uncertain)),
        )
        computation = computation.model_copy(
            update={"limitations": (*computation.limitations, limitation)}
        )
    return PolicyComparison(
        before_revision_id=before.revision_id,
        after_revision_id=after.revision_id,
        computation=computation,
    )
