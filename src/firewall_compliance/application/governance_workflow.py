"""Assess explicit governance evidence against one exact saved policy revision."""

from datetime import datetime
from uuid import uuid4

from firewall_compliance import __version__
from firewall_compliance.application.analysis_result import (
    AnalysisResult,
    PolicyComponent,
    replay_policy,
)
from firewall_compliance.domain.policy_governance import (
    PolicyGovernanceInputs,
    PolicyGovernanceProfile,
)

GOVERNANCE_CHECK_IDS = ("FW-RULE-GOVERNANCE", "FW-UNUSED-CANDIDATE")


def assess_governance(
    source: AnalysisResult,
    component_id: str,
    profile: PolicyGovernanceProfile,
    inputs: PolicyGovernanceInputs | None = None,
    *,
    assessed_at: datetime,
    max_operations: int = 100000,
) -> AnalysisResult:
    """Return a new bundle with an additional stage on the chosen exact revision.

    Original components and their decisions remain unchanged. Neither the original
    configuration path nor a collector is consulted. Omitted evidence is unknown
    and never silently reuses the previous assessment's input document.
    """
    if assessed_at.tzinfo is None or assessed_at < source.finished_at:
        raise ValueError("assessment time must be aware and cannot precede source completion")
    if any(decision.decided_at > assessed_at for decision in source.decisions):
        raise ValueError("assessment cannot precede retained decision timestamps")
    selected = next(
        (component for component in source.components if component.component_id == component_id),
        None,
    )
    if not isinstance(selected, PolicyComponent):
        raise ValueError("component must identify one saved policy analysis")
    if inputs is not None and inputs.revision_id != selected.revision.revision_id:
        raise ValueError("governance evidence must target the selected exact revision")
    options = selected.options.model_copy(
        update={
            "check_ids": GOVERNANCE_CHECK_IDS,
            "governance_profile": profile,
            "governance_inputs": inputs,
            "governance_max_operations": max_operations,
        }
    )
    report = replay_policy(
        selected.revision,
        options,
        assessed_at,
    )
    stage = PolicyComponent(
        component_id=f"governance:{uuid4()}",
        revision=selected.revision,
        options=options,
        result=report,
    )
    return source.model_copy(
        update={
            "analysis_id": uuid4(),
            "application_version": __version__,
            "finished_at": assessed_at,
            "components": (*source.components, stage),
        }
    )
