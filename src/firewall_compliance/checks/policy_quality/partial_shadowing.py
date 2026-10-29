"""Policy check implementation."""

from dataclasses import dataclass
from typing import Literal

from firewall_compliance.analysis.policy_matching import ScopeKey
from firewall_compliance.checks.common.policy import PolicyCheckContext, _evaluate_coverage
from firewall_compliance.domain.assurance import CheckResult


@dataclass(frozen=True)
class PartialShadowedRulesCheck:
    """Exact nonempty covered and residual predicates; opt-in, outside default seven."""

    check_id = "FW-PARTIAL-SHADOWED"
    complete_scopes: frozenset[ScopeKey] | None = None
    max_fragments: int = 4096
    max_operations: int = 200000
    evidence_version: Literal["1.0.0", "1.1.0"] = "1.1.0"

    def __post_init__(self) -> None:
        if self.evidence_version not in {"1.0.0", "1.1.0"}:
            raise ValueError("Unsupported coverage evidence version.")

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        return _evaluate_coverage(
            self.check_id,
            context,
            full=False,
            complete_scopes=self.complete_scopes,
            max_fragments=self.max_fragments,
            max_operations=self.max_operations,
            evidence_version=self.evidence_version,
        )
