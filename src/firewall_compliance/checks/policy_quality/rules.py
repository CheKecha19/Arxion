"""Compatibility exports for policy checks."""

from dataclasses import dataclass as dataclass
from datetime import datetime as datetime
from typing import Any as Any
from typing import Literal as Literal
from uuid import NAMESPACE_URL as NAMESPACE_URL
from uuid import uuid5 as uuid5

from firewall_compliance.analysis.policy_coverage import CoverageBudget as CoverageBudget
from firewall_compliance.analysis.policy_coverage import CoverageLimitError as CoverageLimitError
from firewall_compliance.analysis.policy_coverage import PacketBox as PacketBox
from firewall_compliance.analysis.policy_coverage import (
    UnsupportedCoverageError as UnsupportedCoverageError,
)
from firewall_compliance.analysis.policy_coverage import packet_boxes as packet_boxes
from firewall_compliance.analysis.policy_coverage import subtract_boxes as subtract_boxes
from firewall_compliance.analysis.policy_matching import RuleMatch as RuleMatch
from firewall_compliance.analysis.policy_matching import ScopeKey as ScopeKey
from firewall_compliance.analysis.policy_matching import resolve_rule as resolve_rule
from firewall_compliance.analysis.policy_matching import scope_key as scope_key
from firewall_compliance.checks.access.any_any import AnyAnyCheck as AnyAnyCheck
from firewall_compliance.checks.common.policy import ARUBA_CHECK_VERSION as ARUBA_CHECK_VERSION
from firewall_compliance.checks.common.policy import (
    ARUBA_METADATA_WARNINGS as ARUBA_METADATA_WARNINGS,
)
from firewall_compliance.checks.common.policy import CHECK_VERSION as CHECK_VERSION
from firewall_compliance.checks.common.policy import (
    COVERAGE_CHECK_VERSION as COVERAGE_CHECK_VERSION,
)
from firewall_compliance.checks.common.policy import (
    PLATFORM_SCOPE_WARNINGS as PLATFORM_SCOPE_WARNINGS,
)
from firewall_compliance.checks.common.policy import TERMINAL_ACTIONS as TERMINAL_ACTIONS
from firewall_compliance.checks.common.policy import PolicyCheck as PolicyCheck
from firewall_compliance.checks.common.policy import PolicyCheckContext as PolicyCheckContext
from firewall_compliance.checks.common.policy import _aruba_blocked_acls as _aruba_blocked_acls
from firewall_compliance.checks.common.policy import _coverage_finding as _coverage_finding
from firewall_compliance.checks.common.policy import _coverage_groups as _coverage_groups
from firewall_compliance.checks.common.policy import _evaluate_coverage as _evaluate_coverage
from firewall_compliance.checks.common.policy import _finding as _finding
from firewall_compliance.checks.common.policy import _limitation as _limitation
from firewall_compliance.checks.common.policy import _pair_groups as _pair_groups
from firewall_compliance.checks.common.policy import _result as _result
from firewall_compliance.checks.common.policy import _same_effect as _same_effect
from firewall_compliance.checks.common.policy import check_version as check_version
from firewall_compliance.checks.policy_quality.duplicates import (
    DuplicateRulesCheck as DuplicateRulesCheck,
)
from firewall_compliance.checks.policy_quality.merge import (
    MergeCandidateCheck as MergeCandidateCheck,
)
from firewall_compliance.checks.policy_quality.partial_shadowing import (
    PartialShadowedRulesCheck as PartialShadowedRulesCheck,
)
from firewall_compliance.checks.policy_quality.shadowing import (
    ShadowedRulesCheck as ShadowedRulesCheck,
)
from firewall_compliance.checks.policy_quality.union_shadowing import (
    UnionShadowedRulesCheck as UnionShadowedRulesCheck,
)
from firewall_compliance.checks.rule_hygiene.comments import CommentsCheck as CommentsCheck
from firewall_compliance.checks.rule_hygiene.disabled import (
    DisabledRulesCheck as DisabledRulesCheck,
)
from firewall_compliance.checks.rule_hygiene.logging import LoggingCheck as LoggingCheck
from firewall_compliance.domain import DataStatus as DataStatus
from firewall_compliance.domain import DeviceRevision as DeviceRevision
from firewall_compliance.domain import Evidence as Evidence
from firewall_compliance.domain import Finding as Finding
from firewall_compliance.domain import FindingCategory as FindingCategory
from firewall_compliance.domain import Rule as Rule
from firewall_compliance.domain import RuleAction as RuleAction
from firewall_compliance.domain import Severity as Severity
from firewall_compliance.domain.assurance import CheckLimitation as CheckLimitation
from firewall_compliance.domain.assurance import CheckResult as CheckResult
from firewall_compliance.domain.assurance import CheckStatus as CheckStatus
