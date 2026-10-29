"""Compatibility exports for relocated implementations."""

from dataclasses import dataclass as dataclass
from hashlib import sha256 as sha256
from ipaddress import ip_network as ip_network
from typing import Any as Any
from uuid import NAMESPACE_URL as NAMESPACE_URL
from uuid import uuid5 as uuid5

from firewall_compliance.checks.access.excessive import ExcessiveAccessCheck as ExcessiveAccessCheck
from firewall_compliance.checks.access.scope_common import CHECK_VERSION as CHECK_VERSION
from firewall_compliance.checks.access.scope_common import _address_count as _address_count
from firewall_compliance.checks.access.scope_common import _addresses_covered as _addresses_covered
from firewall_compliance.checks.access.scope_common import _approved_services as _approved_services
from firewall_compliance.checks.access.scope_common import _Budget as _Budget
from firewall_compliance.checks.access.scope_common import _intersects as _intersects
from firewall_compliance.checks.access.scope_common import _interval_count as _interval_count
from firewall_compliance.checks.access.scope_common import _LimitReached as _LimitReached
from firewall_compliance.checks.access.scope_common import _networks as _networks
from firewall_compliance.checks.access.scope_common import _parse_limitations as _parse_limitations
from firewall_compliance.checks.access.scope_common import _ProfileCheck as _ProfileCheck
from firewall_compliance.checks.access.scope_common import _result as _result
from firewall_compliance.checks.access.scope_common import _services_covered as _services_covered
from firewall_compliance.checks.attachments.bindings import (
    PolicyAttachmentCheck as PolicyAttachmentCheck,
)
from firewall_compliance.checks.policy_quality.rules import PolicyCheckContext as PolicyCheckContext
from firewall_compliance.domain.assurance import CheckLimitation as CheckLimitation
from firewall_compliance.domain.assurance import CheckResult as CheckResult
from firewall_compliance.domain.assurance import CheckStatus as CheckStatus
from firewall_compliance.domain.configuration import Rule as Rule
from firewall_compliance.domain.enums import FindingCategory as FindingCategory
from firewall_compliance.domain.enums import RuleAction as RuleAction
from firewall_compliance.domain.enums import Severity as Severity
from firewall_compliance.domain.finding import Evidence as Evidence
from firewall_compliance.domain.finding import Finding as Finding
from firewall_compliance.domain.policy_matching import AddressSet as AddressSet
from firewall_compliance.domain.policy_matching import Interval as Interval
from firewall_compliance.domain.policy_matching import RuleMatch as RuleMatch
from firewall_compliance.domain.policy_matching import intervals_cover as intervals_cover
from firewall_compliance.domain.policy_matching import merge_intervals as merge_intervals
from firewall_compliance.domain.policy_matching import resolve_rule as resolve_rule
from firewall_compliance.domain.policy_scope import PolicyScopeProfile as PolicyScopeProfile
from firewall_compliance.domain.policy_scope import RoleAccessRequirement as RoleAccessRequirement
