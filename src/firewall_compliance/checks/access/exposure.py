"""Compatibility exports for relocated implementations."""

from dataclasses import dataclass as dataclass
from hashlib import sha256 as sha256
from ipaddress import IPv4Address as IPv4Address
from ipaddress import IPv6Address as IPv6Address
from ipaddress import ip_network as ip_network
from typing import Any as Any
from typing import Literal as Literal
from uuid import NAMESPACE_URL as NAMESPACE_URL
from uuid import uuid5 as uuid5

from firewall_compliance.checks.access.admin_sources import (
    UntrustedAdministrativeAccessCheck as UntrustedAdministrativeAccessCheck,
)
from firewall_compliance.checks.access.dangerous_services import (
    DangerousServicesCheck as DangerousServicesCheck,
)
from firewall_compliance.checks.access.exposure_common import CHECK_VERSION as CHECK_VERSION
from firewall_compliance.checks.access.exposure_common import _addresses as _addresses
from firewall_compliance.checks.access.exposure_common import _Budget as _Budget
from firewall_compliance.checks.access.exposure_common import _BudgetExceeded as _BudgetExceeded
from firewall_compliance.checks.access.exposure_common import _charge_rule as _charge_rule
from firewall_compliance.checks.access.exposure_common import _ExposureCheck as _ExposureCheck
from firewall_compliance.checks.access.exposure_common import _intersection as _intersection
from firewall_compliance.checks.access.exposure_common import _ports as _ports
from firewall_compliance.checks.access.exposure_common import (
    _serialize_addresses as _serialize_addresses,
)
from firewall_compliance.checks.access.exposure_common import _subtract as _subtract
from firewall_compliance.checks.access.exposure_common import _witness_flow as _witness_flow
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
from firewall_compliance.domain.policy_exposure import (
    PolicyExposureProfile as PolicyExposureProfile,
)
from firewall_compliance.domain.policy_exposure import (
    PolicyServiceSelector as PolicyServiceSelector,
)
from firewall_compliance.domain.policy_matching import AddressSet as AddressSet
from firewall_compliance.domain.policy_matching import Interval as Interval
from firewall_compliance.domain.policy_matching import RuleMatch as RuleMatch
from firewall_compliance.domain.policy_matching import merge_intervals as merge_intervals
from firewall_compliance.domain.policy_matching import resolve_rule as resolve_rule
