"""DangerousServicesCheck implementation."""

from __future__ import annotations

from firewall_compliance.checks.access.exposure_common import _ExposureCheck
from firewall_compliance.checks.policy_quality.rules import PolicyCheckContext
from firewall_compliance.domain.assurance import CheckResult


class DangerousServicesCheck(_ExposureCheck):
    """Review declared ALLOW intersections with an explicitly forbidden service catalogue."""

    check_id = "FW-DANGEROUS-SERVICES"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        return self._evaluate(context, self.profile.dangerous_services, administrative=False)
