"""UntrustedAdministrativeAccessCheck implementation."""

from __future__ import annotations

from firewall_compliance.checks.access.exposure_common import _ExposureCheck
from firewall_compliance.checks.policy_quality.rules import PolicyCheckContext
from firewall_compliance.domain.assurance import CheckResult


class UntrustedAdministrativeAccessCheck(_ExposureCheck):
    """Review explicit administrative targets/services outside explicit trusted sources."""

    check_id = "FW-ADMIN-UNTRUSTED"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        return self._evaluate(context, self.profile.administrative_services, administrative=True)
