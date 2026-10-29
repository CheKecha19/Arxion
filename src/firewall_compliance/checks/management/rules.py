"""Twelve evidence-based configuration checks; no packet reachability claims."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_network
from uuid import NAMESPACE_URL, uuid5

from firewall_compliance.checks.management.access.catalogue import CHECKS as ACCESS_CHECKS
from firewall_compliance.checks.management.logging.catalogue import CHECKS as LOGGING_CHECKS
from firewall_compliance.checks.management.snmp.catalogue import CHECKS as SNMP_CHECKS
from firewall_compliance.checks.management.time.catalogue import CHECKS as TIME_CHECKS
from firewall_compliance.checks.policy_quality.rules import PolicyCheckContext
from firewall_compliance.domain import Evidence, Finding, FindingCategory, Severity
from firewall_compliance.domain.assurance import CheckLimitation, CheckResult, CheckStatus
from firewall_compliance.domain.management import ManagementFact, ManagementKind, ManagementProfile

MANAGEMENT_CHECKS: dict[str, tuple[ManagementKind, str, str]] = {
    **ACCESS_CHECKS,
    **SNMP_CHECKS,
    **LOGGING_CHECKS,
    **TIME_CHECKS,
}


def outside_networks(value: str, approved: tuple[str, ...]) -> str | None:
    """Return a witness outside the union, preserving IPv4/IPv6 separation."""
    allowed = [ip_network(item) for item in approved]
    for item in filter(None, value.split(",")):
        target = ip_network(item)
        cursor = int(target.network_address)
        for network in sorted(allowed, key=lambda n: int(n.network_address)):
            if network.version != target.version:
                continue
            start, end = int(network.network_address), int(network.broadcast_address)
            if start > cursor:
                break
            cursor = max(cursor, end + 1)
        if cursor <= int(target.broadcast_address):
            return str(IPv4Address(cursor) if target.version == 4 else IPv6Address(cursor))
    return None


@dataclass
class ManagementCheck:
    check_id: str
    profile: ManagementProfile

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        kind, title, recommendation = MANAGEMENT_CHECKS[self.check_id]
        inventory = context.revision.parse_result.management
        limits: list[CheckLimitation] = []
        findings: list[Finding] = []

        def limit(code: str, message: str) -> None:
            limits.append(CheckLimitation(code=code, message=message))

        def result() -> CheckResult:
            return CheckResult(
                check_id=self.check_id,
                check_version="1.0.0",
                status=CheckStatus.PARTIAL if limits else CheckStatus.COMPLETE,
                findings=tuple(findings),
                limitations=tuple(limits),
            )

        if inventory is None:
            limit("MANAGEMENT_UNSUPPORTED", "Для этого адаптера нет сведений об управлении.")
            return result()
        required = {
            "MGMT-SYSLOG-MISSING": self.profile.require_syslog,
            "MGMT-NTP-MISSING": self.profile.require_ntp,
            "MGMT-BANNER": self.profile.require_banner,
            "MGMT-SNMP-WRITE": not self.profile.allow_snmp_write,
        }
        if self.check_id in required and not required[self.check_id]:
            limit("CHECK_NOT_EXECUTED", "Требование отключено профилем организации.")
            return result()
        approved: tuple[str, ...] | None = None
        allowlists = {
            "MGMT-ADMIN-SOURCES": self.profile.approved_admin_networks,
            "MGMT-SNMP-SOURCES": self.profile.approved_snmp_networks,
            "MGMT-SYSLOG-UNAPPROVED": self.profile.approved_syslog_servers,
            "MGMT-NTP-UNAPPROVED": self.profile.approved_ntp_servers,
        }
        if self.check_id in allowlists:
            approved = allowlists[self.check_id]
            if approved is None:
                limit(
                    "MANAGEMENT_PROFILE_REQUIRED",
                    "Не задан соответствующий разрешённый список организации.",
                )
        if not inventory.complete_export:
            limit(
                "MANAGEMENT_EXPORT_INCOMPLETE",
                "Полнота экспорта не подтверждена; отсутствие настроек не доказано.",
            )
        issues = [item for item in inventory.issues if item.kind == kind]
        if issues:
            limit(
                "MANAGEMENT_SYNTAX_UNSUPPORTED",
                "Есть неподдержанные или противоречивые настройки этой области; вывод отложен.",
            )
            return result()
        if self.check_id in allowlists and approved is None:
            return result()
        facts = [fact for fact in inventory.facts if fact.kind == kind]
        violations: list[tuple[ManagementFact | None, str | None]] = []
        missing_check = self.check_id in {"MGMT-SYSLOG-MISSING", "MGMT-NTP-MISSING", "MGMT-BANNER"}
        if missing_check:
            if not facts and inventory.complete_export:
                violations.append((None, None))
            elif kind == "banner":
                violations.extend((fact, None) for fact in facts if fact.value == "false")
        elif not facts:
            limit(
                "MANAGEMENT_FACTS_UNKNOWN",
                "Явные настройки не найдены; значения по умолчанию не предполагаются.",
            )
        else:
            for fact in facts:
                witness = None
                if kind in {"telnet", "http", "snmp_legacy", "snmp_write"}:
                    violated = fact.value == "true"
                elif kind == "timeout":
                    violated = (
                        int(fact.value) == 0 or int(fact.value) > self.profile.max_idle_seconds
                    )
                elif kind in {"admin_sources", "snmp_sources"}:
                    witness = outside_networks(fact.value, approved or ())
                    violated = witness is not None
                else:
                    violated = fact.value not in (approved or ())
                if violated:
                    violations.append((fact, witness))
        revision = context.revision
        for violation, witness in violations:
            scope = violation.scope if violation else "complete-export"
            findings.append(
                Finding(
                    finding_id=uuid5(
                        NAMESPACE_URL, f"{revision.revision_id}:{self.check_id}:{scope}"
                    ),
                    check_id=self.check_id,
                    category=FindingCategory.SECURITY,
                    severity=Severity.LOW if kind == "banner" else Severity.MEDIUM,
                    title=title,
                    description=(
                        "Нарушение требования к настроенной конфигурации управления. "
                        "Достижимость и работоспособность службы не проверялись."
                    ),
                    configuration_id=revision.parse_result.configuration.configuration_id,
                    revision_id=revision.revision_id,
                    device_id=revision.device.device_id,
                    evidence=Evidence(
                        summary=title,
                        source_locations=violation.source_locations
                        if violation
                        else (inventory.source_location,),
                        facts={
                            "scope": scope,
                            "configured_value": violation.value if violation else "absent",
                            "outside_address": witness,
                            "profile": self.profile.model_dump(mode="json"),
                            "complete_export": inventory.complete_export,
                            "management_parser_version": inventory.parser_version,
                        },
                    ),
                    recommendation=recommendation,
                    confidence=1.0,
                    first_seen=context.analyzed_at,
                    last_seen=context.analyzed_at,
                )
            )
        return result()


def management_checks(profile: ManagementProfile | None = None) -> tuple[ManagementCheck, ...]:
    snapshot = (profile or ManagementProfile()).as_snapshot()
    return tuple(ManagementCheck(check_id, snapshot) for check_id in MANAGEMENT_CHECKS)
