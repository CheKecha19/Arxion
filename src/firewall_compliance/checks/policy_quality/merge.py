"""Policy check implementation."""

from firewall_compliance.analysis.policy_matching import RuleMatch, resolve_rule
from firewall_compliance.checks.common.policy import (
    PolicyCheckContext,
    _finding,
    _limitation,
    _pair_groups,
    _result,
    _same_effect,
)
from firewall_compliance.domain import DataStatus, Finding, Severity
from firewall_compliance.domain.assurance import CheckResult


class MergeCandidateCheck:
    """Соседние правила с одинаковыми эффектами и одной различающейся осью."""

    check_id = "FW-MERGE-CANDIDATE"

    def evaluate(self, context: PolicyCheckContext) -> CheckResult:
        groups, limitations = _pair_groups(context)
        findings: list[Finding] = []
        for rules in groups:
            for index, (before, after) in enumerate(zip(rules, rules[1:], strict=False)):
                left, right = resolve_rule(before), resolve_rule(after)
                assert isinstance(left, RuleMatch) and isinstance(right, RuleMatch)
                earlier_matches = [resolve_rule(rule) for rule in rules[:index]]
                if any(
                    match is not None and (match.covers(left) or match.covers(right))
                    for match in earlier_matches
                ):
                    continue
                if before.action == after.action and (
                    before.logging_status != DataStatus.KNOWN
                    or after.logging_status != DataStatus.KNOWN
                    or before.logging_enabled is None
                    or after.logging_enabled is None
                ):
                    limitations.append(
                        _limitation(
                            "UNKNOWN_MERGE_METADATA",
                            "Нет достоверного логирования для объединения.",
                            before,
                            after,
                        )
                    )
                if not _same_effect(before, after):
                    continue
                if before.description_status not in {
                    DataStatus.KNOWN,
                    DataStatus.ABSENT,
                } or after.description_status not in {DataStatus.KNOWN, DataStatus.ABSENT}:
                    limitations.append(
                        _limitation(
                            "UNKNOWN_MERGE_METADATA",
                            "Нет достоверных описаний для оценки объединения.",
                            before,
                            after,
                        )
                    )
                    continue
                different_axes = sum(
                    (
                        left.sources != right.sources,
                        left.destinations != right.destinations,
                        left.services != right.services,
                    )
                )
                if (
                    different_axes == 1
                    and before.description == after.description
                    and before.owner == after.owner
                    and not left.covers(right)
                    and not right.covers(left)
                ):
                    findings.append(
                        _finding(
                            context,
                            self.check_id,
                            (before, after),
                            "Соседние правила являются кандидатами на объединение "
                            "по одной оси условий.",
                            Severity.INFO,
                            "Вручную проверить возможность объединения значений одной оси "
                            "без расширения остальных условий.",
                        )
                    )
        return _result(self.check_id, context, findings, limitations)
