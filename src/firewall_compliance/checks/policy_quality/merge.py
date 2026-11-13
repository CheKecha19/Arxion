"""Policy check implementation."""

from itertools import pairwise

from firewall_compliance.checks.common.ordered_coverage import (
    CoverageSearchLimit,
    OrderedCoverageIndex,
)
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
        groups, limitations = _pair_groups(context, enforce_pair_limit=False)
        findings: list[Finding] = []
        for rules in groups:
            if len(rules) < 2:
                continue
            coverage = OrderedCoverageIndex(rules, context.max_pair_rules)
            for position, (before, after) in enumerate(pairwise(rules)):
                if before.action != after.action:
                    continue
                metadata_issue = None
                if (
                    before.logging_status != DataStatus.KNOWN
                    or after.logging_status != DataStatus.KNOWN
                    or before.logging_enabled is None
                    or after.logging_enabled is None
                ):
                    metadata_issue = "Нет достоверного логирования для объединения."
                elif not _same_effect(before, after):
                    continue
                elif before.description_status not in {
                    DataStatus.KNOWN,
                    DataStatus.ABSENT,
                } or after.description_status not in {DataStatus.KNOWN, DataStatus.ABSENT}:
                    metadata_issue = "Нет достоверных описаний для оценки объединения."
                if metadata_issue is None:
                    left, right = coverage.matches[position], coverage.matches[position + 1]
                    different_axes = sum(
                        (
                            left.sources != right.sources,
                            left.destinations != right.destinations,
                            left.services != right.services,
                        )
                    )
                    if (
                        different_axes != 1
                        or before.description != after.description
                        or before.owner != after.owner
                    ):
                        continue
                try:
                    if coverage.first_covering((position, position + 1), before=position) is not None:
                        continue
                    if metadata_issue is not None:
                        limitations.append(
                            _limitation("UNKNOWN_MERGE_METADATA", metadata_issue, before, after)
                        )
                        continue
                    if coverage.covers(position, position + 1) or coverage.covers(position + 1, position):
                        continue
                except CoverageSearchLimit:
                    limitations.append(
                        _limitation(
                            "COVER_CANDIDATE_LIMIT",
                            "Исчерпан бюджет точных сравнений. Поиск кандидатов на объединение "
                            "от указанной пары до конца этой области выполнен частично.",
                            before,
                            after,
                        )
                    )
                    break
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
