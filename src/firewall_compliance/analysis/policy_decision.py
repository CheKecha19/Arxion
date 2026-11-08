"""Локальное first-match решение по явно подтверждённой ACL."""

from ipaddress import ip_address
from typing import Literal

from firewall_compliance.analysis.policy_matching import matches_query, resolve_rule
from firewall_compliance.domain.enums import DataStatus, SourceDocumentKind
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.policy_decision import (
    PolicyBindingEvidence,
    PolicyDecisionResult,
    PolicyDecisionStatus,
    PolicyTraceEntry,
)
from firewall_compliance.domain.reachability import AnalysisReason, ReachabilityQuery
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.domain.switch_policy import is_transit_rule

_ACTIONS: dict[str, Literal["allow", "deny", "drop", "reject"]] = {
    "allow": "allow",
    "deny": "deny",
    "drop": "drop",
    "reject": "reject",
}


def _located(location: SourceLocation) -> bool:
    return location.line_start is not None or bool(location.object_path or location.object_id)


def evaluate_policy(
    revision: DeviceRevision, query: ReachabilityQuery, binding: PolicyBindingEvidence
) -> PolicyDecisionResult:
    """Оценить переданный acl_input tuple без преобразования адресов."""
    revision = DeviceRevision.model_validate(revision.model_dump(mode="python"))
    query = ReachabilityQuery.model_validate(query.model_dump(mode="python"))
    binding = PolicyBindingEvidence.model_validate(binding.model_dump(mode="python"))
    parsed = revision.parse_result
    configuration = parsed.configuration
    rules = tuple(
        sorted(
            (rule for rule in parsed.rules if rule.policy_id == binding.policy_id),
            key=lambda rule: (rule.sequence, rule.rule_id),
        )
    )
    reasons: list[AnalysisReason] = []
    trace: list[PolicyTraceEntry] = []

    def reason(
        code: str,
        category: Literal["missing_evidence", "unsupported", "contradiction", "pending"],
        message: str,
    ) -> None:
        reasons.append(AnalysisReason(code=code, category=category, message=message))

    if (
        query.revision_id != revision.revision_id
        or query.device_id != revision.device.device_id
        or query.device_context != revision.device.context
    ):
        reason("query_context_mismatch", "contradiction", "Запрос относится к другому снимку.")
    if query.table_id != "default" or ip_address(query.source_ip).version != 4:
        reason("query_scope_unsupported", "unsupported", "Поддерживается только default IPv4.")
    if not binding.complete or not binding.completeness_reference:
        reason("acl_incomplete", "missing_evidence", "Нет явного основания полноты ACL.")
    if binding.terminal and not binding.terminal_reference:
        reason("terminal_reference_missing", "missing_evidence", "Нет основания конца цепочки.")
    source = next(
        (
            item
            for item in revision.sources
            if item.source_document_id == binding.source_document_id
        ),
        None,
    )
    if source is None:
        reason("binding_source_missing", "missing_evidence", "Источник привязки отсутствует.")
    elif (
        source.kind != SourceDocumentKind.CONFIGURATION
        or source.source_name != configuration.source_name
        or source.content_sha256.casefold() != configuration.content_sha256.casefold()
    ):
        reason("binding_source_mismatch", "contradiction", "Источник не совпадает с конфигурацией.")
    if (
        source is not None and binding.binding_location.source_name != source.source_name
    ) or not _located(binding.binding_location):
        reason("binding_location_invalid", "contradiction", "Не подтверждена позиция привязки.")
    if revision.observed_at is None or source is None or source.observation is None:
        reason("observation_missing", "missing_evidence", "Нет общего наблюдения конфигурации.")
    elif (
        source.observation.observed_at != revision.observed_at
        if revision.observation_window is None
        else not revision.observation_window.start
        <= source.observation.observed_at
        <= revision.observation_window.end
    ):
        reason("observation_mismatch", "contradiction", "Наблюдение вне снимка ревизии.")
    interface = next(
        (item for item in revision.interfaces if item.interface_id == binding.interface_id),
        None,
    )
    ingress = next(
        (item for item in revision.interfaces if item.interface_id == query.ingress_interface_id),
        None,
    )
    if interface is None or ingress is None:
        reason("interface_missing", "missing_evidence", "Интерфейс отсутствует в ревизии.")
    elif (
        revision.interfaces_status != DataStatus.KNOWN
        or interface.data_status != DataStatus.KNOWN
        or ingress.data_status != DataStatus.KNOWN
    ):
        reason("interface_unknown", "missing_evidence", "Факт интерфейса не подтверждён.")
    if binding.direction == "in" and binding.interface_id != query.ingress_interface_id:
        reason("ingress_binding_mismatch", "contradiction", "Входная ACL привязана иначе.")
    if parsed.warnings or parsed.errors or parsed.unsupported_constructs:
        reason("parse_diagnostics", "unsupported", "Диагностика разбора исключает решение.")
    if (
        parsed.coverage.recognized_constructs != parsed.coverage.discovered_constructs
        or parsed.coverage.unsupported_constructs
    ):
        reason("parse_coverage_mismatch", "unsupported", "Покрытие разбора неполное.")
    if not rules:
        reason("acl_rules_missing", "missing_evidence", "Нет правил подтверждённой ACL.")
    if len({rule.sequence for rule in rules}) != len(rules):
        reason("duplicate_sequence", "contradiction", "Порядок ACL неоднозначен.")
    if len({rule.rule_id for rule in rules}) != len(rules):
        reason("duplicate_rule_id", "contradiction", "Идентификаторы ACL повторяются.")
    for rule in rules:
        if not is_transit_rule(rule):
            reason(
                "non_transit_policy",
                "unsupported",
                "Управляющая, непривязанная или неизвестная ACL не определяет транзитный доступ.",
            )
            break
        zone = rule.source_zone if binding.direction == "in" else rule.destination_zone
        opposite_zone = rule.destination_zone if binding.direction == "in" else rule.source_zone
        if (
            rule.policy_direction != binding.direction
            or rule.policy_semantics != "first_match"
            or rule.zone_status != DataStatus.KNOWN
            or zone is None
            or zone.casefold() != binding.interface_label.casefold()
            or opposite_zone is not None
        ):
            reason("rule_scope_mismatch", "contradiction", "Область правила не подтверждена.")
            break
        if rule.source_location.source_name != configuration.source_name or not _located(
            rule.source_location
        ):
            reason("rule_location_invalid", "contradiction", "Не подтверждён источник правила.")
            break

    status: PolicyDecisionStatus = "no_match"
    matched_rule_id = None
    if reasons:
        status = (
            "unknown"
            if any(item.category in {"contradiction", "unsupported"} for item in reasons)
            else "not_enough_evidence"
        )
    else:
        for rule in rules:
            outcome: Literal["disabled", "no_match", "match", "unknown"]
            if not rule.enabled:
                outcome = "disabled"
            else:
                resolved = resolve_rule(rule)
                if resolved is None:
                    outcome = "unknown"
                    reason(
                        "rule_match_unknown", "unsupported", "Условие предшественника неизвестно."
                    )
                elif not matches_query(resolved, query):
                    outcome = "no_match"
                elif rule.action.value not in _ACTIONS:
                    outcome = "unknown"
                    reason(
                        "rule_action_unknown",
                        "unsupported",
                        "Действие совпавшего правила неизвестно.",
                    )
                else:
                    outcome = "match"
                    status = _ACTIONS[rule.action.value]
                    matched_rule_id = rule.rule_id
            trace.append(
                PolicyTraceEntry(
                    rule_id=rule.rule_id,
                    sequence=rule.sequence,
                    outcome=outcome,
                    source_location=rule.source_location,
                )
            )
            if outcome == "unknown":
                status = "unknown"
                break
            if outcome == "match":
                break
        else:
            if (
                binding.implicit_action == "deny"
                and binding.terminal
                and binding.terminal_reference
            ):
                status = "implicit_deny"

    locations = [binding.binding_location, *(rule.source_location for rule in rules)]
    locations.extend(
        item.source_location
        for item in (*parsed.warnings, *parsed.errors)
        if item.source_location is not None
    )
    locations.extend(item.source_location for item in parsed.unsupported_constructs)
    sources = tuple(sorted(revision.sources, key=lambda item: str(item.source_document_id)))
    return PolicyDecisionResult(
        query=query,
        binding=binding,
        status=status,
        matched_rule_id=matched_rule_id,
        trace=tuple(trace),
        reasons=tuple(reasons),
        sources=sources,
        evidence=Evidence(
            summary="Локальное решение ACL.",
            source_locations=tuple(locations),
            related_rule_ids=tuple(rule.rule_id for rule in rules),
            facts={
                "revision_id": str(revision.revision_id),
                "revision_schema_version": revision.schema_version,
                "configuration_id": str(configuration.configuration_id),
                "configuration": configuration.model_dump(mode="json"),
                "content_sha256": configuration.content_sha256,
                "parser_version": configuration.parser_version,
                "application_version": revision.application_version,
                "device": revision.device.model_dump(mode="json"),
                "observed_at": revision.observed_at.isoformat() if revision.observed_at else None,
                "observation_window": revision.observation_window.model_dump(mode="json")
                if revision.observation_window
                else None,
                "binding": binding.model_dump(mode="json"),
                "interface": interface.model_dump(mode="json") if interface else None,
                "rules": [rule.model_dump(mode="json") for rule in rules],
                "sources": [item.model_dump(mode="json") for item in sources],
                "coverage": parsed.coverage.model_dump(mode="json"),
                "warnings": [item.model_dump(mode="json") for item in parsed.warnings],
                "errors": [item.model_dump(mode="json") for item in parsed.errors],
                "unsupported_constructs": [
                    item.model_dump(mode="json") for item in parsed.unsupported_constructs
                ],
            },
            limitations=(
                "acl_input: явно заданный real/untranslated tuple.",
                "Локальный результат не доказывает передачу потока.",
            ),
        ),
    )
