"""Сравнение сохранённых запусков с независимыми каналами доказательств."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from hashlib import sha256
import html
import json
from typing import Any

from firewall_compliance.analysis.revision_diff import compare_device_revisions
from firewall_compliance.application.collection_integrity import count_drop_warning
from firewall_compliance.application.policy_comparison import compare_policy_revisions
from firewall_compliance.application.workspace_profile import ProfileVersion, analysis_settings
from firewall_compliance.checks.common.policy import CONFIGURED_COMWARE_CHECKS
from firewall_compliance.checks.common.transit import (
    ConfiguredComwarePolicy,
    configured_comware_policies,
)
from firewall_compliance.domain.enums import RuleAction
from firewall_compliance.domain.policy_matching import RuleMatch, ScopeKey, resolve_rule, scope_key
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.check_presentation import check_execution_status

CHANGE_LABELS = {
    "added": "Добавлено", "removed": "Удалено", "modified": "Изменены значения",
    "first_observed": "Впервые наблюдается", "not_observed": "Не наблюдается",
    "order_changed": "Изменился порядок", "representation_changed": "Изменилось представление",
    "evidence_changed": "Изменилось основание", "coverage_changed": "Изменилась полнота",
    "provenance_changed": "Изменилось происхождение", "normalization_changed": "Изменилась нормализация",
    "normalization_dependent": "Различие зависит от нормализации",
    "availability_changed": "Изменилась доступность данных", "scope_incomparable": "Несопоставимые области",
}

type _SwitchCondition = tuple[ScopeKey, str | None, str | None, int, RuleAction, RuleMatch]
type _ConfiguredPolicies = dict[str, ConfiguredComwarePolicy]


def _profile(run: Mapping[str, Any]) -> dict[str, Any]:
    settings = run.get("settings") or {}
    values = analysis_settings(settings)
    snapshot = None
    try:
        canonical = ProfileVersion.from_settings(str(run["project_id"]), 1, values)
        reference = settings.get("workspace_profile_fingerprint")
        known = isinstance(reference, str) and reference == canonical.fingerprint
        snapshot = canonical.settings()
    except (TypeError, ValueError):
        known, reference = False, None
    return {
        "version": settings.get("workspace_profile_version"),
        "fingerprint": reference if known else None,
        "settings": snapshot,
        "known": known,
    }


def _device_items(run: Mapping[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    devices: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unresolved = []
    for item in run.get("items", []):
        report = item.get("report") or {}
        revision = item.get("revision") or {}
        identifier = report.get("device_id") or revision.get("device", {}).get("device_id")
        if not identifier:
            unresolved.append({
                "item_id": item["id"], "source_name": item.get("source_name"),
                "status": item.get("status"), "reason": "Устройство не определено в сохранённом результате",
            })
        else:
            devices[str(identifier)].append(item)
    return dict(devices), unresolved


def _input_scope(run: Mapping[str, Any]) -> dict[str, Any]:
    settings = run.get("settings") or {}
    source_id = settings.get("source_id", "")
    saved_files = isinstance(source_id, str) and source_id.startswith("files:")
    if source_id and not saved_files:
        fingerprint = settings.get("source_config_fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint or settings.get("source_collection_state") != "completed":
            return {"known": False, "fingerprint": None, "mode": "api", "reason": "Область или завершение сбора не подтверждены"}
        payload = {
            "mode": "api", "source_id": settings["source_id"],
            "configuration": fingerprint, "sites": sorted(settings.get("source_site_ids") or []),
            "selection": settings.get("source_selection_fingerprint"),
        }
    elif settings.get("analysis_source"):
        return {"known": False, "fingerprint": None, "mode": "derived", "reason": "Нет сохранённого общего идентификатора области сбора"}
    else:
        if saved_files and settings.get("source_collection_state") != "completed":
            return {"known": False, "fingerprint": None, "mode": "files", "reason": "Не все файлы получены"}
        devices, unresolved = _device_items(run)
        if unresolved or not devices:
            return {"known": False, "fingerprint": None, "mode": "files", "reason": "Область файлов определена не полностью"}
        members = []
        sites = settings.get("workspace_input_sites") or {}
        for identifier, items in sorted(devices.items()):
            if len(items) != 1:
                return {"known": False, "fingerprint": None, "mode": "files", "reason": "Неоднозначное назначение файлов устройству"}
            item = items[0]
            source = item.get("source_path") or item.get("source_name")
            if not isinstance(source, str) or not source:
                return {"known": False, "fingerprint": None, "mode": "files", "reason": "Источник файла не зафиксирован"}
            members.append((identifier, source, sites.get(source)))
        payload = {"mode": "files", "members": members}
        if saved_files:
            payload.update({
                "source_id": source_id,
                "sites": sorted(settings.get("source_site_ids") or []),
            })
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return {"known": True, "fingerprint": sha256(encoded).hexdigest(), "mode": payload["mode"]}


def _complete(item: Mapping[str, Any], *, allow_partial_checks: bool = False) -> bool:
    parsed = item.get("parse_result") or {}
    coverage = parsed.get("coverage") or (item.get("report") or {}).get("parse_coverage") or {}
    valid_status = {"complete", "partial"} if allow_partial_checks else {"complete"}
    return bool(
        item.get("status") in valid_status and not item.get("collection_warnings")
        and not parsed.get("errors") and not parsed.get("unsupported_constructs")
        and coverage.get("recognized_constructs") is not None
        and coverage.get("recognized_constructs") == coverage.get("discovered_constructs")
    )


def _captured_file_scope(
    run: Mapping[str, Any], devices: Mapping[str, list[dict[str, Any]]],
) -> tuple[tuple[str, str, str | None], ...] | None:
    settings = run.get("settings") or {}
    source_id = settings.get("source_id")
    if (
        run.get("state") not in {"completed", "interrupted"}
        or not isinstance(source_id, str) or not source_id.startswith("files:")
        or settings.get("source_collection_state") != "completed"
    ):
        return None
    sites = settings.get("workspace_input_sites") or {}
    files = []
    for identifier, items in sorted(devices.items()):
        if len(items) != 1:
            return None
        path = items[0].get("path") or items[0].get("source_path")
        if not isinstance(path, str) or not path:
            return None
        files.append((identifier, path, sites.get(path)))
    return tuple(files) if files else None


def _switch_finding_rule_pairs(
    before: DeviceRevision, after: DeviceRevision,
    old_checks: Mapping[str, Any], new_checks: Mapping[str, Any], *,
    comware_policies: tuple[_ConfiguredPolicies, _ConfiguredPolicies] | None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Сопоставить известные условия на одной позиции настроенного ACL."""
    def by_condition(
        revision: DeviceRevision, checks: Mapping[str, Any], policies: _ConfiguredPolicies | None,
    ) -> dict[_SwitchCondition, list[str]]:
        referenced = {
            rule_id for check in checks.values() for finding in check.get("findings", [])
            for rule_id in finding.get("affected_rule_ids", [])
        }
        if not referenced:
            return {}
        bindings = {
            rule.rule_id: policy.binding
            for policy in policies.values()
            for rule in policy.rules
        } if policies is not None else {}
        scoped = [(scope, rule) for rule in revision.parse_result.rules if (scope := scope_key(rule)) is not None]
        positions = Counter((scope, rule.sequence) for scope, rule in scoped)
        rules: dict[_SwitchCondition, list[str]] = defaultdict(list)
        for scope, rule in scoped:
            if rule.rule_id not in referenced or not rule.enabled or positions[scope, rule.sequence] != 1:
                continue
            binding = bindings.get(rule.rule_id)
            if policies is not None and binding is None:
                continue
            match = resolve_rule(rule)
            if match is not None and rule.action != RuleAction.UNKNOWN:
                profile, vrf = (binding.configured_profile, binding.vrf) if binding else (None, None)
                rules[scope, profile, vrf, rule.sequence, rule.action, match].append(rule.rule_id)
        return rules

    old_policies, new_policies = comware_policies if comware_policies is not None else (None, None)
    old = by_condition(before, old_checks, old_policies)
    new = by_condition(after, new_checks, new_policies)
    pairs = {
        old[key][0]: new[key][0] for key in old.keys() & new.keys()
        if len(old[key]) == len(new[key]) == 1
    }
    return {key: key for key in pairs}, {value: key for key, value in pairs.items()}


def _compare_finding_rows(
    old_item: Mapping[str, Any], new_item: Mapping[str, Any],
    old: DeviceRevision, new: DeviceRevision, *,
    profile_comparable: bool, inputs_comparable: bool, configured_scope_comparable: bool = False,
    source_limitations: tuple[str, ...] | None = None,
) -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    identifier = old.device.device_id

    def add(channel: str, change: str, entity: str, details: dict[str, Any]) -> None:
        rows.append({"device": identifier, "channel": channel, "change": change, "entity": entity, "details": details})

    old_checks = {value["check_id"]: value for value in (old_item.get("report") or {}).get("checks", [])}
    new_checks = {value["check_id"]: value for value in (new_item.get("report") or {}).get("checks", [])}
    if source_limitations is not None and (source_limitations or not (old_checks or new_checks)):
        add("Полнота проверок", "Несопоставимые основания", "Снимки устройства", {
            "reasons": source_limitations or ("В обоих снимках нет сохранённых результатов проверок.",),
        })
    old_config, new_config = old.parse_result.configuration, new.parse_result.configuration
    changed_aruba = (
        old.device.vendor == "hp-aruba" and old.device.platform in {"aos-cx", "aos-switch"}
        and old_config.content_sha256 != new_config.content_sha256
    )
    comware = (old.device.vendor, old.device.platform) == ("hp-h3c", "comware")
    changed_comware = (
        comware and (old_config.content_sha256, old_config.parser_version)
        != (new_config.content_sha256, new_config.parser_version)
    )
    comware_policies = (
        configured_comware_policies(old.parse_result), configured_comware_policies(new.parse_result)
    ) if comware else None
    same_parser = old_config.parser_version == new_config.parser_version
    rule_pairs: tuple[dict[str, str], dict[str, str]] = ({}, {})
    if (changed_aruba or changed_comware) and same_parser:
        rule_pairs = _switch_finding_rule_pairs(
            old, new, old_checks, new_checks, comware_policies=comware_policies,
        )
    configured_checks_comparable = bool(configured_scope_comparable and comware_policies and all(comware_policies))
    for check_id in sorted(old_checks.keys() | new_checks.keys()):
        old_check, new_check = old_checks.get(check_id), new_checks.get(check_id)
        if source_limitations is not None and old_check and new_check and (
            check_execution_status(old_check) == check_execution_status(new_check) == "not_applicable"
            and old_check.get("check_version")
            and old_check.get("check_version") == new_check.get("check_version")
            and not (old_check.get("findings") or new_check.get("findings"))
        ):
            continue
        configured_check = check_id in CONFIGURED_COMWARE_CHECKS
        check_limit = _check_comparison_limit(old_check, new_check)
        comparable = bool(
            (inputs_comparable or (configured_check and configured_checks_comparable))
            and check_limit is None
        )
        before_check = _check_summary(old_check)
        after_check = _check_summary(new_check)
        reasons = source_limitations
        if source_limitations is not None and check_limit is not None:
            reasons = (*source_limitations, check_limit)
        if not comparable:
            diagnostics: dict[str, Any] = {
                "profile_comparable": profile_comparable,
                "before": before_check, "after": after_check,
            }
            if reasons is not None:
                diagnostics["reasons"] = reasons
            add("Полнота проверок", "Несопоставимые основания", check_id, diagnostics)
        comware_check = changed_comware and configured_check
        if changed_comware and not comware_check:
            check_pairs: tuple[dict[str, str], dict[str, str]] = ({}, {})
        else:
            check_pairs = rule_pairs
        buckets = []
        for side, check, mapped in zip(
            ("before", "after"), (old_check, new_check), check_pairs, strict=True,
        ):
            values: dict[tuple[str, tuple[tuple[str, str], ...]], list[dict[str, Any]]] = defaultdict(list)
            # Исходный ID коммутатора может совпасть после замены содержимого строки.
            switch_scope_changed = comware_check or (source_limitations is not None and changed_aruba)
            fallback = side if switch_scope_changed else "id"
            for finding in (check or {}).get("findings", []):
                rules = tuple(sorted(
                    ("condition", mapped[key]) if key in mapped else (fallback, key)
                    for key in finding.get("affected_rule_ids", [])
                ))
                signature = finding["title"], rules
                values[signature].append(finding)
            buckets.append(values)
        left, right = buckets
        ambiguous_titles = (
            {title for title, _ in left.keys() - right.keys()}
            & {title for title, _ in right.keys() - left.keys()}
            if changed_aruba or comware_check else set()
        )
        for signature in sorted(left.keys() | right.keys()):
            old_findings, new_findings = left.get(signature, []), right.get(signature, [])
            paired = bool(old_findings and new_findings)
            comparable_rules = paired and bool(signature[1]) and all(kind == "condition" for kind, _ in signature[1])
            uncertain = not paired and signature[0] in ambiguous_titles
            change = (
                "Неоднозначная сигнатура" if len(old_findings) > 1 or len(new_findings) > 1
                else "Сохраняется на сопоставленных условиях" if comparable and comparable_rules
                else "Сходная сигнатура" if paired
                else "Сопоставление правил не подтверждено" if uncertain
                else "Есть во втором результате" if new_findings and source_limitations is not None and not comparable
                else "Появилась в результатах" if new_findings
                else "Более не обнаружена" if comparable
                else "Отсутствие не подтверждено"
            )
            details: dict[str, Any] = {
                "before": old_findings, "after": new_findings, "comparable": comparable and not uncertain,
                "limitation": (
                    "Сопоставлены область, номер позиции, действие и нормализованные условия ACL. "
                    "Исходные привязки сохранены в обоих результатах."
                    if comparable_rules and (comparable or source_limitations is None) else
                    "Условия сопоставлены. Полнота или происхождение проверки требуют уточнения."
                    if source_limitations is not None and comparable_rules else
                    "Сигнатура не доказывает стабильную идентичность правила. Отсутствие не подтверждает исправление."
                ),
            }
            if reasons is not None:
                details.update({"before_check": before_check, "after_check": after_check, "reasons": reasons})
            add("Находки", change, check_id + " · " + signature[0], details)
    return tuple(rows)


def _check_summary(check: dict[str, Any] | None) -> dict[str, Any] | None:
    return {key: check.get(key) for key in ("status", "check_version", "limitations")} if check else None


def _check_comparison_limit(before: dict[str, Any] | None, after: dict[str, Any] | None) -> str | None:
    if not before or not after:
        return "Одна сторона не содержит результата этой проверки."
    if check_execution_status(before) != "complete" or check_execution_status(after) != "complete":
        return "Для подтверждения изменения нужна завершённая проверка в обоих снимках."
    if not before.get("check_version") or before["check_version"] != after.get("check_version"):
        return "Версии проверки различаются или отсутствуют."
    return None


def compare_saved_device_findings(
    before_item: Mapping[str, Any], after_item: Mapping[str, Any],
    old: DeviceRevision, new: DeviceRevision, *,
    before_run: Mapping[str, Any], after_run: Mapping[str, Any],
    source_limitations: Sequence[str] = (),
) -> tuple[dict[str, Any], ...]:
    """Сопоставить результаты точных снимков одного устройства из сверок матрицы."""
    if not before_run.get("project_id") or before_run["project_id"] != after_run.get("project_id"):
        raise ValueError("Снимки должны принадлежать одному проекту.")
    if _device_identity(old) != _device_identity(new):
        raise ValueError("Снимки должны принадлежать одному устройству, платформе и контексту.")
    old_config, new_config = old.parse_result.configuration, new.parse_result.configuration
    reasons = list(source_limitations)
    if before_run.get("id") == after_run.get("id"):
        reasons.append("Оба снимка получены в одном запуске. Последовательность независимых проверок не подтверждена.")
    if new_config.captured_at < old_config.captured_at or (
        new_config.captured_at == old_config.captured_at and new_config.content_sha256 != old_config.content_sha256
    ):
        reasons.append("Время снимков устройства не подтверждает порядок сравнения.")
    if old_config.parser_version != new_config.parser_version:
        reasons.append("Версии парсера различаются.")
    before_profile, after_profile = _profile(before_run), _profile(after_run)
    profile_comparable = bool(
        before_profile["known"] and after_profile["known"]
        and before_profile["fingerprint"] == after_profile["fingerprint"]
    )
    if not profile_comparable:
        reasons.append("Профили проверок различаются или их происхождение не подтверждено.")
    _device_source_limitations(before_item, after_item, old, new, before_run, after_run, reasons)
    threshold = (after_profile["settings"] or {}).get("rule_count_drop_percent", 30)
    drop = count_drop_warning(
        len(old.parse_result.rules), len(new.parse_result.rules),
        threshold_percent=threshold, before_reference=str(old.revision_id), unit="правила",
    )
    if drop is not None:
        reasons.append(drop.message)
    return _compare_finding_rows(
        before_item, after_item, old, new, profile_comparable=profile_comparable,
        inputs_comparable=not reasons, source_limitations=tuple(dict.fromkeys(reasons)),
    )


def _device_identity(revision: DeviceRevision) -> tuple[str, str, str, str | None]:
    device = revision.device
    return device.device_id, device.vendor, device.platform, device.context


def _device_source_limitations(
    before_item: Mapping[str, Any], after_item: Mapping[str, Any], old: DeviceRevision, new: DeviceRevision,
    before_run: Mapping[str, Any], after_run: Mapping[str, Any], reasons: list[str],
) -> None:
    settings = [(run.get("settings") or {}) for run in (before_run, after_run)]
    for label, item, revision, run, run_settings in (
        ("Первый снимок", before_item, old, before_run, settings[0]),
        ("Второй снимок", after_item, new, after_run, settings[1]),
    ):
        if not run.get("id") or item.get("run_id") != run["id"]:
            raise ValueError("Элемент снимка не принадлежит указанному запуску.")
        parsed = revision.parse_result
        report = item.get("report") or {}
        if report and (
            report.get("revision_id") != str(revision.revision_id)
            or report.get("configuration_id") != str(parsed.configuration.configuration_id)
            or report.get("device_id") != revision.device.device_id
            or report.get("parser_version") != parsed.configuration.parser_version
        ):
            raise ValueError("Сохранённый отчёт не соответствует указанному снимку устройства.")
        if not report:
            reasons.append(f"{label}: сохранённый результат проверок недоступен.")
        if (
            run.get("state") not in {"completed", "interrupted"}
            or run_settings.get("source_collection_state") not in {None, "completed"}
            or (run_settings.get("source_id") and run_settings.get("source_collection_state") != "completed")
        ):
            reasons.append(f"{label}: завершение сбора источника не подтверждено.")
        if item.get("collection_warnings"):
            reasons.append(f"{label}: есть предупреждение о полноте сбора.")
        if (
            item.get("status") not in {"complete", "partial"}
            or parsed.errors or parsed.unsupported_constructs or parsed.coverage.coverage_ratio < 1
            or report.get("parse_errors") or report.get("unsupported_constructs")
        ):
            reasons.append(f"{label}: полнота разбора конфигурации не подтверждена.")
    if _device_configuration_scope(old, settings[0]) != _device_configuration_scope(new, settings[1]):
        reasons.append("Область входной конфигурации различается.")
    if any(
        run_settings.get("source_id") and not str(run_settings["source_id"]).startswith("files:")
        or run_settings.get("analysis_source")
        for run_settings in settings
    ):
        scopes = _input_scope(before_run), _input_scope(after_run)
        if not all(scope["known"] and scope["mode"] == "api" for scope in scopes) or (
            scopes[0]["fingerprint"] != scopes[1]["fingerprint"]
        ):
            reasons.append("Область получения исходных политик различается или не подтверждена.")


def _device_configuration_scope(revision: DeviceRevision, settings: Mapping[str, Any]) -> tuple[object, ...]:
    facts = revision.parse_result.switch_facts
    return (
        facts.configuration_complete if facts is not None else settings.get("configuration_complete", False),
        settings.get("configuration_view", "unknown"),
        settings.get("configuration_node_path"),
    )


def previous_comparable_run(
    runs: Sequence[dict[str, Any]], after: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Выбрать предшествующий полный запуск, не угадывая неполную область."""
    profile = _profile(after)
    scope = _input_scope(after)
    devices, unresolved = _device_items(after)
    if after.get("state") != "completed" or not profile["known"] or not scope["known"] or not devices or unresolved:
        return None
    if any(len(items) != 1 or not _complete(items[0]) for items in devices.values()):
        return None
    try:
        timestamp = datetime.fromisoformat(after["created_at"])
        if timestamp.utcoffset() is None:
            return None
    except (ValueError, TypeError, KeyError):
        return None
    candidates = []
    for run in runs:
        try:
            captured = datetime.fromisoformat(run["created_at"])
            if captured.utcoffset() is None or captured >= timestamp:
                continue
        except (ValueError, TypeError, KeyError):
            continue
        if (
            run.get("project_id") != after["project_id"] or run.get("state") != "completed"
            or run.get("site_selection") != after.get("site_selection")
            or _profile(run)["fingerprint"] != profile["fingerprint"]
            or _input_scope(run)["fingerprint"] != scope["fingerprint"]
        ):
            continue
        old_devices, old_unresolved = _device_items(run)
        if old_unresolved or old_devices.keys() != devices.keys():
            continue
        valid = True
        for identifier, items in old_devices.items():
            if len(items) != 1 or not _complete(items[0]):
                valid = False
                break
            old, new = items[0], devices[identifier][0]
            first, second = old.get("revision") or {}, new.get("revision") or {}
            first_device, second_device = first.get("device") or {}, second.get("device") or {}
            if (
                not first or not second
                or first_device.get("device_id") != identifier or second_device.get("device_id") != identifier
                or not (old.get("parse_result") or {}).get("configuration", {}).get("parser_version")
                or any(first_device.get(key) != second_device.get(key) for key in ("vendor", "platform", "context"))
                or (old.get("parse_result") or {}).get("configuration", {}).get("parser_version")
                != (new.get("parse_result") or {}).get("configuration", {}).get("parser_version")
            ):
                valid = False
                break
            checks = []
            for item in (old, new):
                entries = (item.get("report") or {}).get("checks", [])
                if not entries or any(check_execution_status(value) not in {"complete", "not_applicable"} for value in entries):
                    valid = False
                    break
                checks.append({value["check_id"]: (value.get("check_version"), check_execution_status(value)) for value in entries})
            if not valid or len(checks) != 2 or checks[0] != checks[1] or any(not value[0] for value in checks[0].values()):
                valid = False
                break
        if valid:
            candidates.append((captured, run["id"], run))
    return max(candidates, key=lambda value: (value[0], value[1]))[2] if candidates else None


def compare_saved_runs(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    if before["project_id"] != after["project_id"] or before["id"] == after["id"]:
        raise ValueError("Choose different runs of one project")
    if before.get("site_selection") != after.get("site_selection"):
        raise ValueError("Run selections have different site scopes")
    first, unresolved_before = _device_items(before)
    second, unresolved_after = _device_items(after)
    old_profile, new_profile = _profile(before), _profile(after)
    profile_comparable = bool(
        old_profile["known"] and new_profile["known"]
        and old_profile["fingerprint"] == new_profile["fingerprint"]
    )
    old_scope, new_scope = _input_scope(before), _input_scope(after)
    scope_comparable = bool(old_scope["known"] and new_scope["known"] and old_scope["fingerprint"] == new_scope["fingerprint"])
    old_file_scope = _captured_file_scope(before, first) if scope_comparable else None
    same_file_scope = old_file_scope is not None and old_file_scope == _captured_file_scope(after, second)
    rows: list[dict[str, Any]] = []
    devices = []

    def add(device: str, channel: str, change: str, entity: str, details: object) -> None:
        rows.append({"device": device, "channel": channel, "change": CHANGE_LABELS.get(change, change), "entity": entity, "details": details})

    if not profile_comparable:
        add("Весь запуск", "Профиль", "Профили различаются или не подтверждены", "Профиль проверок", {
            "before": old_profile, "after": new_profile,
        })
    if not scope_comparable:
        add("Весь запуск", "Область входов", "Области различаются или не подтверждены", "Область сбора / импорта", {"before": old_scope, "after": new_scope})
    for item in unresolved_before:
        add("Не определено", "Неопределённые входы", "Нет достоверной ревизии", str(item.get("source_name")), {"before": item, "after": None})
    for item in unresolved_after:
        add("Не определено", "Неопределённые входы", "Нет достоверной ревизии", str(item.get("source_name")), {"before": None, "after": item})

    for identifier in sorted(first.keys() | second.keys()):
        old_items, new_items = first.get(identifier, []), second.get(identifier, [])
        record: dict[str, Any] = {
            "device_id": identifier,
            "before_item_ids": [item["id"] for item in old_items],
            "after_item_ids": [item["id"] for item in new_items],
            "before_inputs": [{key: item.get(key) for key in ("id", "source_name", "content_sha256", "status")} for item in old_items],
            "after_inputs": [{key: item.get(key) for key in ("id", "source_name", "content_sha256", "status")} for item in new_items],
        }
        devices.append(record)
        if len(old_items) > 1 or len(new_items) > 1:
            record["state"] = "ambiguous"
            add(identifier, "Состав", "Неоднозначное сопоставление", identifier, record.copy())
            continue
        if not old_items or not new_items:
            record["state"] = "not_observed" if old_items else "first_observed"
            add(identifier, "Состав", "Не наблюдается" if old_items else "Впервые наблюдается", identifier, record.copy())
            continue
        old_item, new_item = old_items[0], new_items[0]
        try:
            old = DeviceRevision.model_validate(old_item.get("revision"))
            new = DeviceRevision.model_validate(new_item.get("revision"))
        except (ValueError, TypeError):
            record["state"] = "invalid_revision"
            add(identifier, "Полнота", "Ревизия недоступна", identifier, record.copy())
            continue
        if old.device.device_id != identifier or new.device.device_id != identifier:
            record["state"] = "identity_mismatch"
            add(identifier, "Состав", "Не совпадает идентификатор устройства", identifier, record.copy())
            continue
        record.update({
            "before_revision": old.model_dump(mode="json"),
            "after_revision": new.model_dump(mode="json"),
        })
        if (old.device.vendor, old.device.platform, old.device.context) != (
            new.device.vendor, new.device.platform, new.device.context,
        ):
            record["state"] = "scope_incomparable"
            add(identifier, "Полнота", "Различаются платформа или контекст", identifier, {"before": old.device.model_dump(mode="json"), "after": new.device.model_dump(mode="json")})
            continue
        record["state"] = "paired"
        scope = str(before["project_id"]) + "/device/" + identifier
        try:
            policy = compare_policy_revisions(old, new, scope_reference=scope)
        except (ValueError, TypeError):
            policy = None
            add(identifier, "Ограничения", "Сравнение правил недоступно", identifier, "Идентичность или структура входов не подтверждены.")
        try:
            network = compare_device_revisions(old, new)
        except (ValueError, TypeError):
            network = None
            add(identifier, "Ограничения", "Сравнение сети недоступно", identifier, "Контексты сетевых фактов не согласованы.")
        record["policy"] = policy.model_dump(mode="json") if policy else None
        record["network"] = network.model_dump(mode="json") if network else None
        for field, channel in (
            ("semantic_changes", "Правила / объекты"), ("provenance_changes", "Происхождение"),
            ("normalization_changes", "Нормализация"), ("completeness_changes", "Полнота"),
        ):
            for change in getattr(policy.computation, field) if policy else ():
                add(identifier, channel, change.kind, ", ".join((*change.before_ids, *change.after_ids)), change.model_dump(mode="json"))
        for change in network.changes if network else ():
            add(identifier, "Сетевые факты", change.change_kind.value, change.entity_id, change.model_dump(mode="json"))
        for field, channel in (
            ("provenance_changes", "Происхождение сети"),
            ("normalization_changes", "Нормализация сети"), ("completeness_changes", "Полнота сети"),
        ):
            for change in getattr(network, field) if network else ():
                add(identifier, channel, change.code, change.entity_id, change.model_dump(mode="json"))
        for limitation in policy.computation.limitations if policy else ():
            add(identifier, "Ограничения", limitation.code, ", ".join(limitation.entity_ids), limitation.model_dump(mode="json"))
        for limitation in network.limitations if network else ():
            add(identifier, "Ограничения", "Сетевое сравнение", identifier, limitation)
        same_parser = old.parse_result.configuration.parser_version == new.parse_result.configuration.parser_version
        inputs_comparable = bool(
            before.get("state") == after.get("state") == "completed"
            and profile_comparable and scope_comparable and _complete(old_item) and _complete(new_item)
            and same_parser
        )
        # В файловом цикле частичная посторонняя проверка не отменяет уже завершившийся сбор.
        configured_scope_comparable = bool(
            (old.device.vendor, old.device.platform) == ("hp-h3c", "comware") and profile_comparable and scope_comparable
            and same_parser and same_file_scope
            and _complete(old_item, allow_partial_checks=True)
            and _complete(new_item, allow_partial_checks=True)
            and all(
                not revision.parse_result.unsupported_constructs
                and revision.parse_result.coverage.coverage_ratio == 1
                for revision in (old, new)
            )
        )
        rows.extend(_compare_finding_rows(
            old_item, new_item, old, new, profile_comparable=profile_comparable,
            inputs_comparable=inputs_comparable, configured_scope_comparable=configured_scope_comparable,
        ))
    return {
        "package_type": "firewall-compliance.run-comparison", "schema_version": "1.0.0",
        "project_id": str(before["project_id"]), "before_run_id": str(before["id"]), "after_run_id": str(after["id"]),
        "generated_at": datetime.now(UTC).isoformat(),
        "before_created_at": before.get("created_at"), "after_created_at": after.get("created_at"),
        "site_selection": before.get("site_selection"),
        "profiles": {"before": old_profile, "after": new_profile, "comparable": profile_comparable},
        "input_scopes": {"before": old_scope, "after": new_scope, "comparable": scope_comparable},
        "devices": devices, "rows": rows,
        "unresolved_before": unresolved_before, "unresolved_after": unresolved_after,
        "limitations": [
            "Сравниваются сохранённые ревизии, а не атомарные снимки всей инфраструктуры.",
            "Добавление/удаление правила требует доказанной идентичности и полноты; совпадение rule_id само по себе недостаточно.",
            "Изменение условий не доказывает открытие/закрытие сквозного доступа. Решения пользователя не переносятся автоматически.",
            "Область площадки при наличии фильтра определяется текущими назначениями устройств.",
        ],
    }


def comparison_report_section(package: Mapping[str, Any], comparison_id: str) -> str:
    def escape(value: object) -> str:
        return html.escape(str(value), quote=True)

    parts = [
        f'<section id="comparison-{escape(comparison_id)}"><h2>Изменения между запусками</h2>',
        f"<p>Сравнение: {escape(comparison_id)}; рассчитано: {escape(package['generated_at'])}<br>"
        f"Было: {escape(package['before_run_id'])} · {escape(package['before_created_at'])}<br>"
        f"Стало: {escape(package['after_run_id'])} · {escape(package['after_created_at'])}</p>",
        f"<p>Основание выбора: {escape(package.get('selection_basis', 'не указано'))}<br>"
        f"Область: {escape(package.get('site_selection') if package.get('site_selection') is not None else 'все площадки')}</p>",
        "<ul>" + "".join(f"<li>{escape(value)}</li>" for value in package["limitations"]) + "</ul>",
        "<p>Профили сопоставимы: " + escape(package["profiles"]["comparable"])
        + "; области входов сопоставимы: " + escape(package["input_scopes"]["comparable"]) + "</p>",
    ]
    for row in package["rows"]:
        parts.append(
            f"<article><h3>{escape(row['device'])} · {escape(row['channel'])} · {escape(row['change'])}</h3>"
            f"<p>{escape(row['entity'])}</p><pre>"
            + escape(json.dumps(row["details"], ensure_ascii=False, indent=2))
            + "</pre></article>"
        )
    if not package["rows"]:
        parts.append("<p>Отображаемых различий в пределах зафиксированных входов нет.</p>")
    parts.append("</section>")
    return "\n".join(parts)
