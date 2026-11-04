"""Сравнение сохранённых запусков с независимыми каналами доказательств."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from hashlib import sha256
import html
import json
from typing import Any

from firewall_compliance.analysis.revision_diff import compare_device_revisions
from firewall_compliance.application.policy_comparison import compare_policy_revisions
from firewall_compliance.application.workspace_profile import ProfileVersion, analysis_settings
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
    if settings.get("source_id"):
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
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return {"known": True, "fingerprint": sha256(encoded).hexdigest(), "mode": payload["mode"]}


def _complete(item: Mapping[str, Any]) -> bool:
    parsed = item.get("parse_result") or {}
    coverage = parsed.get("coverage") or (item.get("report") or {}).get("parse_coverage") or {}
    return bool(
        item.get("status") == "complete" and not item.get("collection_warnings")
        and not parsed.get("errors") and not parsed.get("unsupported_constructs")
        and coverage.get("recognized_constructs") is not None
        and coverage.get("recognized_constructs") == coverage.get("discovered_constructs")
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
        old_checks = {value["check_id"]: value for value in (old_item.get("report") or {}).get("checks", [])}
        new_checks = {value["check_id"]: value for value in (new_item.get("report") or {}).get("checks", [])}
        inputs_comparable = bool(
            before.get("state") == after.get("state") == "completed"
            and profile_comparable and scope_comparable and _complete(old_item) and _complete(new_item)
            and old.parse_result.configuration.parser_version == new.parse_result.configuration.parser_version
        )
        for check_id in sorted(old_checks.keys() | new_checks.keys()):
            old_check, new_check = old_checks.get(check_id), new_checks.get(check_id)
            comparable = bool(
                inputs_comparable and old_check and new_check
                and check_execution_status(old_check) == check_execution_status(new_check) == "complete"
                and old_check.get("check_version") == new_check.get("check_version")
                and old_check.get("check_version")
            )
            if not comparable:
                add(identifier, "Полнота проверок", "Несопоставимые основания", check_id, {
                    "profile_comparable": profile_comparable,
                    "before": {key: old_check.get(key) for key in ("status", "check_version", "limitations")} if old_check else None,
                    "after": {key: new_check.get(key) for key in ("status", "check_version", "limitations")} if new_check else None,
                })
            buckets = []
            for check in (old_check, new_check):
                values: dict[tuple[str, tuple[str, ...]], list[dict[str, Any]]] = defaultdict(list)
                for finding in (check or {}).get("findings", []):
                    signature = (finding["title"], tuple(sorted(finding.get("affected_rule_ids", []))))
                    values[signature].append(finding)
                buckets.append(values)
            left, right = buckets
            for signature in sorted(left.keys() | right.keys()):
                old_findings, new_findings = left.get(signature, []), right.get(signature, [])
                change = (
                    "Неоднозначная сигнатура" if len(old_findings) > 1 or len(new_findings) > 1
                    else "Сходная сигнатура" if old_findings and new_findings
                    else "Появилась в результатах" if new_findings
                    else "Более не обнаружена" if comparable
                    else "Отсутствие не подтверждено"
                )
                add(identifier, "Находки", change, check_id + " · " + signature[0], {
                    "before": old_findings, "after": new_findings, "comparable": comparable,
                    "limitation": "Сигнатура не доказывает стабильную идентичность правила. Отсутствие не подтверждает исправление.",
                })
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
