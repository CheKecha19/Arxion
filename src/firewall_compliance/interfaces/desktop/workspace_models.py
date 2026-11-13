"""Проекции проверок и облачных сборов для desktop без изменения исходных данных."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any


def cloud_resource_key(scan: dict[str, Any], record: dict[str, Any], index: int) -> str:
    """Различать ID ресурсов по подключению, не сопоставляя их по имени или IP."""
    config = scan.get("config", {})
    connection = {
        key: config.get(key)
        for key in (
            "platform",
            "site",
            "tenant",
            "project_id",
            "region",
            "ecs_endpoint",
            "vpc_endpoint",
        )
    }
    connection["platform"] = connection["platform"] or "vmware"
    return json.dumps(
        [connection, record.get("type"), record.get("id") or [scan["id"], index]],
        sort_keys=True,
        ensure_ascii=False,
    )


def cloud_resources(scans: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Последнее наблюдение каждого ресурса по сохранённым сборам."""
    return cloud_inventory(scans)[0]


def cloud_inventory(
    scans: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """Состав инвентаря и операции, в которых наблюдался каждый ресурс.

    Каждая строка сохраняет собственное время и исходный сбор. Сеть и секреты
    не используются, сохранённые результаты не изменяются.
    """
    resources: dict[str, dict[str, Any]] = {}
    history: dict[str, list[dict[str, Any]]] = {}
    for scan in sorted(scans, key=lambda value: value["created_at"], reverse=True):
        operation = {
            "id": scan["id"], "created_at": scan["created_at"], "state": scan.get("state", "unknown"),
            "operation_kind": "collection",
        }
        for index, record in enumerate(scan.get("result", {}).get("records", [])):
            if not isinstance(record, dict):
                continue
            identity = "cloud:" + cloud_resource_key(scan, record, index)
            observations = history.setdefault(identity, [])
            if not observations or observations[-1]["id"] != scan["id"]:
                observations.append(operation)
            resources.setdefault(
                identity,
                {
                    "id": identity,
                    "kind": "cloud",
                    "scan": scan,
                    "record": record,
                    "record_index": index,
                    "platform": scan["config"].get("platform", "vmware"),
                },
            )
    return list(resources.values()), history


def project_operations(
    runs: Sequence[dict[str, Any]], scans: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Объединить представление, сохранив разные ID и контракты операций."""
    return sorted(
        [
            *({**run, "operation_kind": "check"} for run in runs),
            *({**scan, "operation_kind": "collection"} for scan in scans),
        ],
        key=lambda item: item["created_at"],
        reverse=True,
    )
