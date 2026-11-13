"""Source attempt history, independent of live connectivity or safety claims."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any


def configuration_fingerprint(config: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(
        dict(config), sort_keys=True, ensure_ascii=False, allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def build_source_health(
    connections: Sequence[Mapping[str, Any]],
    runs: Sequence[Mapping[str, Any]],
    scans: Sequence[Mapping[str, Any]],
    *,
    site_memberships: Mapping[str, Sequence[str]] | None = None,
) -> tuple[dict[str, Any], ...]:
    """Use newest attempts and retain the last success for unchanged configuration.

    Dates describe collection operations, not an atomic infrastructure observation.
    A past success never means that a source is connected at the present moment.
    Site assignments describe the current workspace configuration.
    """
    runs_by_source: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    analysis_by_scan: dict[str, Any] = {}
    for run in runs:
        settings = run.get("settings", {})
        if not isinstance(settings, Mapping):
            continue
        source_id, scan_id = settings.get("source_id"), settings.get("cloud_scan_id")
        if isinstance(source_id, str):
            runs_by_source[source_id].append(run)
        if isinstance(scan_id, str):
            analysis_by_scan.setdefault(scan_id, run.get("state"))
    scans_by_platform: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for scan in scans:
        config = scan.get("config", {})
        if not isinstance(config, Mapping):
            continue
        platform = config.get("platform", "vmware")
        if isinstance(platform, str):
            scans_by_platform[platform].append(scan)

    rows = []
    for connection in connections:
        key, config = connection["provider"], connection["config"]
        scope = {"site_ids": tuple(site_memberships.get(key, ()))} if site_memberships is not None else {}
        if not isinstance(config, Mapping):
            rows.append({
                "source_id": key, "label": key, "platform": "unknown", "state": "invalid",
                "last_attempt": None, "last_success": None, "errors": 1,
                "analysis_state": "unknown",
                "warnings": 0,
                **scope,
            })
            continue
        attempts = []
        platform = key.removeprefix("cloud_ru_")
        source_runs = runs_by_source.get(key, [])
        fingerprint = configuration_fingerprint(config) if source_runs else None
        for run in source_runs:
            settings = run["settings"]
            collection_state = settings.get("source_collection_state", run.get("state"))
            attempts.append({
                "created_at": run.get("created_at"), "state": collection_state,
                "analysis_state": run.get("state"),
                "success": collection_state == "completed",
                "compatible": settings.get("source_config_fingerprint") == fingerprint,
                "errors": sum(item.get("status") in {"error", "unsupported"} for item in run.get("items", ())),
                "warnings": sum(len(item.get("collection_warnings", ())) for item in run.get("items", ())),
            })
        if key.startswith("ngfw:"):
            platform = key.split(":")[1]
        elif key.startswith("files:"):
            platform = "files"
        elif key.startswith("cloud_ru_"):
            for scan in scans_by_platform.get(platform, []):
                observed = scan.get("config", {})
                attempts.append({
                    "created_at": scan.get("created_at"), "state": scan.get("state"),
                    "analysis_state": analysis_by_scan.get(
                        scan["id"],
                        "not_executed" if platform == "vmware" else "not_supported",
                    ),
                    "success": scan.get("state") == "completed",
                    "compatible": {k: v for k, v in observed.items() if k != "platform"} == config,
                    "errors": len(scan.get("result", {}).get("errors", ())),
                    "warnings": len(scan.get("result", {}).get("integrity_warnings", ())),
                })
        latest = max(attempts, key=lambda row: row["created_at"] or "", default=None)
        last_success = max(
            (attempt for attempt in attempts if attempt["compatible"] and attempt["success"]),
            key=lambda row: row["created_at"] or "",
            default=None,
        )
        state = latest["state"] if latest else "never"
        if latest and not latest["compatible"]:
            state = "configuration_changed"
        if platform == "files" and config.get("enabled") is False:
            state = "disabled"
        rows.append({
            "source_id": key, "label": config.get("label") or config.get("site") or key,
            "platform": platform, "state": state,
            "last_attempt": latest["created_at"] if latest else None,
            "last_success": last_success["created_at"] if last_success else None,
            "errors": latest["errors"] if latest else 0,
            "analysis_state": latest.get("analysis_state", "unknown") if latest else "not_executed",
            "warnings": latest.get("warnings", 0) if latest else 0,
            **scope,
        })
    return tuple(rows)
