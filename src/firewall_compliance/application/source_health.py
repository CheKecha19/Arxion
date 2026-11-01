"""Source attempt history, independent of live connectivity or safety claims."""

from __future__ import annotations

import hashlib
import json
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
) -> tuple[dict[str, Any], ...]:
    """Use newest attempts and retain the last success for unchanged configuration.

    Dates describe collection operations, not an atomic infrastructure observation.
    A past success never means that a source is connected at the present moment.
    """
    rows = []
    for connection in connections:
        key, config = connection["provider"], connection["config"]
        if not isinstance(config, Mapping):
            rows.append({
                "source_id": key, "label": key, "platform": "unknown", "state": "invalid",
                "last_attempt": None, "last_success": None, "errors": 1,
                "analysis_state": "unknown",
                "warnings": 0,
            })
            continue
        attempts = []
        platform = key.removeprefix("cloud_ru_")
        for run in runs:
            if run.get("settings", {}).get("source_id") == key:
                collection_state = run["settings"].get("source_collection_state", run.get("state"))
                attempts.append({
                    "created_at": run.get("created_at"), "state": collection_state,
                    "analysis_state": run.get("state"),
                    "success": collection_state == "completed",
                    "compatible": run["settings"].get("source_config_fingerprint")
                    == configuration_fingerprint(config),
                    "errors": sum(item.get("status") in {"error", "unsupported"} for item in run.get("items", ())),
                    "warnings": sum(len(item.get("collection_warnings", ())) for item in run.get("items", ())),
                })
        if key.startswith("ngfw:"):
            platform = key.split(":")[1]
        elif key.startswith("cloud_ru_"):
            for scan in scans:
                observed = scan.get("config", {})
                if observed.get("platform", "vmware") != platform:
                    continue
                attempts.append({
                    "created_at": scan.get("created_at"), "state": scan.get("state"),
                    "analysis_state": next(
                        (run.get("state") for run in runs if run.get("settings", {}).get("cloud_scan_id") == scan["id"]),
                        "not_executed" if platform == "vmware" else "not_supported",
                    ),
                    "success": scan.get("state") == "completed",
                    "compatible": {k: v for k, v in observed.items() if k != "platform"} == config,
                    "errors": len(scan.get("result", {}).get("errors", ())),
                    "warnings": len(scan.get("result", {}).get("integrity_warnings", ())),
                })
        attempts.sort(key=lambda row: row["created_at"] or "", reverse=True)
        latest = attempts[0] if attempts else None
        compatible = [attempt for attempt in attempts if attempt["compatible"]]
        last_success = next((attempt for attempt in compatible if attempt["success"]), None)
        state = latest["state"] if latest else "never"
        if latest and not latest["compatible"]:
            state = "configuration_changed"
        rows.append({
            "source_id": key, "label": config.get("label") or config.get("site") or key,
            "platform": platform, "state": state,
            "last_attempt": latest["created_at"] if latest else None,
            "last_success": last_success["created_at"] if last_success else None,
            "errors": latest["errors"] if latest else 0,
            "analysis_state": latest.get("analysis_state", "unknown") if latest else "not_executed",
            "warnings": latest.get("warnings", 0) if latest else 0,
        })
    return tuple(rows)
