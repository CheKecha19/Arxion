"""Project observations from saved history; collection and check dates stay distinct."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from firewall_compliance.interfaces.desktop.check_presentation import check_execution_status
from firewall_compliance.interfaces.desktop.workspace_models import cloud_resource_key

# Match cloud_resource_key/dashboard identity without copying credentials or request options.
_CONNECTION_FIELDS = (
    "platform",
    "site",
    "tenant",
    "project_id",
    "region",
    "ecs_endpoint",
    "vpc_endpoint",
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _date(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() is None:
            return None
        return parsed.astimezone(UTC).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        return None


def _connection(config: dict[str, Any]) -> dict[str, Any]:
    value = {
        key: config.get(key) if isinstance(config.get(key), str) else None
        for key in _CONNECTION_FIELDS
    }
    value["platform"] = value["platform"] or "vmware"
    return value


def _vdc(inventory: dict[str, Any]) -> str | None:
    for field in ("vdcName", "vdc", "orgVdc", "ownerRef"):
        value = inventory.get(field)
        if isinstance(value, dict):
            value = value.get("name") or value.get("id")
        if isinstance(value, str) and value:
            return value
    return None


def _category(config: dict[str, Any]) -> str:
    vendor, platform = (
        str(config.get("vendor", "")).lower(),
        str(config.get("platform", "")).lower(),
    )
    if any(value in platform for value in ("usergate", "ideco", "ngfw", "cisco-asa", "cisco_asa")):
        return "ngfw"
    if vendor == "cisco" and platform in {"asa", "asa-9.16"}:
        return "ngfw"
    if vendor in {"hp-aruba", "hp_aruba", "hp-h3c", "aruba", "h3c", "hp"}:
        return "network"
    return "unclassified"


def _checked(report: dict[str, Any]) -> bool:
    checks = report.get("checks")
    if not isinstance(checks, list):
        return False
    for check in checks:
        if not isinstance(check, dict):
            continue
        limitations = check.get("limitations", [])
        if not isinstance(limitations, list) or any(
            not isinstance(value, dict) for value in limitations
        ):
            continue
        if check_execution_status({"status": "unknown", **check}) in {"complete", "partial"}:
            return True
    return False


def project_observations(
    runs: Sequence[dict[str, Any]], scans: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Accumulate identities without making reanalysis a new cloud collection.

    Unknown dates remain empty. Collection metadata is selected by its own capture
    date, while source.run_id/analysis_scan_id identify the latest analysis attempt.
    A failed attempt cannot erase the date of an earlier executed check.
    """
    observations: dict[str, dict[str, Any]] = {}
    collection_ranks: dict[str, tuple[bool, str, int, str]] = {}
    analysis_ranks: dict[str, tuple[bool, str, str, str]] = {}
    analyses: dict[str, dict[str, Any]] = {}
    last_checks: dict[str, str] = {}
    device_links: dict[str, tuple[tuple[bool, str, str, str], str]] = {}

    def observe(value: dict[str, Any], stamp: str | None, *, priority: int) -> None:
        identity = value["identity"]
        rank = (stamp is not None, stamp or "", priority, str(value["source"].get("scan_id", "")))
        existing = observations.get(identity)
        dates = {}
        for field in ("first_seen", "last_scan"):
            candidates = [date for date in ((existing or {}).get(field), value.get(field)) if date]
            dates[field] = (
                (min(candidates) if field == "first_seen" else max(candidates))
                if candidates
                else None
            )
        if existing is None or rank > collection_ranks[identity]:
            observations[identity] = value
            collection_ranks[identity] = rank
        observations[identity].update(dates)

    for scan in scans:
        config = _connection(_mapping(scan.get("config")))
        for index, record in enumerate(_mapping(scan.get("result")).get("records", [])):
            if not isinstance(record, dict):
                continue
            stamp = _date(record.get("collected_at")) or _date(scan.get("created_at"))
            inventory = _mapping(record.get("inventory"))
            resource_type = str(record.get("type", "unknown"))
            if resource_type == "vms" and str(inventory.get("isVAppTemplate", "false")).lower() in {
                "true",
                "1",
            }:
                resource_type = "vm_templates"
            observe(
                {
                    "identity": "cloud:"
                    + cloud_resource_key({**scan, "config": config}, record, index),
                    "name": str(record.get("name") or record.get("id") or "Облачный ресурс"),
                    "platform": "Cloud.ru " + str(config["platform"]).capitalize(),
                    "resource_type": resource_type,
                    "category": "cloud",
                    "first_seen": stamp,
                    "last_scan": stamp,
                    "last_check": None,
                    "vdc": _vdc(inventory),
                    "source": {
                        "kind": "cloud",
                        "scan_id": scan["id"],
                        "resource_id": record.get("id"),
                        "connection": config,
                        "record_index": index,
                    },
                },
                stamp,
                priority=1,
            )

    for run in runs:
        for item in run.get("items", []):
            report = _mapping(item.get("report"))
            parsed = _mapping(item.get("parse_result"))
            configuration = _mapping(parsed.get("configuration"))
            revision = _mapping(item.get("revision"))
            device = _mapping(revision.get("device"))
            origin = _mapping(item.get("cloud_origin"))
            if not report and not origin:
                continue
            stamp = (
                _date(report.get("analyzed_at"))
                or _date(run.get("finished_at"))
                or _date(run.get("created_at"))
            )
            if origin:
                config = _connection(_mapping(origin.get("connection")))
                resource_type = str(origin.get("resource_type") or "edges")
                index = origin.get("record_index", 0)
                if not isinstance(index, int) or index < 0:
                    index = 0
                identity = "cloud:" + cloud_resource_key(
                    {"config": config, "id": origin["scan_id"]},
                    {"type": resource_type, "id": origin.get("resource_id")},
                    index,
                )
                # Capture belongs to the analyzed collection, not the reanalysis.
                captured = _date(configuration.get("captured_at"))
                observe(
                    {
                        "identity": identity,
                        "name": str(
                            device.get("hostname")
                            or item.get("source_name")
                            or origin.get("resource_id")
                            or "Облачный ресурс"
                        ),
                        "platform": "Cloud.ru " + str(config["platform"]).capitalize(),
                        "resource_type": resource_type,
                        "category": "cloud",
                        "first_seen": captured,
                        "last_scan": captured,
                        "last_check": None,
                        "vdc": None,
                        "source": {
                            "kind": "cloud",
                            "scan_id": origin["scan_id"],
                            "resource_id": origin.get("resource_id"),
                            "connection": config,
                            "record_index": index,
                        },
                    },
                    captured,
                    priority=0,
                )
                analysis_source = {"analysis_scan_id": origin["scan_id"]}
            else:
                device_id = report.get("device_id") or configuration.get("device_id")
                if not isinstance(device_id, str) or not device_id:
                    continue
                identity = "device:" + device_id
                imported = (
                    _date(configuration.get("imported_at"))
                    or _date(revision.get("imported_at"))
                    or _date(run.get("finished_at"))
                    or _date(run.get("created_at"))
                )
                metadata = {**device, **configuration}
                observe(
                    {
                        "identity": identity,
                        "name": str(device.get("hostname") or device_id),
                        "platform": str(metadata.get("platform", "unknown")),
                        "resource_type": "device",
                        "category": _category(metadata),
                        "first_seen": _date(configuration.get("imported_at"))
                        or _date(revision.get("imported_at"))
                        or _date(run.get("created_at"))
                        or imported,
                        "last_scan": imported,
                        "last_check": None,
                        "vdc": None,
                        "source": {
                            "kind": "device",
                            "device_id": device_id,
                            "content_sha256": configuration.get("content_sha256"),
                        },
                    },
                    imported,
                    priority=1,
                )
                analysis_source = {}
            rank = (stamp is not None, stamp or "", str(run["id"]), str(item.get("id", "")))
            if identity not in analysis_ranks or rank > analysis_ranks[identity]:
                analysis_ranks[identity] = rank
                analyses[identity] = {
                    **analysis_source,
                    "run_id": run["id"],
                    "item_id": item.get("id"),
                }
            device_id = report.get("device_id")
            if (
                isinstance(device_id, str)
                and device_id
                and (identity not in device_links or rank > device_links[identity][0])
            ):
                device_links[identity] = rank, device_id
            if _checked(report) and stamp:
                last_checks[identity] = max(last_checks.get(identity, stamp), stamp)

    for identity, value in observations.items():
        value["source"].update(analyses.get(identity, {}))
        if identity in device_links:
            value["source"]["device_id"] = device_links[identity][1]
        value["last_check"] = last_checks.get(identity)
    return list(observations.values())
