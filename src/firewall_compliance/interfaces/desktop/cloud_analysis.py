"""Prepare ordinary persisted analysis items from a saved cloud collection."""

from __future__ import annotations

from threading import Event
from typing import Any

from firewall_compliance.analysis.firewall_assurance import analyze_firewall
from firewall_compliance.application.cloud_analysis import ADAPTER_VERSION, vmware_revision
from firewall_compliance.domain.assurance import CheckStatus
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.domain.policy_scope import PolicyScopeProfile
from firewall_compliance.interfaces.desktop.backend import selected_checks


def analyze_saved_vmware(
    scan: dict[str, Any], settings: dict[str, Any], cancel: Event
) -> list[dict[str, Any]]:
    if scan["config"].get("platform", "vmware") != "vmware":
        raise ValueError("Проверки поддержаны для VMware Edge Firewall.")
    enabled = settings.get("enabled_check_ids")
    checks = (
        selected_checks(
            tuple(key for key in enabled if key.startswith("FW-")),
            policy_exposure_profile=PolicyExposureProfile.model_validate(
                settings.get("policy_exposure_profile") or {}
            ),
            policy_scope_profile=PolicyScopeProfile.model_validate(
                settings.get("policy_scope_profile") or {}
            ),
        )
        if enabled is not None
        else None
    )
    items = []
    for index, record in enumerate(scan.get("result", {}).get("records", [])):
        if cancel.is_set():
            raise ValueError("Проверка облачных правил отменена.")
        if (
            not isinstance(record, dict)
            or record.get("type") != "edges"
            or not isinstance(record.get("data"), dict)
            or "firewall" not in record["data"]
        ):
            continue
        origin = {
            "scan_id": scan["id"],
            "record_index": index,
            "resource_id": str(record.get("id") or f"unknown-record-{index}"),
            "connection": scan["config"],
            "adapter_version": ADAPTER_VERSION,
            "scope": "Edge Firewall; NAT, DFW и эффективная достижимость не анализируются.",
        }
        try:
            revision = vmware_revision(scan, index)
        except (ValueError, KeyError, TypeError):
            items.append(
                {
                    "path": "",
                    "source_name": str(record.get("name") or origin["resource_id"]),
                    "content_sha256": "",
                    "status": "error",
                    "report": None,
                    "parse_result": None,
                    "revision": None,
                    "excerpts": [],
                    "diagnostics": [
                        {
                            "code": "VMWARE_NORMALIZATION_FAILED",
                            "message": "Не удалось нормализовать Firewall этого Edge Gateway; "
                            "проверки не выполнены. Исходный снимок сохранён.",
                        }
                    ],
                    "cloud_origin": origin,
                }
            )
            continue
        report = analyze_firewall(
            revision,
            checks=checks,
            require_logging=settings.get("require_logging", True),
            require_comments=settings.get("require_comments", True),
        )
        partial = bool(revision.parse_result.warnings or revision.parse_result.errors) or any(
            check.status == CheckStatus.PARTIAL for check in report.checks
        )
        items.append(
            {
                "path": "",
                "source_name": revision.parse_result.configuration.source_name,
                "content_sha256": revision.parse_result.configuration.content_sha256,
                "status": "partial" if partial else "complete",
                "report": report.model_dump(mode="json"),
                "parse_result": revision.parse_result.model_dump(mode="json"),
                "revision": revision.model_dump(mode="json"),
                "excerpts": [],
                "diagnostics": [
                    issue.model_dump(mode="json") for issue in revision.parse_result.warnings
                ],
                "cloud_origin": origin,
            }
        )
    if not items:
        raise ValueError(
            "В сборе нет правил VMware Edge Firewall. Выберите Edge Gateway и Firewall при сборе."
        )
    if cancel.is_set():
        raise ValueError("Проверка облачных правил отменена.")
    return items
