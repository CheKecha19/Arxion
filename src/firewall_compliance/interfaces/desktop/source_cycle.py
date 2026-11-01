"""Configured-source cycle over existing scan/run history, without Qt objects."""

from __future__ import annotations

import json
from hashlib import sha256
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Event
from typing import Any

from firewall_compliance.application.inspection_cycle import CycleProgress, CycleSettings
from firewall_compliance.application.source_health import configuration_fingerprint
from firewall_compliance.devices.cloud.cloud_ru.public_client import (
    PLATFORM_RESOURCES, PUBLIC_DATA, AdvancedClient, AdvancedConfig,
    CloudCredentials, EvolutionClient, EvolutionConfig, PublicSelection,
)
from firewall_compliance.devices.cloud.cloud_ru.vmware.client import (
    DATA_TYPES, RESOURCE_TYPES, ScanSelection, VMwareClient, VMwareConfig,
)
from firewall_compliance.interfaces.desktop.cloud_analysis import analyze_saved_vmware
from firewall_compliance.interfaces.desktop.cycle_backend import FileCycleInput, run_file_cycle
from firewall_compliance.interfaces.desktop.ngfw_sources import SavedNgfwSources, collect_saved_ngfw
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.profile_history import LegacyProfileHistory


@dataclass(frozen=True, slots=True)
class SourceManifest:
    source_id: str
    platform: str
    config_json: str
    resources: tuple[str, ...] = ()
    data: tuple[str, ...] = ()

    def config(self) -> dict[str, Any]:
        value = json.loads(self.config_json)
        if not isinstance(value, dict):
            raise ValueError("Source configuration must be an object")
        return value


@dataclass(frozen=True, slots=True)
class SourceCycleItem:
    source_id: str
    state: str
    scan_id: str | None = None
    run_id: str | None = None
    message: str = ""


@dataclass(frozen=True, slots=True)
class SourceCycleResult:
    items: tuple[SourceCycleItem, ...]

    @property
    def successful(self) -> bool:
        return bool(self.items) and all(item.state == "complete" for item in self.items)


def configured_sources(store: ProjectStore, project_id: str) -> tuple[SourceManifest, ...]:
    """Capture public configuration and last explicitly selected collection scope."""
    scans = store.list_cloud_scans(project_id)
    connections = store.list_source_connections(project_id)
    result = []
    for platform in ("vmware", "advanced", "evolution"):
        connection = next((row for row in connections if row["provider"] == "cloud_ru_" + platform), None)
        if connection is None:
            continue
        config = connection["config"]
        previous = next(
            (scan for scan in scans if scan["config"].get("platform", "vmware") == platform
             and {key: value for key, value in scan["config"].items() if key != "platform"} == config),
            None,
        )
        resources = tuple(RESOURCE_TYPES) if platform == "vmware" else PLATFORM_RESOURCES[platform]
        data = tuple(DATA_TYPES) if platform == "vmware" else tuple(PUBLIC_DATA)
        selection = previous["selection"] if previous is not None else {}
        result.append(SourceManifest(
            "cloud_ru_" + platform, platform, json.dumps(config, sort_keys=True, allow_nan=False),
            tuple(selection.get("resources", resources)), tuple(selection.get("data", data)),
        ))
    for row in connections:
        if not row["provider"].startswith("ngfw:"):
            continue
        parts = row["provider"].split(":")
        platform = parts[1] if len(parts) == 3 else "unsupported"
        result.append(SourceManifest(row["provider"], platform, json.dumps(row["config"], allow_nan=False)))
    return tuple(result)


def run_source_cycle(
    store: ProjectStore,
    project_id: str,
    sources: Sequence[SourceManifest],
    settings: Mapping[str, Any],
    *,
    files: Sequence[FileCycleInput] = (),
    cancel: Event | None = None,
    progress: Callable[[CycleProgress], None] | None = None,
    factories: Mapping[str, Callable[..., Any]] | None = None,
) -> SourceCycleResult:
    """Update configured sources serially, retaining independent errors and scans.

    Cloud public platforms remain inventory-only. NGFW snapshots are unique local
    files and use the same file-analysis cycle. Call only in a worker. A caller
    must prevent manual/plan cycles from collecting these same sources together.
    """
    captured = CycleSettings.capture(settings)
    LegacyProfileHistory(store.path).initialize()
    options = captured.values()
    manifest = tuple(sources)
    if len({source.source_id for source in manifest}) != len(manifest):
        raise ValueError("Duplicate source in collection manifest")
    clients: dict[str, Callable[..., Any]] = {
        "vmware": VMwareClient, "advanced": AdvancedClient, "evolution": EvolutionClient
    }
    clients.update(factories or {})
    stop = cancel if cancel is not None else Event()
    emit = progress or (lambda _event: None)
    outcomes = []
    total = len(manifest) + bool(files)
    for index, source in enumerate(manifest):
        emit(CycleProgress("collection", index, total, source.source_id))
        if stop.is_set():
            cancelled_run = store.create_run(project_id, settings=options)
            store.record_cancelled(cancelled_run, Path(source.source_id))
            store.finish_run(cancelled_run, "cancelled")
            outcomes.append(SourceCycleItem(
                source.source_id, "cancelled", run_id=cancelled_run, message="Отменено до получения данных"
            ))
            continue
        scan_id = None
        failure_run = None
        try:
            if source.platform in {"usergate", "ideco"}:
                current = SavedNgfwSources(store).get(project_id, source.source_id)
                if current is None or current.model_dump(mode="json") != source.config():
                    raise ValueError("Source configuration changed")
                path = collect_saved_ngfw(
                    store, project_id, source.source_id,
                    store.path.parent / "collected" / sha256(project_id.encode()).hexdigest()[:24],
                    stop.is_set,
                )
                result = run_file_cycle(
                    store, project_id, (FileCycleInput(path),), options, cancel=stop,
                    source_reference=source.source_id,
                    source_fingerprint=configuration_fingerprint(source.config()),
                )
                outcomes.append(SourceCycleItem(source.source_id, result.outcome.state, run_id=result.run_id))
                continue
            platform = source.platform
            if platform not in clients:
                raise ValueError("Unsupported source platform")
            config = source.config()
            current = (
                store.get_vmware_integration(project_id) if platform == "vmware"
                else store.get_public_cloud_integration(project_id, platform)
            )
            if config != current:
                raise ValueError("Source configuration changed")
            if platform == "vmware":
                selection = ScanSelection(source.resources, source.data)
                client = clients[platform](
                    VMwareConfig(**config), store.get_vmware_token(project_id), cancel=stop
                )
            else:
                selection = PublicSelection(source.resources, source.data)
                configuration = AdvancedConfig if platform == "advanced" else EvolutionConfig
                client = clients[platform](
                    configuration(**config),
                    CloudCredentials(**store.get_public_cloud_credentials(project_id, platform)),
                    cancel=stop,
                )
            scan_id = store.create_cloud_scan(
                project_id, asdict(selection), {"platform": platform, **config}
            )
            payload = asdict(client.scan(selection))
        except Exception:
            message = "Сбор источника не завершён. Проверьте настройки, доступность и права API."
            if scan_id is not None:
                store.finish_cloud_scan(scan_id, {
                    "state": "cancelled" if stop.is_set() else "failed",
                    "records": [], "requests": [], "errors": [{"resource": source.source_id, "message": message}],
                })
            else:
                try:
                    fingerprint = configuration_fingerprint(source.config())
                except (ValueError, TypeError):
                    fingerprint = None
                failure_run = store.create_run(project_id, settings={
                    **options, "source_id": source.source_id,
                    "source_config_fingerprint": fingerprint,
                    "source_collection_state": "cancelled" if stop.is_set() else "failed",
                })
                store.record_error(failure_run, Path(source.source_id), message)
                store.finish_run(failure_run, "cancelled" if stop.is_set() else "interrupted")
            outcomes.append(SourceCycleItem(
                source.source_id, "cancelled" if stop.is_set() else "failed", scan_id=scan_id,
                run_id=failure_run, message=message,
            ))
            continue
        store.finish_cloud_scan(scan_id, payload)
        state = {"completed": "complete", "partial": "partial", "cancelled": "cancelled"}.get(
            payload.get("state"), "failed"
        )
        run_id = None
        message = "Собран инвентарь; проверка правил этой платформы не поддержана."
        if platform == "vmware" and state in {"complete", "partial"} and not stop.is_set():
            scan = next(item for item in store.list_cloud_scans(project_id) if item["id"] == scan_id)
            emit(CycleProgress("analysis", index, total, source.source_id))
            try:
                enabled = options.get("enabled_check_ids")
                if enabled is not None and not any(key.startswith("FW-") for key in enabled):
                    reports = []
                    message = "Сбор сохранён; проверки FW выключены в выбранном профиле."
                else:
                    reports = analyze_saved_vmware(scan, options, stop)
            except Exception:
                reports = []
                message = "Сбор сохранён, но проверка правил не завершена."
            if stop.is_set():
                state, message = "cancelled", "Сбор сохранён; проверка отменена."
            elif reports:
                run_id = store.save_cloud_analysis(scan_id, reports, options)
                if any(item.get("status") != "complete" for item in reports):
                    state = "partial"
                message = "Сбор и проверка завершены в поддержанной области Edge Firewall."
            else:
                state = "partial"
                if not message.startswith("Сбор сохранён"):
                    message = "Сбор сохранён; проверяемые правила Edge Firewall не получены."
                run_id = store.create_run(project_id, settings={**options, "cloud_scan_id": scan_id})
                store.record_error(run_id, Path(source.source_id), message)
                store.finish_run(run_id, "interrupted")
        outcomes.append(SourceCycleItem(source.source_id, state, scan_id, run_id, message))
    if files:
        emit(CycleProgress("analysis", len(manifest), total, "files"))
        result = run_file_cycle(store, project_id, files, options, cancel=stop)
        outcomes.append(SourceCycleItem("files", result.outcome.state, run_id=result.run_id))
    emit(CycleProgress("finished", total, total))
    return SourceCycleResult(tuple(outcomes))
