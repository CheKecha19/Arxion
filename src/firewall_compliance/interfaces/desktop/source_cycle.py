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
from firewall_compliance.application.collection_integrity import count_drop_warning
from firewall_compliance.application.workspace_profile import ProfileVersion, analysis_settings
from firewall_compliance.devices.cloud.cloud_ru.public_client import (
    PLATFORM_RESOURCES, PUBLIC_DATA, AdvancedClient, AdvancedConfig,
    CloudCredentials, EvolutionClient, EvolutionConfig, PublicSelection,
)
from firewall_compliance.devices.cloud.cloud_ru.vmware.client import (
    DATA_TYPES, RESOURCE_TYPES, ScanSelection, VMwareClient, VMwareConfig,
)
from firewall_compliance.interfaces.desktop.cloud_analysis import analyze_saved_vmware
from firewall_compliance.interfaces.desktop.cycle_backend import FileCycleInput, run_file_cycle
from firewall_compliance.interfaces.desktop.file_sources import (
    FILE_SOURCE_PREFIX, SavedFileSources, default_file_device_id, file_path_key,
)
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
    site_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            raise ValueError("Source ID is required")
        if not isinstance(self.config_json, str):
            raise TypeError("Configuration must be serialized JSON")
        for name in ("resources", "data", "site_ids"):
            values = getattr(self, name)
            if isinstance(values, (str, bytes)):
                raise TypeError("Manifest selections must be collections")
            values = tuple(values)
            if any(not isinstance(value, str) or not value for value in values):
                raise ValueError("Manifest selections must contain identifiers")
            object.__setattr__(self, name, tuple(dict.fromkeys(values)))

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
    warning_count: int = 0


@dataclass(frozen=True, slots=True)
class SourceCycleResult:
    items: tuple[SourceCycleItem, ...]

    @property
    def successful(self) -> bool:
        return bool(self.items) and all(item.state == "complete" for item in self.items)


def configured_sources(store: ProjectStore, project_id: str) -> tuple[SourceManifest, ...]:
    """Capture public configuration and last explicitly selected collection scope."""
    scans = store.list_cloud_scan_headers(project_id)
    connections = store.list_source_connections(project_id)
    site_memberships = store.workspace_metadata.source_sites(project_id)
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
            site_memberships.get("cloud_ru_" + platform, ()),
        ))
    for row in connections:
        key = row["provider"]
        if key.startswith(FILE_SOURCE_PREFIX):
            config = row["config"]
            if isinstance(config, dict) and config.get("enabled") is False:
                continue
            result.append(SourceManifest(
                key, "files", json.dumps(config, allow_nan=False),
                site_ids=site_memberships.get(key, ()),
            ))
            continue
        if not key.startswith("ngfw:"):
            continue
        parts = row["provider"].split(":")
        platform = parts[1] if len(parts) == 3 else "unsupported"
        result.append(SourceManifest(
            row["provider"], platform, json.dumps(row["config"], allow_nan=False),
            site_ids=site_memberships.get(row["provider"], ()),
        ))
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
    options = captured.values()
    ProfileVersion.from_settings(project_id, 1, analysis_settings(options))
    for key in ("configuration_complete", "include_fragments"):
        if key in options and type(options[key]) is not bool:
            raise ValueError("Параметры полноты и фрагментов должны быть логическими")
    LegacyProfileHistory(store.path).initialize()
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
    # Reuse an association from a staged row when the saved set has no
    # explicit binding. The ad hoc batch excludes files already processed by
    # saved sources, while each saved source retains its own run provenance.
    staged = {file_path_key(item.path): item for item in files}
    consumed: set[str] = set()
    total = len(manifest) + bool(files)
    for index, source in enumerate(manifest):
        emit(CycleProgress("collection", index, total, source.source_id))
        if stop.is_set():
            cancelled_settings = dict(options)
            if source.platform == "files":
                try:
                    fingerprint = configuration_fingerprint(source.config())
                except (ValueError, TypeError):
                    fingerprint = None
                cancelled_settings.update(
                    source_id=source.source_id, source_collection_state="cancelled",
                    source_config_fingerprint=fingerprint,
                    source_site_ids=list(source.site_ids),
                )
            cancelled_run = store.create_run(project_id, settings=cancelled_settings)
            store.record_cancelled(cancelled_run, Path(source.source_id))
            store.finish_run(cancelled_run, "cancelled")
            outcomes.append(SourceCycleItem(
                source.source_id, "cancelled", run_id=cancelled_run, message="Отменено до получения данных"
            ))
            continue
        scan_id = None
        failure_run = None
        try:
            if source.platform == "files":
                config = SavedFileSources.from_config(source.source_id, source.config())
                current = SavedFileSources(store).get(project_id, source.source_id)
                if config != current or not config.enabled:
                    raise ValueError("Файловый источник изменился")
                paths = config.paths_for_run()
                if not paths:
                    raise ValueError("В папке нет файлов поддерживаемых форматов")
                site_id = source.site_ids[0] if len(source.site_ids) == 1 else None
                explicit = {file_path_key(Path(name)): device for name, device in config.device_ids.items()}
                previous = SavedFileSources(store).previous_devices(project_id, config)
                planned = []
                for path in paths:
                    key = file_path_key(path)
                    staged_item = staged.get(key)
                    planned.append(FileCycleInput(
                        path, explicit.get(key)
                        or (staged_item.device_id if staged_item else None)
                        or previous.get(key) or default_file_device_id(path),
                        expected_sha256=staged_item.expected_sha256 if staged_item else None,
                        site_id=(staged_item.site_id if staged_item else None) or site_id,
                    ))
                inputs = tuple(planned)
                result = run_file_cycle(
                    store, project_id, inputs, options, cancel=stop,
                    progress=lambda event: emit(CycleProgress(
                        event.stage, event.completed, event.total, source.source_id,
                    )),
                    source_reference=source.source_id,
                    source_fingerprint=configuration_fingerprint(source.config()),
                    source_sites=source.site_ids,
                )
                consumed.update(file_path_key(path) for path in paths)
                outcomes.append(SourceCycleItem(
                    source.source_id, result.outcome.state, run_id=result.run_id,
                    warning_count=len(result.warnings),
                ))
                continue
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
                    store, project_id, (FileCycleInput(
                        path, device_id=source.source_id,
                        site_id=source.site_ids[0] if len(source.site_ids) == 1 else None
                    ),), options, cancel=stop,
                    progress=lambda event: emit(CycleProgress(
                        event.stage, event.completed, event.total, source.source_id
                    )),
                    source_reference=source.source_id,
                    source_fingerprint=configuration_fingerprint(source.config()),
                    source_sites=source.site_ids,
                )
                outcomes.append(SourceCycleItem(
                    source.source_id, result.outcome.state, run_id=result.run_id,
                    warning_count=len(result.warnings),
                ))
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
                project_id, {**asdict(selection), "workspace_site_ids": list(source.site_ids)},
                {"platform": platform, **config},
            )
            payload = asdict(client.scan(selection))
        except Exception:
            message = (
                "Файловый источник не прочитан. Проверьте список файлов, путь к папке и доступ."
                if source.platform == "files"
                else "Сбор источника не завершён. Проверьте настройки, доступность и права API."
            )
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
                    "source_site_ids": list(source.site_ids),
                })
                store.record_error(failure_run, Path(source.source_id), message)
                store.finish_run(failure_run, "cancelled" if stop.is_set() else "interrupted")
            outcomes.append(SourceCycleItem(
                source.source_id, "cancelled" if stop.is_set() else "failed", scan_id=scan_id,
                run_id=failure_run, message=message,
            ))
            continue
        previous_scan = next((scan for scan in store.list_cloud_scan_headers(project_id)
            if scan["id"] != scan_id and scan.get("state") == "completed"
            and scan.get("config") == {"platform": platform, **config}
            and set(scan.get("selection", {}).get("resources", ())) == set(source.resources)
            and set(scan.get("selection", {}).get("data", ())) == set(source.data)
        ), None)
        warning = None
        if previous_scan is not None and payload.get("state") in {"completed", "partial"}:
            previous_count = store.cloud_scan_record_count(project_id, previous_scan["id"])
            if previous_count is not None:
                warning = count_drop_warning(
                    previous_count, len(payload.get("records", ())),
                    threshold_percent=options.get("inventory_count_drop_percent", 30),
                    before_reference=previous_scan["id"], unit="ресурсы",
                )
        if warning is not None:
            payload["integrity_warnings"] = [{"code": warning.code, "message": warning.message}]
        store.finish_cloud_scan(scan_id, payload)
        state = {"completed": "complete", "partial": "partial", "cancelled": "cancelled"}.get(
            payload.get("state"), "failed"
        )
        run_id = None
        message = "Результат сбора сохранён."
        if platform in {"advanced", "evolution"} and state in {"complete", "partial"}:
            message = "Сбор сохранён. Полученные политики групп безопасности можно сверить в матрице доступа."
        if platform == "vmware" and state in {"complete", "partial"} and not stop.is_set():
            emit(CycleProgress("analysis", index, total, source.source_id))
            try:
                scan = store.get_cloud_scan(project_id, scan_id)
                if scan is None:
                    raise ValueError("Исходный облачный сбор не найден")
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
                run_id = store.save_cloud_analysis(
                    scan_id, reports, {**options, "source_site_ids": list(source.site_ids)}
                )
                if len(source.site_ids) == 1:
                    metadata = store.workspace_metadata
                    assigned = metadata.device_sites(project_id)
                    device_ids = tuple(dict.fromkeys(
                        item["report"]["device_id"] for item in reports
                        if item.get("report") and item["report"]["device_id"] not in assigned
                    ))
                    if device_ids:
                        metadata.assign_devices(project_id, device_ids, source.site_ids[0])
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
        outcomes.append(SourceCycleItem(
            source.source_id, state, scan_id, run_id, message,
            warning_count=1 if warning is not None else 0,
        ))
    remaining = tuple(item for item in files if file_path_key(item.path) not in consumed)
    if remaining:
        staged_positions = {file_path_key(item.path): index for index, item in enumerate(files)}
        emit(CycleProgress("analysis", len(manifest), total, "files"))

        def report_file_progress(event: CycleProgress) -> None:
            identifier = event.item_id or event.source_id
            position = (
                staged_positions[file_path_key(remaining[int(identifier)].path)]
                if identifier is not None and identifier.isdecimal() else None
            )
            emit(CycleProgress(
                event.stage, event.completed, event.total, "files",
                str(position) if position is not None else None,
            ))

        result = run_file_cycle(
            store, project_id, remaining, options, cancel=stop,
            progress=report_file_progress,
        )
        outcomes.append(SourceCycleItem(
            "files", result.outcome.state, run_id=result.run_id, warning_count=len(result.warnings)
        ))
    emit(CycleProgress("finished", total, total))
    return SourceCycleResult(tuple(outcomes))


def retry_task_inputs(
    store: ProjectStore, project_id: str, kind: str, task_id: str,
) -> tuple[tuple[SourceManifest, ...], tuple[FileCycleInput, ...]]:
    """Plan a new attempt; never overwrite the selected history entry."""
    sources = configured_sources(store, project_id)
    if kind == "scan":
        scan = store.get_cloud_scan(project_id, task_id)
        if scan is None:
            raise ValueError("Сбор не найден в выбранном проекте")
        if scan["state"] == "running" or (
            scan["state"] == "completed" and not scan.get("result", {}).get("integrity_warnings")
            and not scan.get("result", {}).get("errors")
        ):
            raise ValueError("В сборе нет ошибок или предупреждений для повтора")
        source_key = "cloud_ru_" + scan["config"].get("platform", "vmware")
    elif kind == "run":
        run = store.get_run(task_id)
        if run["project_id"] != project_id or run["state"] == "running":
            raise ValueError("Выберите завершённую задачу этого проекта")
        if not any(item.get("status") in {"error", "unsupported", "cancelled", "canceled", "partial"} for item in run["items"]):
            raise ValueError("Неуспешных элементов для повтора нет")
        source_key = run.get("settings", {}).get("source_id")
        if not source_key and run.get("settings", {}).get("cloud_scan_id"):
            source_key = "cloud_ru_vmware"
        if not source_key or source_key.startswith(FILE_SOURCE_PREFIX):
            files = []
            assignments = store.workspace_metadata.device_sites(project_id)
            settings = run.get("settings", {})
            saved_devices = settings.get("workspace_input_devices", {})
            saved_sites = settings.get("workspace_input_sites", {})
            for item in run["items"]:
                if item.get("status") not in {"error", "unsupported", "cancelled", "canceled", "partial"}:
                    continue
                path = Path(item["path"])
                if source_key and item.get("path") == source_key:
                    # Enumeration failed before there were individual paths. A
                    # retry must expand the configured folder again.
                    selected = tuple(source for source in sources if source.source_id == source_key)
                    if not selected:
                        raise ValueError("Включённый файловый источник для повтора отсутствует")
                    return selected, ()
                device_id = (
                    (item.get("report") or {}).get("device_id") or saved_devices.get(str(path))
                    or store.suggest_device(project_id, path.name)
                )
                files.append(FileCycleInput(
                    path, device_id, site_id=(assignments.get(device_id) if device_id is not None else None)
                    or saved_sites.get(str(path)),
                ))
            return (), tuple(files)
    else:
        raise ValueError("Неподдерживаемый тип задачи")
    selected = tuple(source for source in sources if source.source_id == source_key)
    if not selected:
        raise ValueError("Сохранённое подключение для повтора отсутствует")
    return selected, ()
