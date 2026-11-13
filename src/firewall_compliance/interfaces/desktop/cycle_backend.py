"""Desktop persistence adapter for the headless inspection cycle; no Qt imports."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from threading import Event
from typing import Any

from firewall_compliance.application.inspection_cycle import (
    Cancellation,
    CycleFailure,
    CycleInput,
    CycleOutcome,
    CycleProgress,
    CycleSettings,
    ItemOutcome,
    SourceOutcome,
    SourcePlan,
    run_inspection_cycle,
)
from firewall_compliance.application.workspace_profile import (
    ANALYSIS_SETTING_KEYS,
    ProfileVersion,
    analysis_settings,
)
from firewall_compliance.application.collection_integrity import count_drop_warning
from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.domain.policy_scope import PolicyScopeProfile
from firewall_compliance.interfaces.desktop.backend import (
    AnalysisSession,
    analyze_file,
    selected_checks,
)
from firewall_compliance.interfaces.desktop.file_sources import FILE_SOURCE_PREFIX
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.profile_history import LegacyProfileHistory
from firewall_compliance.parsers import ParseFailure


@dataclass(frozen=True, slots=True)
class FileCycleInput:
    path: Path
    device_id: str | None = None
    expected_sha256: str | None = None
    site_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", Path(self.path))
        if self.site_id is not None and (not isinstance(self.site_id, str) or not self.site_id.strip()):
            raise ValueError("site_id must be nonempty when supplied")
        if self.device_id is not None and (
            not isinstance(self.device_id, str) or not self.device_id.strip()
        ):
            raise ValueError("device_id must be nonempty when provided")
        if self.expected_sha256 is not None:
            digest = self.expected_sha256
            if not isinstance(digest, str) or len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")


@dataclass(frozen=True, slots=True)
class FileCycleResult:
    run_id: str
    outcome: CycleOutcome[AnalysisSession | ParseFailure]
    sessions: tuple[tuple[str, AnalysisSession], ...]
    warnings: tuple[str, ...] = ()


def saved_file_inputs(run: Mapping[str, Any]) -> tuple[FileCycleInput, ...]:
    """Build an explicit replay manifest, never silently treating old paths as new data.

    The collector later verifies raw bytes against the saved hash. Changed files
    must instead be supplied as new explicit FileCycleInput values without an old
    expected hash. Missing paths/hashes are rejected, not skipped as successful.
    """
    result = []
    for item in run.get("items", ()):
        path, digest = item.get("path"), item.get("content_sha256")
        if not isinstance(path, str) or not path or not isinstance(digest, str):
            raise ValueError("Saved input has no replayable path/hash")
        report = item.get("report") or {}
        result.append(FileCycleInput(Path(path), report.get("device_id"), digest))
    return tuple(result)


def _digest(path: Path) -> str:
    before = path.stat()
    value = sha256(path.read_bytes()).hexdigest()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise CycleFailure("SOURCE_CHANGED")
    return value


def run_file_cycle(
    store: ProjectStore,
    project_id: str,
    inputs: Sequence[FileCycleInput],
    settings: Mapping[str, Any],
    *,
    progress: Callable[[CycleProgress], None] | None = None,
    cancel: Cancellation | None = None,
    source_reference: str | None = None,
    source_fingerprint: str | None = None,
    source_sites: tuple[str, ...] = (),
    started: Callable[[str], None] | None = None,
) -> FileCycleResult:
    """Collect, analyze and save a file batch in a worker, preserving every failure.

    No cloud collector is implied by this adapter. Previously successful results
    remain unchanged. A failed/partial cycle uses the existing interrupted run
    state; its item statuses retain complete/partial/error distinctions. The
    optional started callback receives the saved run ID in the worker before
    collection; UI consumers must enqueue it rather than access widgets.
    """
    if not inputs:
        raise ValueError("Select at least one input")
    manifest = tuple(inputs)
    history_counts = getattr(store, "project_rule_count_history", None)
    previous_counts: dict[tuple[str, str, str], tuple[int, str]] = {}
    if callable(history_counts):
        previous_counts = history_counts(
            project_id, source_id=source_reference, source_fingerprint=source_fingerprint,
        )
    else:
        for previous_run in store.project_history(project_id):
            if source_reference is not None and (
                previous_run.get("settings", {}).get("source_id") != source_reference
                or previous_run.get("settings", {}).get("source_config_fingerprint") != source_fingerprint
            ):
                continue
            for previous_item in reversed(previous_run["items"]):
                report = previous_item.get("report") or {}
                parsed = previous_item.get("parse_result") or {}
                rules = parsed.get("rules")
                if previous_item.get("status") == "complete" and report and isinstance(rules, list):
                    key = (
                        str(report["device_id"]), str(report["parser_version"]),
                        str(parsed.get("configuration", {}).get("platform")),
                    )
                    previous_counts.setdefault(key, (len(rules), previous_item["id"]))
    if any(not isinstance(item, FileCycleInput) for item in manifest):
        raise TypeError("inputs must contain FileCycleInput values")
    captured = CycleSettings.capture(settings)
    values = captured.values()
    if set(values) - ANALYSIS_SETTING_KEYS - {
        "configuration_complete", "include_fragments",
        "configuration_view", "configuration_node_path",
    }:
        raise ValueError("Only analysis settings may be captured by a file cycle")
    profile = ProfileVersion.from_settings(project_id, 1, analysis_settings(values))
    options = profile.settings()
    management = (
        ManagementProfile.model_validate(options["management_profile"])
        if options.get("management_profile") is not None else None
    )
    exposure = (
        PolicyExposureProfile.model_validate(options["policy_exposure_profile"])
        if options.get("policy_exposure_profile") is not None else None
    )
    scope = (
        PolicyScopeProfile.model_validate(options["policy_scope_profile"])
        if options.get("policy_scope_profile") is not None else None
    )
    enabled_values = options.get("enabled_check_ids")
    enabled = tuple(enabled_values) if enabled_values is not None else None
    selected_checks(enabled, management, exposure, scope)
    if type(values.get("configuration_complete", False)) is not bool:
        raise ValueError("configuration_complete must be boolean")
    if values.get("configuration_view", "unknown") not in {
        "unknown", "local", "effective", "effective_detail", "pending",
    }:
        raise ValueError("unknown configuration view")
    node_path = values.get("configuration_node_path")
    if node_path is not None and (not isinstance(node_path, str) or not node_path.strip()):
        raise ValueError("configuration node path must be nonempty")
    if "include_fragments" in values and type(values["include_fragments"]) is not bool:
        raise ValueError("include_fragments must be boolean")
    run_settings = dict(values)
    if any(item.site_id is not None for item in manifest):
        run_settings["workspace_input_sites"] = {
            str(item.path): item.site_id for item in manifest if item.site_id is not None
        }
    saved_files = source_reference is not None and source_reference.startswith(FILE_SOURCE_PREFIX)
    if saved_files:
        run_settings["workspace_input_devices"] = {
            str(item.path): item.device_id for item in manifest if item.device_id is not None
        }
    if source_reference is not None:
        run_settings["source_id"] = source_reference
        run_settings["source_config_fingerprint"] = source_fingerprint
        run_settings["source_collection_state"] = "running" if saved_files else "completed"
        run_settings["source_site_ids"] = list(source_sites)
    LegacyProfileHistory(store.path).initialize()
    if any(item.site_id is not None for item in manifest):
        store.workspace_metadata.initialize()
        available_sites = {site["id"] for site in store.workspace_metadata.list_sites()}
        if any(item.site_id is not None and item.site_id not in available_sites for item in manifest):
            raise ValueError("Площадка подготовленных данных больше не существует")
    run_id = store.create_run(project_id, settings=run_settings)
    cancellation = cancel if cancel is not None else Event()
    collected_hashes: dict[str, str] = {}
    input_by_id = {str(index): item for index, item in enumerate(manifest)}
    sessions: list[tuple[str, AnalysisSession]] = []
    warnings: list[str] = []

    def collect(identifier: str) -> tuple[CycleInput[FileCycleInput], ...]:
        item = input_by_id[identifier]
        digest = _digest(item.path)
        if item.expected_sha256 is not None and digest != item.expected_sha256:
            raise CycleFailure("SOURCE_HASH_MISMATCH")
        collected_hashes[identifier] = digest
        return (CycleInput(identifier, item),)

    def analyze(
        source_id: str, item: CycleInput[FileCycleInput], _settings: CycleSettings
    ) -> ItemOutcome[AnalysisSession | ParseFailure]:
        outcome = analyze_file(
            item.value.path,
            device_id=item.value.device_id,
            require_logging=options.get("require_logging", True),
            require_comments=options.get("require_comments", True),
            enabled_check_ids=enabled,
            management_profile=management,
            policy_exposure_profile=exposure,
            policy_scope_profile=scope,
            configuration_complete=values.get("configuration_complete", False),
            configuration_view=values.get("configuration_view", "unknown"),
            configuration_node_path=values.get("configuration_node_path"),
        )
        analyzed_hash = (
            outcome.source.content_sha256
            if isinstance(outcome, AnalysisSession) else outcome.content_sha256
        )
        if analyzed_hash != collected_hashes[source_id] or _digest(item.value.path) != analyzed_hash:
            raise CycleFailure("SOURCE_CHANGED")
        if isinstance(outcome, ParseFailure):
            return ItemOutcome(source_id, item.input_id, "failed", outcome, "PARSE_FAILURE")
        report = outcome.report
        partial = (
            bool(report.parse_errors or report.unsupported_constructs)
            or any(
                check.status.value == "partial"
                or any(limit.code == "CHECK_NOT_EXECUTED" for limit in check.limitations)
                for check in report.checks
            )
            or report.parse_coverage.coverage_ratio < 1
        )
        return ItemOutcome(
            source_id, item.input_id, "partial" if partial else "complete", outcome
        )

    def persist_source(outcome: SourceOutcome) -> None:
        item = input_by_id[outcome.source_id]
        if outcome.state == "failed":
            store.record_error(run_id, item.path, outcome.message)
        elif outcome.state == "cancelled":
            store.record_cancelled(run_id, item.path)

    def persist_item(outcome: ItemOutcome[AnalysisSession | ParseFailure]) -> None:
        item = input_by_id[outcome.input_id]
        if isinstance(outcome.value, AnalysisSession):
            device_id = outcome.value.report.device_id
            if item.site_id is not None and device_id not in store.workspace_metadata.device_sites(project_id):
                store.workspace_metadata.assign_device(project_id, device_id, item.site_id)
            report = outcome.value.report
            platform = outcome.value.parse_result.configuration.platform
            previous = previous_counts.get((
                str(report.device_id), report.parser_version, str(getattr(platform, "value", platform))
            ))
            warning = count_drop_warning(
                previous[0], len(outcome.value.parse_result.rules),
                threshold_percent=options.get("rule_count_drop_percent", 30),
                before_reference=previous[1], unit="правила",
            ) if previous else None
            messages = (warning.message,) if warning is not None else ()
            warnings.extend(messages)
            item_id = store.record_session(run_id, outcome.value, collection_warnings=messages)
            sessions.append((item_id, outcome.value))
        elif isinstance(outcome.value, ParseFailure):
            store.record_failure(run_id, item.path, outcome.value)
        elif outcome.state == "cancelled":
            store.record_cancelled(run_id, item.path)
        else:
            store.record_error(run_id, item.path, outcome.message)

    try:
        if started is not None:
            started(run_id)
        sources = tuple(
            SourcePlan(identifier, lambda identifier=identifier: collect(identifier))
            for identifier in input_by_id
        )
        outcome = run_inspection_cycle(
            sources, captured, analyze, cancel=cancellation, progress=progress,
            persist_item=persist_item, persist_source=persist_source,
        )
    except BaseException:
        if saved_files:
            store.finish_run(run_id, "interrupted", source_collection_state="failed")
        else:
            store.finish_run(run_id, "interrupted")
        raise
    state = (
        "cancelled" if outcome.state == "cancelled"
        else "completed" if outcome.state == "complete"
        else "interrupted"
    )
    if saved_files:
        collected = sum(item.state == "collected" for item in outcome.sources)
        collection_state = (
            "completed" if collected == len(manifest) else
            "cancelled" if cancellation.is_set() else
            "partial" if collected else "failed"
        )
        store.finish_run(run_id, state, source_collection_state=collection_state)
    else:
        store.finish_run(run_id, state)
    return FileCycleResult(run_id, outcome, tuple(sessions), tuple(warnings))
