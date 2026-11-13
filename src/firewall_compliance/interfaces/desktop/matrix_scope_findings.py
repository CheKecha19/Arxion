"""Находки из точных снимков устройств, использованных в сравнении матрицы."""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from firewall_compliance.application.matrix_comparison import MatrixScopeChange
from firewall_compliance.application.matrix_scope_assessment import (
    SOURCE_FALLBACK_NOTE,
    MatrixScopeAssessment,
    MatrixScopeSource,
    matrix_scope_revision_checksum,
)
from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.project_store import ProjectStore
from firewall_compliance.interfaces.desktop.run_comparison import compare_saved_device_findings


@dataclass(frozen=True, slots=True)
class MatrixFindingSourcePair:
    before: MatrixScopeSource
    after: MatrixScopeSource
    limitations: tuple[str, ...]

    @property
    def label(self) -> str:
        source = self.after
        context = f" · {source.device_context}" if source.device_context else ""
        before_date, after_date = (item.captured_at.isoformat(timespec="seconds") for item in (self.before, source))
        identity = f" · {source.device_id}" if source.device_label != source.device_id else ""
        return f"{source.device_label}{identity} · {source.platform}{context} · {before_date} → {after_date}"


@dataclass(frozen=True, slots=True)
class MatrixFindingSources:
    pairs: dict[str, MatrixFindingSourcePair]
    by_requirement: dict[str, str]
    overview: tuple[str, ...]


def _identity(source: MatrixScopeSource) -> tuple[str, str, str | None]:
    return source.device_id, source.platform, source.device_context


def _origin(source: MatrixScopeSource) -> tuple[str | None, str | None, UUID]:
    return source.run_id, source.item_id, source.revision_id


def matrix_finding_sources(
    before: MatrixScopeAssessment, after: MatrixScopeAssessment, changes: Sequence[MatrixScopeChange],
) -> MatrixFindingSources:
    old = {source.revision_id: source for source in before.sources}
    new = {source.revision_id: source for source in after.sources}
    stale_revisions = []
    for result in (before, after):
        affected = {
            identifier for issue in result.diagnostics if issue.code == SOURCE_FALLBACK_NOTE
            for identifier in issue.requirement_ids
        }
        stale_revisions.append({
            row.revision_id for row in result.requirements if row.requirement_id in affected and row.revision_id is not None
        })
    exclusions: Counter[str] = Counter()
    pairs: dict[str, MatrixFindingSourcePair] = {}
    by_requirement: dict[str, str] = {}
    pair_keys: dict[tuple[UUID, UUID], str] = {}
    for change in changes:
        left_id = change.before.revision_id if change.before is not None else None
        right_id = change.after.revision_id if change.after is not None else None
        left = old.get(left_id) if left_id is not None else None
        right = new.get(right_id) if right_id is not None else None
        if left is None or right is None:
            exclusions["missing"] += 1
        elif _identity(left) != _identity(right):
            exclusions["different"] += 1
        elif not all(source.run_id and source.item_id for source in (left, right)):
            exclusions["direct"] += 1
        elif _origin(left) == _origin(right):
            exclusions["same"] += 1
        else:
            revisions = left.revision_id, right.revision_id
            if revisions not in pair_keys:
                key = str(len(pairs))
                pair_keys[revisions] = key
                limitations = tuple(
                    f"{label} · использован прежний снимок после более поздней неудачной попытки сбора."
                    for label, revision_id, stale in zip(("Было", "Стало"), revisions, stale_revisions, strict=True)
                    if revision_id in stale
                )
                pairs[key] = MatrixFindingSourcePair(left, right, limitations)
            by_requirement[change.requirement_id] = pair_keys[revisions]
    labels = {
        "missing": "Нет пары однозначных источников",
        "different": "Выбраны разные устройства, платформы или контексты",
        "direct": "Источники загружены напрямую из облачного сбора без отчёта запуска",
        "same": "Использован один и тот же снимок",
    }
    overview = tuple(f"{label} · строк матрицы: {exclusions[key]}" for key, label in labels.items() if exclusions[key])
    ordered_pairs = dict(sorted(pairs.items(), key=lambda entry: entry[1].after.device_label.casefold()))
    return MatrixFindingSources(ordered_pairs, by_requirement, overview)


def _read(
    store: ProjectStore, project_id: str, source: MatrixScopeSource, side: str,
) -> tuple[dict[str, Any], dict[str, Any], DeviceRevision, str | None]:
    if not source.run_id or not source.item_id:
        raise ValueError(f"{side} · у источника нет ссылки на сохранённый запуск.")
    record = store.get_run_item_with_header(project_id, source.run_id, source.item_id)
    if record is None:
        raise ValueError(f"{side} · исходный элемент запуска недоступен в этом проекте.")
    header, item = record
    try:
        revision = DeviceRevision.model_validate(item.get("revision"))
    except ValueError:
        raise ValueError(f"{side} · сохранённая ревизия не читается.") from None
    device, config = revision.device, revision.parse_result.configuration
    if (
        revision.revision_id != source.revision_id
        or (device.device_id, device.platform, device.context) != _identity(source)
        or (config.content_sha256, config.parser_version, config.captured_at) != (
            source.configuration_sha256, source.parser_version, source.captured_at,
        )
        or matrix_scope_revision_checksum(revision) != source.revision_checksum
    ):
        raise ValueError(f"{side} · ревизия запуска отличается от сохранённого источника сверки.")
    raw_report = item.get("report")
    try:
        report = FirewallAssuranceResult.model_validate(raw_report) if raw_report is not None else None
    except ValueError:
        report = None
    if report is None or (report.revision_id, report.configuration_id, report.device_id, report.parser_version) != (
        revision.revision_id, config.configuration_id, device.device_id, config.parser_version,
    ):
        item["report"] = None
        return header, item, revision, f"{side} · отчёт проверок этого снимка отсутствует или его происхождение не подтверждено."
    return header, item, revision, None


def load_matrix_finding_rows(
    store: ProjectStore, project_id: str, pair: MatrixFindingSourcePair,
) -> tuple[tuple[dict[str, Any], ...], tuple[str, ...]]:
    old_header, old_item, old_revision, old_gap = _read(store, project_id, pair.before, "Было")
    new_header, new_item, new_revision, new_gap = _read(store, project_id, pair.after, "Стало")
    gaps = tuple(gap for gap in (old_gap, new_gap) if gap is not None)
    rows = compare_saved_device_findings(
        old_item, new_item, old_revision, new_revision, before_run=old_header, after_run=new_header,
        source_limitations=(*pair.limitations, *gaps),
    )
    diagnostics = tuple(
        f"{label} · запуск {source.run_id} · снимок {source.item_id}"
        for label, source in (("Было", pair.before), ("Стало", pair.after))
    )
    return rows, diagnostics
