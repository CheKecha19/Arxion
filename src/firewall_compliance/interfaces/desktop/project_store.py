"""Локальные проекты и результаты без хранения полного исходного документа."""

import json
import os
import sqlite3
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cached_property
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.enums import FindingStatus
from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.infrastructure.windows_secrets import protect_secret, unprotect_secret
from firewall_compliance.interfaces.desktop.backend import AnalysisSession, source_preview
from firewall_compliance.parsers import ParseFailure

if TYPE_CHECKING:
    from firewall_compliance.application.acl_map import AclMapBatch
    from firewall_compliance.application.analysis_result import AnalysisResult
    from firewall_compliance.application.matrix_scope_assessment import MatrixScopeSource
    from firewall_compliance.domain.acl_map import AclMap
    from firewall_compliance.interfaces.desktop.logical_networks import LogicalNetworkStore
    from firewall_compliance.interfaces.desktop.resource_registry import ResourceRegistry
    from firewall_compliance.interfaces.desktop.workspace_store import WorkspaceMetadataStore


type _MatrixRevision = tuple[str, str, dict[str, Any]]
type _MatrixScopeRevisions = tuple[tuple[_MatrixRevision, ...], tuple[tuple[MatrixScopeSource, bool], ...]]


class SourceMismatchError(ValueError):
    """Выбранный документ отличается от исходника сохранённого снимка."""


@dataclass(frozen=True, slots=True)
class MatrixBaselineRun:
    run_id: str
    created_at: str
    state: str


def _is_file_run(settings: Mapping[str, Any]) -> bool:
    from firewall_compliance.interfaces.desktop.file_sources import FILE_SOURCE_PREFIX

    source_id = settings.get("source_id")
    return not (settings.get("cloud_scan_id") or settings.get("analysis_source")) and (
        not source_id or isinstance(source_id, str) and source_id.startswith(FILE_SOURCE_PREFIX)
    )


def _now() -> str:
    return datetime.now(UTC).isoformat()


def default_database_path() -> Path:
    """Путь в личном профиле Windows; исходные конфигурации сюда не копируются."""
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local" / "share")))
    return base / "FirewallCompliance" / "projects.sqlite3"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def matrix_scope_revision_json(revision: Mapping[str, Any]) -> str:
    """Компактное представление сохранённой ревизии для SQLite без JSON1."""
    return json.dumps(revision, ensure_ascii=False, separators=(",", ":"))


def matrix_scope_stored_checksum(value: str) -> str:
    """Контрольная сумма текста ревизии, извлечённого из записи SQLite."""
    return sha256(value.encode("utf-8")).hexdigest()


def _cloud_projection_unavailable(error: sqlite3.OperationalError) -> bool:
    message = str(error)
    return message.startswith("no such function: json_") or message in {
        "no such table: json_each", "no such table: json_tree", "malformed JSON",
    }


def _excerpts(session: AnalysisSession) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    budget = 40
    for check in session.report.checks:
        if check.check_id.startswith("MGMT-"):
            # Management evidence is normalized; raw community/banner lines must
            # not enter persistent excerpts or exported reports.
            continue
        for finding in check.findings:
            for location in finding.evidence.source_locations:
                if location.line_start is None or budget <= 0:
                    continue
                end = min(location.line_end or location.line_start, location.line_start + 2)
                key = (location.line_start, end)
                if key in seen or end - location.line_start + 1 > budget:
                    continue
                bounded = location.model_copy(update={"line_end": end})
                try:
                    text = source_preview(session, bounded)
                except ValueError:
                    continue
                seen.add(key)
                budget -= end - location.line_start + 1
                result.append({"location": bounded.model_dump(mode="json"), "text": text[:4096]})
    return result


class ProjectStore:
    """SQLite-хранилище с отдельными транзакциями для результатов и решений пользователя."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.path = db_path or default_database_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] > 1:
                raise ValueError("Хранилище создано более новой версией приложения")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL,
                    settings TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
                    created_at TEXT NOT NULL, finished_at TEXT, state TEXT NOT NULL,
                    settings TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS items (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
                    payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS marks (
                    run_id TEXT NOT NULL REFERENCES runs(id), finding_id TEXT NOT NULL,
                    status TEXT NOT NULL, comment TEXT NOT NULL, updated_at TEXT NOT NULL,
                    PRIMARY KEY(run_id, finding_id));
                CREATE TABLE IF NOT EXISTS device_links (
                    project_id TEXT NOT NULL REFERENCES projects(id), source_key TEXT NOT NULL,
                    device_id TEXT NOT NULL, PRIMARY KEY(project_id, source_key));
                CREATE TABLE IF NOT EXISTS integrations (
                    project_id TEXT NOT NULL REFERENCES projects(id), provider TEXT NOT NULL,
                    config TEXT NOT NULL, protected_secret TEXT NOT NULL,
                    PRIMARY KEY(project_id, provider));
                CREATE TABLE IF NOT EXISTS cloud_scans (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
                    created_at TEXT NOT NULL, finished_at TEXT, state TEXT NOT NULL,
                    selection TEXT NOT NULL, config TEXT NOT NULL, result TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS analysis_results (
                    analysis_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id),
                    run_id TEXT REFERENCES runs(id),
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS analysis_results_project
                    ON analysis_results(project_id,created_at);
                CREATE TRIGGER IF NOT EXISTS analysis_results_no_update
                    BEFORE UPDATE ON analysis_results
                    BEGIN SELECT RAISE(ABORT, 'Analysis results are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS analysis_results_no_delete
                    BEFORE DELETE ON analysis_results
                    BEGIN SELECT RAISE(ABORT, 'Analysis results are immutable'); END;
                CREATE TABLE IF NOT EXISTS finding_mark_baselines (
                    project_id TEXT NOT NULL REFERENCES projects(id),
                    run_id TEXT NOT NULL REFERENCES runs(id), finding_id TEXT NOT NULL,
                    status TEXT NOT NULL, comment TEXT NOT NULL, updated_at TEXT,
                    kind TEXT NOT NULL CHECK(kind IN ('legacy_mark','original_report')),
                    history_started_at TEXT NOT NULL,
                    PRIMARY KEY(project_id,run_id,finding_id));
                CREATE TABLE IF NOT EXISTS finding_mark_transitions (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL REFERENCES projects(id),
                    run_id TEXT NOT NULL REFERENCES runs(id), finding_id TEXT NOT NULL,
                    changed_at TEXT NOT NULL,
                    previous_status TEXT NOT NULL, previous_comment TEXT NOT NULL,
                    new_status TEXT NOT NULL, new_comment TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS finding_mark_transitions_identity
                    ON finding_mark_transitions(project_id,run_id,finding_id,sequence);
                CREATE TRIGGER IF NOT EXISTS finding_mark_baselines_no_update
                    BEFORE UPDATE ON finding_mark_baselines
                    BEGIN SELECT RAISE(ABORT, 'Finding history is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS finding_mark_baselines_no_delete
                    BEFORE DELETE ON finding_mark_baselines
                    BEGIN SELECT RAISE(ABORT, 'Finding history is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS finding_mark_transitions_no_update
                    BEFORE UPDATE ON finding_mark_transitions
                    BEGIN SELECT RAISE(ABORT, 'Finding history is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS finding_mark_transitions_no_delete
                    BEFORE DELETE ON finding_mark_transitions
                    BEGIN SELECT RAISE(ABORT, 'Finding history is append-only'); END;
                PRAGMA user_version=1;
            """)
            # Capture known saved states, never manufacture their earlier transitions.
            db.execute(
                "INSERT OR IGNORE INTO finding_mark_baselines "
                "SELECT r.project_id,m.run_id,m.finding_id,m.status,m.comment,m.updated_at,"
                "'legacy_mark',? FROM marks m JOIN runs r ON r.id=m.run_id",
                (_now(),),
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @cached_property
    def resource_registry(self) -> "ResourceRegistry":
        """Add resource metadata without rewriting the legacy project/result tables."""
        from firewall_compliance.interfaces.desktop.resource_registry import ResourceRegistry

        return ResourceRegistry(self.path)

    @cached_property
    def logical_networks(self) -> "LogicalNetworkStore":
        from firewall_compliance.interfaces.desktop.logical_networks import LogicalNetworkStore

        return LogicalNetworkStore(self)

    @cached_property
    def workspace_metadata(self) -> "WorkspaceMetadataStore":
        """Access optional site metadata without implicitly migrating the database."""
        from firewall_compliance.interfaces.desktop.workspace_store import WorkspaceMetadataStore

        return WorkspaceMetadataStore(self)

    def project_history(
        self, project_id: str, *, compact: bool = False,
    ) -> list[dict[str, Any]]:
        """Read saved runs, with a compact option for overview screens."""
        with self._connect() as db:
            try:
                return self._read_project_history(db, project_id, compact=compact)
            except sqlite3.OperationalError as error:
                if not compact or not (
                    str(error).startswith("no such function: json_") or str(error) == "no such table: json_each"
                ):
                    raise
                return self._read_project_history(db, project_id)

    @staticmethod
    def _read_project_history(
        db: sqlite3.Connection, project_id: str, *, compact: bool = False,
    ) -> list[dict[str, Any]]:
        # Истории для обзора нужны отчёты, метаданные ревизий и решения. Правила,
        # сетевые факты и фрагменты извлекаются полностью для открытого снимка.
        item_projection = (
            """CASE WHEN json_valid(i.payload)
                THEN CASE WHEN json_type(i.payload, '$.report.device_id') = 'text'
                THEN json_set(json_remove(i.payload,
                    '$.parse_result.rules', '$.parse_result.endpoints', '$.parse_result.services',
                    '$.parse_result.policy_attachments', '$.parse_result.source_map',
                    '$.parse_result.management', '$.parse_result.switch_facts',
                    '$.parse_result.switch_policies', '$.parse_result.controller_inventory',
                    '$.revision.parse_result', '$.revision.sources', '$.revision.interfaces',
                    '$.revision.routes', '$.revision.network_segments', '$.revision.topology_links',
                    '$.revision.interfaces_evidence', '$.revision.routes_evidence',
                    '$.revision.network_segments_evidence', '$.revision.topology_evidence', '$.excerpts'),
                    '$.observed_switch_hostname', json_extract(i.payload,'$.parse_result.switch_facts.hostname'),
                    '$.observed_interface_addresses', json((
                        SELECT json_group_array(value) FROM (
                            SELECT address.value
                            FROM json_each(i.payload,'$.revision.interfaces') AS iface
                            JOIN json_each(
                                CASE WHEN iface.type='object' THEN iface.value ELSE '{}' END,'$.addresses'
                            ) AS address
                            WHERE iface.type='object' AND address.type='text'
                            UNION
                            SELECT json_extract(address.value,'$.cidr')
                            FROM json_each(i.payload,'$.parse_result.switch_facts.interfaces') AS iface
                            JOIN json_each(
                                CASE WHEN iface.type='object' THEN iface.value ELSE '{}' END,'$.addresses'
                            ) AS address
                            WHERE CASE WHEN address.type='object'
                                THEN json_extract(address.value,'$.status')='known' END
                        )
                    )))
                ELSE i.payload END ELSE i.payload END"""
            if compact else "i.payload"
        )
        runs = db.execute(
            "SELECT * FROM runs WHERE project_id=? ORDER BY created_at DESC,rowid DESC",
            (project_id,),
        ).fetchall()
        items = db.execute(
            f"SELECT i.id,i.run_id,{item_projection} AS payload FROM items i JOIN runs r ON r.id=i.run_id "
            "WHERE r.project_id=? ORDER BY i.rowid",
            (project_id,),
        )
        marks = db.execute(
            "SELECT m.* FROM marks m JOIN runs r ON r.id=m.run_id WHERE r.project_id=?",
            (project_id,),
        )
        by_run: dict[str, list[dict[str, Any]]] = {}
        for item in items:
            by_run.setdefault(item["run_id"], []).append(
                {"id": item["id"], **json.loads(item["payload"])}
            )
        decisions: dict[str, dict[str, Any]] = {}
        for mark in marks:
            decisions.setdefault(mark["run_id"], {})[mark["finding_id"]] = {
                key: mark[key] for key in ("status", "comment", "updated_at")
            }
        return [
            {
                **dict(run),
                "settings": json.loads(run["settings"]),
                "items": by_run.get(run["id"], []),
                "marks": decisions.get(run["id"], {}),
            }
            for run in runs
        ]

    def project_workspace_history(
        self, project_id: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | None:
        """Read compact history and latest full device items in one SQLite snapshot."""
        try:
            with self._connect() as db:
                db.execute("BEGIN")
                history = self._read_project_history(db, project_id, compact=True)
                latest: list[tuple[str, str, str]] = []
                seen: set[str] = set()
                for run in history:
                    for item in reversed(run["items"]):
                        report = item.get("report")
                        if not report or report["device_id"] in seen:
                            continue
                        seen.add(report["device_id"])
                        latest.append((item["id"], run["id"], run["created_at"]))

                devices = []
                # Размер порции ограничивает число SQL-параметров, а не число устройств.
                for offset in range(0, len(latest), 500):
                    batch = latest[offset:offset + 500]
                    placeholders = ",".join("?" for _ in batch)
                    rows = db.execute(
                        "SELECT i.id,i.payload FROM items i JOIN runs r ON r.id=i.run_id "
                        f"WHERE r.project_id=? AND i.id IN ({placeholders})",
                        (project_id, *(item_id for item_id, _, _ in batch)),
                    )
                    full = {row["id"]: json.loads(row["payload"]) for row in rows}
                    devices.extend(
                        {"id": item_id, **full[item_id], "run_id": run_id, "run_created_at": created_at}
                        for item_id, run_id, created_at in batch
                    )
        except sqlite3.OperationalError as error:
            if str(error).startswith("no such function: json_") or str(error) == "no such table: json_each":
                return None
            raise
        return history, devices

    def matrix_baseline_runs(self, project_id: str) -> tuple[MatrixBaselineRun, ...]:
        """Список завершившихся файловых операций для выбора исторического среза."""
        with self._connect() as db:
            rows = db.execute(
                """SELECT id,created_at,state,settings FROM runs
                   WHERE project_id=? AND state!='running' AND finished_at IS NOT NULL
                   ORDER BY created_at DESC,rowid DESC""",
                (project_id,),
            )
            return tuple(
                MatrixBaselineRun(row["id"], row["created_at"], row["state"])
                for row in rows if _is_file_run(json.loads(row["settings"]))
            )

    @staticmethod
    def _matrix_baseline_cut(
        db: sqlite3.Connection, project_id: str, run_id: str | None,
    ) -> tuple[str, int] | None:
        if run_id is None:
            return None
        row = db.execute(
            """SELECT created_at,rowid,settings FROM runs
               WHERE project_id=? AND id=? AND state!='running' AND finished_at IS NOT NULL""",
            (project_id, run_id),
        ).fetchone()
        if row is None or not _is_file_run(json.loads(row[2])):
            raise ValueError("Файловый запуск для исторического среза недоступен.")
        return row[0], row[1]

    def latest_matrix_revisions(
        self, project_id: str, site_id: str | None, *,
        baseline_run_id: str | None = None, cancelled: Callable[[], bool] | None = None,
        policies_only: bool = False,
    ) -> tuple[_MatrixRevision, ...]:
        """Последние политики и сетевые факты по устройствам и контекстам.

        Исторический срез включает выбранный файловый запуск и результаты,
        которые уже были сохранены к его началу.
        Для списка политик ревизии без правил отбрасываются после выбора последнего снимка.
        """
        revisions, _ = self._latest_matrix_revisions(
            project_id, site_id, baseline_run_id=baseline_run_id, cancelled=cancelled,
            policies_only=policies_only, compact_paths=False,
        )
        return revisions

    def latest_matrix_scope_revisions(
        self, project_id: str, site_id: str | None, *,
        baseline_run_id: str | None = None, cancelled: Callable[[], bool] | None = None,
    ) -> _MatrixScopeRevisions:
        """Полные снимки для сверки и ссылки на коммутаторы без правил для разбора пути."""
        return self._latest_matrix_revisions(
            project_id, site_id, baseline_run_id=baseline_run_id, cancelled=cancelled,
            policies_only=False, compact_paths=True,
        )

    def _latest_matrix_revisions(
        self, project_id: str, site_id: str | None, *,
        baseline_run_id: str | None, cancelled: Callable[[], bool] | None,
        policies_only: bool, compact_paths: bool,
    ) -> _MatrixScopeRevisions:
        from firewall_compliance.application.matrix_scope_assessment import MatrixScopeSource

        if cancelled is not None and cancelled():
            return (), ()
        assignments = self.workspace_metadata.device_sites(project_id) if site_id is not None else {}
        revisions: list[_MatrixRevision] = []
        paths: list[tuple[MatrixScopeSource, bool]] = []
        candidate_query = """FROM items i JOIN runs r ON i.run_id=r.id
                             WHERE r.project_id=? AND r.state!='running'"""
        try:
            with self._connect() as db:
                db.execute("BEGIN")
                cut = self._matrix_baseline_cut(db, project_id, baseline_run_id)
                if cancelled is not None:
                    db.set_progress_handler(lambda: int(cancelled()), 10_000)
                parameters: tuple[str | int, ...] = (project_id,)
                if cut is not None:
                    created_at, sequence = cut
                    candidate_query += (
                        " AND (r.rowid=? OR ((r.created_at,r.rowid)<(?,?) AND r.finished_at<=?))"
                    )
                    parameters = (project_id, sequence, created_at, sequence, created_at)
                db.create_function("matrix_scope_stored_checksum", 1, matrix_scope_stored_checksum, deterministic=True)
                site_filter = ""
                if site_id is not None:
                    db.create_function(
                        "matrix_scope_device_selected", 1,
                        lambda identifier: int(assignments.get(identifier, "") == site_id), deterministic=True,
                    )
                    site_filter = "AND matrix_scope_device_selected(json_extract(i.payload,'$.revision.device.device_id'))"
                rows = db.execute(
                    f"""WITH ranked AS (
                        SELECT r.id AS run_id,i.id AS item_id,
                               json_extract(i.payload,'$.revision.device.device_id') AS device_id,
                               json_extract(i.payload,'$.revision.device.platform') AS platform,
                               json_extract(i.payload,'$.revision.device.context') AS context,
                               row_number() OVER (
                                   PARTITION BY json_extract(i.payload,'$.revision.device.device_id'),
                                                json_extract(i.payload,'$.revision.device.platform'),
                                                json_extract(i.payload,'$.revision.device.context')
                                   ORDER BY r.created_at DESC,r.rowid DESC,i.rowid DESC
                               ) AS latest
                        {candidate_query}
                          AND json_type(i.payload,'$.revision.device.device_id')='text'
                          {site_filter}
                    ), eligible AS (
                        SELECT q.run_id,q.item_id,q.device_id,q.platform,q.context,i.payload,
                               ? AND q.platform IN ('aos-cx','aos-switch','comware')
                                 AND json_type(i.payload,'$.revision.parse_result.rules')='array'
                                 AND json_array_length(i.payload,'$.revision.parse_result.rules')=0 AS path_only
                        FROM ranked q JOIN items i ON i.id=q.item_id
                        WHERE q.latest=1 AND (
                            json_array_length(i.payload,'$.revision.parse_result.rules')>0
                            OR (?=0 AND json_type(i.payload,'$.revision.parse_result.switch_facts')='object')
                        )
                    )
                    SELECT run_id,item_id,device_id,platform,context,path_only,
                           CASE WHEN NOT coalesce(path_only,0) THEN json_extract(payload,'$.revision') END AS revision,
                           CASE WHEN path_only THEN json_extract(payload,'$.revision.revision_id') END AS revision_id,
                           CASE WHEN path_only THEN coalesce(
                               nullif(json_extract(payload,'$.revision.device.hostname'),''),
                               nullif(json_extract(payload,'$.revision.parse_result.switch_facts.hostname'),''),
                               device_id
                           ) END AS device_label,
                           CASE WHEN path_only THEN json_extract(payload,'$.revision.parse_result.configuration.parser_version')
                           END AS parser_version,
                           CASE WHEN path_only THEN json_extract(payload,'$.revision.parse_result.configuration.captured_at')
                           END AS captured_at,
                           CASE WHEN path_only THEN json_extract(payload,'$.revision.parse_result.configuration.content_sha256')
                           END AS configuration_sha256,
                           CASE WHEN path_only THEN matrix_scope_stored_checksum(json_extract(payload,'$.revision'))
                           END AS revision_checksum,
                           CASE WHEN path_only AND (context IS NULL OR context='default') THEN NOT EXISTS (
                               SELECT 1 FROM json_each(payload,'$.revision.parse_result.switch_facts.interfaces') AS iface
                               WHERE coalesce(json_extract(iface.value,'$.kind'),'physical')!='management'
                                 AND json_extract(iface.value,'$.vrf') IS NOT 'default'
                           ) ELSE 0 END AS default_switch
                    FROM eligible ORDER BY device_id,run_id,item_id""",
                    (*parameters, int(compact_paths), int(policies_only)),
                )
                for row in rows:
                    if cancelled is not None and cancelled():
                        break
                    if row["path_only"]:
                        paths.append((MatrixScopeSource(
                            run_id=row["run_id"], item_id=row["item_id"], revision_id=row["revision_id"],
                            device_id=row["device_id"], device_label=row["device_label"], platform=row["platform"],
                            device_context=row["context"], parser_version=row["parser_version"],
                            captured_at=row["captured_at"], configuration_sha256=row["configuration_sha256"],
                            revision_checksum=row["revision_checksum"], revision_checksum_kind="stored_json",
                        ), bool(row["default_switch"])))
                    else:
                        revisions.append((row["run_id"], row["item_id"], json.loads(row["revision"])))
                return tuple(revisions), tuple(paths)
        except sqlite3.OperationalError as error:
            if cancelled is not None and cancelled() and str(error) == "interrupted":
                return tuple(revisions), tuple(paths)
            if not str(error).startswith("no such function: json_") and str(error) != "no such table: json_each":
                raise
        # SQLite без JSON1 читает полные ревизии и сохраняет прежнюю проверку их контрольной суммы.
        seen: set[tuple[str, str, str | None]] = set()
        with self._connect() as db:
            rows = db.execute(
                f"""SELECT r.id AS run_id,i.id AS item_id,i.payload {candidate_query}
                    ORDER BY r.created_at DESC,r.rowid DESC,i.rowid DESC""",
                parameters,
            )
            for row in rows:
                if cancelled is not None and cancelled():
                    break
                revision = json.loads(row["payload"]).get("revision")
                if not isinstance(revision, dict):
                    continue
                device = revision.get("device") or {}
                if not device.get("device_id") or (
                    site_id is not None and assignments.get(device["device_id"], "") != site_id
                ):
                    continue
                key = device["device_id"], device.get("platform", ""), device.get("context")
                parsed = revision.get("parse_result") or {}
                if key not in seen and (
                    parsed.get("rules") or (not policies_only and isinstance(parsed.get("switch_facts"), dict))
                ):
                    revisions.append((row["run_id"], row["item_id"], revision))
                seen.add(key)
        return tuple(revisions), ()

    def matrix_newer_source_failures(
        self, project_id: str, origins: Sequence[tuple[str, str]],
        *, cancelled: Callable[[], bool] | None = None,
    ) -> dict[tuple[str, str], tuple[str, str]]:
        """Find a newer terminal failure for the same saved source or explicit file path."""
        wanted = set(origins)
        if not wanted or (cancelled is not None and cancelled()):
            return {}
        newest_source: dict[str, tuple[str, str, bool]] = {}
        newest_path: dict[tuple[str, str], tuple[str, str, bool]] = {}
        origin_failures: dict[tuple[str, str], tuple[str, str]] = {}
        try:
            with self._connect() as db:
                if cancelled is not None:
                    db.set_progress_handler(lambda: int(cancelled()), 10_000)
                rows = db.execute(
                    """SELECT r.id AS run_id,r.finished_at,r.settings,
                              i.id AS item_id,json_extract(i.payload,'$.path') AS path,
                              json_extract(i.payload,'$.status') AS status
                       FROM runs r LEFT JOIN items i ON i.run_id=r.id
                       WHERE r.project_id=? AND r.finished_at IS NOT NULL AND r.state!='running'
                       ORDER BY r.created_at DESC,r.rowid DESC,i.rowid DESC""",
                    (project_id,),
                )
                seen_runs: set[str] = set()
                source_id = ""
                for row in rows:
                    if cancelled is not None and cancelled():
                        break
                    run_id, finished, item_id, path, status = (
                        row["run_id"], row["finished_at"], row["item_id"], row["path"], row["status"],
                    )
                    if run_id not in seen_runs:
                        seen_runs.add(run_id)
                        settings = json.loads(row["settings"])
                        source_id = str(settings.get("source_id") or "")
                        if source_id.startswith(("files:", "ngfw:")):
                            collection_failed = settings.get("source_collection_state") in {
                                "failed", "cancelled", "interrupted",
                            }
                            newest_source.setdefault(source_id, (run_id, finished, collection_failed))
                    failed = status in {"error", "unsupported", "canceled", "cancelled"}
                    file_path = str(path) if path and not source_id.startswith(("cloud_ru_", "ngfw:")) else ""
                    path_key = source_id, file_path
                    if file_path and Path(file_path).is_absolute():
                        newest_path.setdefault(path_key, (run_id, finished, failed))
                    if (run_id, item_id) not in wanted:
                        continue
                    attempts = (
                        attempt for attempt in (newest_path.get(path_key), newest_source.get(source_id))
                        if attempt is not None and attempt[0] != run_id and attempt[2]
                    )
                    if (attempt := max(attempts, key=lambda value: value[1], default=None)) is not None:
                        origin_failures[run_id, item_id] = attempt[0], attempt[1]
                    wanted.discard((run_id, item_id))
                    if not wanted:
                        break
        except sqlite3.OperationalError as error:
            if cancelled is not None and cancelled() and str(error) == "interrupted":
                return origin_failures
            if not str(error).startswith("no such function: json_"):
                raise
        return origin_failures

    def project_rule_count_history(
        self, project_id: str, *, source_id: str | None = None,
        source_fingerprint: str | None = None,
    ) -> dict[tuple[str, str, str], tuple[int, str]]:
        """Find the latest complete baseline per device, parser and platform."""
        counts: dict[tuple[str, str, str], tuple[int, str]] = {}
        try:
            with self._connect() as db:
                rows = db.execute(
                    """SELECT i.id,
                        json_extract(i.payload, '$.report.device_id') AS device_id,
                        json_extract(i.payload, '$.report.parser_version') AS parser_version,
                        json_extract(i.payload, '$.parse_result.configuration.platform') AS platform,
                        json_array_length(i.payload, '$.parse_result.rules') AS rule_count
                    FROM items i JOIN runs r ON r.id=i.run_id
                    WHERE r.project_id=?
                      AND json_extract(i.payload, '$.status')='complete'
                      AND json_type(i.payload, '$.report.device_id')='text'
                      AND json_type(i.payload, '$.report.parser_version')='text'
                      AND json_type(i.payload, '$.parse_result.rules')='array'
                      AND (? IS NULL OR (
                          json_extract(r.settings, '$.source_id')=?
                          AND json_extract(r.settings, '$.source_config_fingerprint') IS ?))
                    ORDER BY r.created_at DESC,r.rowid DESC,i.rowid DESC""",
                    (project_id, source_id, source_id, source_fingerprint),
                )
                for row in rows:
                    key = (str(row["device_id"]), str(row["parser_version"]), str(row["platform"]))
                    counts.setdefault(key, (row["rule_count"], row["id"]))
        except sqlite3.OperationalError as error:
            if not str(error).startswith("no such function: json_") and str(error) != "malformed JSON":
                raise
            # Поддерживаем прежнее чтение, если SQLite не умеет разобрать исторический JSON.
            counts.clear()
            for run in self.project_history(project_id):
                settings = run.get("settings", {})
                if source_id is not None and (
                    settings.get("source_id") != source_id
                    or settings.get("source_config_fingerprint") != source_fingerprint
                ):
                    continue
                for item in reversed(run["items"]):
                    report = item.get("report") or {}
                    parsed = item.get("parse_result") or {}
                    rules = parsed.get("rules")
                    if item.get("status") != "complete" or not report or not isinstance(rules, list):
                        continue
                    key = (
                        str(report["device_id"]), str(report["parser_version"]),
                        str(parsed.get("configuration", {}).get("platform")),
                    )
                    counts.setdefault(key, (len(rules), item["id"]))
        return counts

    @staticmethod
    def _analysis_scope(db: sqlite3.Connection, project_id: str, result: "AnalysisResult") -> None:
        if db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone() is None:
            raise KeyError("Unknown project")
        if result.project_reference not in (None, project_id):
            raise ValueError("Analysis result belongs to another project")
        if result.run_reference is not None:
            run = db.execute(
                "SELECT project_id FROM runs WHERE id=?", (result.run_reference,)
            ).fetchone()
            if run is None or run["project_id"] != project_id:
                raise ValueError("Analysis run does not belong to this project")

    @staticmethod
    def _read_analysis_result(
        db: sqlite3.Connection, project_id: str, row: sqlite3.Row
    ) -> "AnalysisResult":
        from firewall_compliance.application.analysis_result import AnalysisResult

        if sha256(row["payload"].encode("utf-8")).hexdigest() != row["payload_sha256"]:
            raise ValueError("Stored analysis payload checksum differs")
        result = AnalysisResult.model_validate_json(row["payload"])
        if (
            str(result.analysis_id) != row["analysis_id"]
            or row["project_id"] != project_id
            or result.run_reference != row["run_id"]
        ):
            raise ValueError("Stored analysis identity does not match its envelope")
        ProjectStore._analysis_scope(db, project_id, result)
        return result

    def save_analysis_result(self, project_id: str, result: "AnalysisResult") -> str:
        """Persist a validated immutable envelope without creating a policy launch."""
        from firewall_compliance.application.analysis_result import AnalysisResult

        if not isinstance(result, AnalysisResult):
            raise TypeError("Expected an AnalysisResult")
        # Revalidate even constructed instances; never trust a caller's cached summary.
        validated = AnalysisResult.model_validate_json(result.model_dump_json())
        payload = json.dumps(
            validated.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        analysis_id = str(validated.analysis_id)
        with self._connect() as db:
            self._analysis_scope(db, project_id, validated)
            previous = db.execute(
                "SELECT * FROM analysis_results WHERE analysis_id=?", (analysis_id,)
            ).fetchone()
            if previous is not None:
                if previous["project_id"] != project_id or previous["payload"] != payload:
                    raise ValueError("Analysis ID already identifies a different saved envelope")
                self._read_analysis_result(db, project_id, previous)
                return analysis_id
            inserted = db.execute(
                "INSERT INTO analysis_results VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(analysis_id) DO NOTHING",
                (
                    analysis_id,
                    project_id,
                    validated.run_reference,
                    _now(),
                    payload,
                    sha256(payload.encode("utf-8")).hexdigest(),
                ),
            )
            if inserted.rowcount == 0:
                # Another writer may have saved this ID after our initial SELECT.
                concurrent = db.execute(
                    "SELECT * FROM analysis_results WHERE analysis_id=?", (analysis_id,)
                ).fetchone()
                if (
                    concurrent is None
                    or concurrent["project_id"] != project_id
                    or concurrent["payload"] != payload
                ):
                    raise ValueError("Analysis ID already identifies a different saved envelope")
                self._read_analysis_result(db, project_id, concurrent)
        return analysis_id

    def get_analysis_result(self, project_id: str, analysis_id: str) -> "AnalysisResult":
        """Read and validate exact snapshots, including their derived engine outputs."""
        identifier = str(UUID(str(analysis_id)))
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM analysis_results WHERE project_id=? AND analysis_id=?",
                (project_id, identifier),
            ).fetchone()
            if row is None:
                raise KeyError("Unknown analysis result in this project")
            return self._read_analysis_result(db, project_id, row)

    def list_analysis_results(self, project_id: str) -> list[dict[str, Any]]:
        """Return compact validated metadata; retained inputs are only in get_analysis_result."""
        result_rows: list[dict[str, Any]] = []
        with self._connect() as db:
            if db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone() is None:
                raise KeyError("Unknown project")
            rows = db.execute(
                "SELECT * FROM analysis_results WHERE project_id=? "
                "ORDER BY created_at DESC,rowid DESC",
                (project_id,),
            ).fetchall()
            for row in rows:
                result = self._read_analysis_result(db, project_id, row)
                result_rows.append(
                    {
                        "analysis_id": str(result.analysis_id),
                        "project_id": project_id,
                        "run_id": result.run_reference,
                        "created_at": row["created_at"],
                        "started_at": result.started_at.isoformat(),
                        "finished_at": result.finished_at.isoformat(),
                        "schema_version": result.schema_version,
                        "application_version": result.application_version,
                        "state": result.state,
                        "component_kinds": [component.kind for component in result.components],
                        "summary": result.summary.model_dump(mode="json")
                        if result.summary
                        else None,
                    }
                )
        return result_rows

    def save_acl_map(
        self,
        project_id: str,
        graph: "AclMap",
        *,
        run_id: str | None = None,
        item_id: str | None = None,
        map_id: str | None = None,
    ) -> str:
        """Persist the exact declared-rule map and optional captured-run provenance."""
        from firewall_compliance.application.acl_map_store import AclMapStore

        with self._connect() as db:
            return AclMapStore(db).save(
                project_id, graph, run_id=run_id, item_id=item_id, map_id=map_id
            )

    def get_acl_map(self, project_id: str, map_id: str) -> "AclMap":
        """Read a validated saved graph without reopening its configuration."""
        from firewall_compliance.application.acl_map_store import AclMapStore

        with self._connect() as db:
            return AclMapStore(db).get(project_id, map_id)

    def list_acl_maps(self, project_id: str) -> list[dict[str, Any]]:
        """Return discoverable saved-map metadata scoped to one project."""
        from firewall_compliance.application.acl_map_store import AclMapStore

        with self._connect() as db:
            return [dict(row) for row in AclMapStore(db).list(project_id)]

    def save_acl_map_batch(
        self,
        project_id: str,
        run_id: str,
        *,
        item_ids: Sequence[str] | None = None,
    ) -> tuple["AclMapBatch", tuple[str, ...]]:
        """Build/save selected captured revisions; preserve every unprocessed input."""
        from firewall_compliance.analysis.acl_map import build_acl_map
        from firewall_compliance.application.acl_map import (
            AclMapBatchFailure,
            build_acl_map_batch,
        )
        from firewall_compliance.application.acl_map_store import AclMapStore
        from firewall_compliance.domain.enums import ParseIssueLevel
        from firewall_compliance.domain.parse_result import ParseIssue

        run = self.get_run(run_id)
        if run["project_id"] != project_id:
            raise ValueError("Run does not belong to selected project")
        if run["state"] == "running":
            raise ValueError("Finish the run before building a batch map")
        items = run["items"]
        if item_ids is not None:
            requested = tuple(item_ids)
            known = {item["id"] for item in items}
            if (
                not requested
                or len(set(requested)) != len(requested)
                or not set(requested) <= known
            ):
                raise ValueError("Select existing, distinct run items")
            items = [item for item in items if item["id"] in requested]
        if len(items) > 1000:
            raise ValueError("Batch exceeds 1000 captured inputs")
        revisions: list[tuple[str, DeviceRevision]] = []
        failures: list[AclMapBatchFailure] = []
        built_at = datetime.now(UTC)
        for item in items:
            diagnostics: list[ParseIssue] = []
            try:
                for issue in item.get("diagnostics", []):
                    if not isinstance(issue, dict):
                        raise ValueError("Invalid stored diagnostic")
                    diagnostics.append(
                        ParseIssue(
                            code=issue.get("code")
                            or issue.get("construct_type")
                            or "SAVED_DIAGNOSTIC",
                            level=issue.get("level") or ParseIssueLevel.ERROR,
                            message=issue["message"],
                            source_location=issue.get("source_location"),
                        )
                    )
                payload = item.get("revision")
                if payload is None:
                    failures.append(
                        AclMapBatchFailure(
                            input_reference=item["id"],
                            code="REVISION_UNAVAILABLE",
                            message="Сохранённый вход не содержит ревизию; карта не построена.",
                            source_name=item.get("source_name"),
                            content_sha256=item.get("content_sha256"),
                            diagnostics=tuple(diagnostics),
                        )
                    )
                else:
                    candidate = DeviceRevision.model_validate(payload)
                    build_acl_map(candidate, built_at=built_at)
                    revisions.append((item["id"], candidate))
            except (ValueError, TypeError, KeyError):
                failures.append(
                    AclMapBatchFailure(
                        input_reference=item["id"],
                        code="INVALID_CAPTURED_ITEM",
                        message="Не удалось подтвердить сохранённую ревизию или её диагностику.",
                    )
                )
        if not items:
            failures.append(
                AclMapBatchFailure(
                    input_reference="run:" + run_id,
                    code="RUN_EMPTY",
                    message="В запуске нет сохранённых входов; карты не построены.",
                )
            )
        batch = build_acl_map_batch(revisions, built_at=built_at, failures=tuple(failures))
        with self._connect() as db:
            db.execute("BEGIN")
            repository = AclMapStore(db)
            identifiers = tuple(
                repository.save(project_id, item.graph, run_id=run_id, item_id=item.input_reference)
                for item in batch.items
            )
        return batch, identifiers

    def create_project(self, name: str) -> str:
        """Создать проект с включёнными проверками журналирования и комментариев."""
        if not name.strip():
            raise ValueError("Название проекта не может быть пустым")
        project_id = str(uuid4())
        with self._connect() as db:
            db.execute(
                "INSERT INTO projects VALUES (?,?,?,?)",
                (
                    project_id,
                    name.strip(),
                    _now(),
                    _json(
                        {
                            "require_logging": True,
                            "require_comments": True,
                            "include_fragments": True,
                        }
                    ),
                ),
            )
        return project_id

    def save_vmware_integration(self, project_id: str, config: dict[str, Any], token: str) -> None:
        """Keep protected token separate from project settings and analysis snapshots."""
        protected = protect_secret(token)
        with self._connect() as db:
            db.execute(
                "INSERT INTO integrations VALUES (?,?,?,?) "
                "ON CONFLICT(project_id,provider) DO UPDATE SET "
                "config=excluded.config,protected_secret=excluded.protected_secret",
                (project_id, "cloud_ru_vmware", _json(config), protected),
            )

    def get_vmware_integration(self, project_id: str) -> dict[str, Any] | None:
        """Return public configuration only; secrets require a separate explicit read."""
        with self._connect() as db:
            row = db.execute(
                "SELECT config FROM integrations WHERE project_id=? AND provider=?",
                (project_id, "cloud_ru_vmware"),
            ).fetchone()
        return json.loads(row["config"]) if row else None

    def list_map_integrations(self, project_id: str) -> list[dict[str, Any]]:
        """Public inventory of configured connections; never load protected credentials."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT provider,config FROM integrations WHERE project_id=? "
                "AND provider IN ('cloud_ru_vmware','cloud_ru_advanced','cloud_ru_evolution') "
                "ORDER BY provider",
                (project_id,),
            ).fetchall()
        return [{"provider": row["provider"], "config": json.loads(row["config"])} for row in rows]

    def list_source_connections(self, project_id: str) -> list[dict[str, Any]]:
        """Public source metadata; one malformed connection does not hide the rest."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT provider,config FROM integrations WHERE project_id=? ORDER BY provider",
                (project_id,),
            ).fetchall()
        result = []
        for row in rows:
            try:
                config = json.loads(row["config"])
            except (ValueError, TypeError):
                config = None
            result.append({"provider": row["provider"], "config": config})
        return result

    def get_vmware_token(self, project_id: str) -> str:
        with self._connect() as db:
            row = db.execute(
                "SELECT protected_secret FROM integrations WHERE project_id=? AND provider=?",
                (project_id, "cloud_ru_vmware"),
            ).fetchone()
        if row is None:
            raise ValueError("Сначала сохраните подключение Cloud.ru VMware в настройках.")
        return unprotect_secret(row["protected_secret"])

    def delete_vmware_integration(self, project_id: str) -> None:
        with self._connect() as db:
            db.execute(
                "DELETE FROM integrations WHERE project_id=? AND provider=?",
                (project_id, "cloud_ru_vmware"),
            )

    def save_public_cloud_integration(
        self, project_id: str, platform: str, config: dict[str, Any], credentials: dict[str, str]
    ) -> None:
        if platform not in {"advanced", "evolution"}:
            raise ValueError("Неизвестная облачная платформа.")
        protected = protect_secret(_json(credentials))
        with self._connect() as db:
            db.execute(
                "INSERT INTO integrations VALUES (?,?,?,?) "
                "ON CONFLICT(project_id,provider) DO UPDATE SET "
                "config=excluded.config,protected_secret=excluded.protected_secret",
                (project_id, "cloud_ru_" + platform, _json(config), protected),
            )

    def get_public_cloud_integration(self, project_id: str, platform: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT config FROM integrations WHERE project_id=? AND provider=?",
                (project_id, "cloud_ru_" + platform),
            ).fetchone()
        return json.loads(row["config"]) if row else None

    def get_public_cloud_credentials(self, project_id: str, platform: str) -> dict[str, str]:
        with self._connect() as db:
            row = db.execute(
                "SELECT protected_secret FROM integrations WHERE project_id=? AND provider=?",
                (project_id, "cloud_ru_" + platform),
            ).fetchone()
        if row is None:
            raise ValueError("Сначала сохраните подключение выбранной платформы в настройках.")
        credentials: dict[str, str] = json.loads(unprotect_secret(row["protected_secret"]))
        return credentials

    def delete_public_cloud_integration(self, project_id: str, platform: str) -> None:
        with self._connect() as db:
            db.execute(
                "DELETE FROM integrations WHERE project_id=? AND provider=?",
                (project_id, "cloud_ru_" + platform),
            )

    def create_cloud_scan(
        self, project_id: str, selection: dict[str, Any], config: dict[str, Any]
    ) -> str:
        scan_id = str(uuid4())
        with self._connect() as db:
            db.execute(
                "INSERT INTO cloud_scans VALUES (?,?,?,?,?,?,?,?)",
                (
                    scan_id,
                    project_id,
                    _now(),
                    None,
                    "running",
                    _json(selection),
                    _json(config),
                    _json({}),
                ),
            )
        return scan_id

    def finish_cloud_scan(self, scan_id: str, result: dict[str, Any]) -> None:
        if result.get("state") not in {
            "completed",
            "partial",
            "failed",
            "cancelled",
            "interrupted",
        }:
            raise ValueError("Неизвестный статус сканирования.")
        with self._connect() as db:
            db.execute(
                "UPDATE cloud_scans SET finished_at=?,state=?,result=? WHERE id=?",
                (_now(), result["state"], _json(result), scan_id),
            )

    def list_cloud_scans(self, project_id: str) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM cloud_scans WHERE project_id=? ORDER BY created_at DESC",
                (project_id,),
            ).fetchall()
        return [
            {
                **dict(row),
                **{key: json.loads(row[key]) for key in ("selection", "config", "result")},
            }
            for row in rows
        ]

    def list_cloud_scan_headers(self, project_id: str) -> list[dict[str, Any]]:
        """Читать настройки и выбор сборов без больших тел результатов."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT id,project_id,created_at,finished_at,state,selection,config "
                "FROM cloud_scans WHERE project_id=? ORDER BY created_at DESC,rowid DESC",
                (project_id,),
            ).fetchall()
        return [
            {**dict(row), "selection": json.loads(row["selection"]), "config": json.loads(row["config"])}
            for row in rows
        ]

    def get_cloud_scan(self, project_id: str, scan_id: str) -> dict[str, Any] | None:
        """Прочитать один конкретный сбор выбранного проекта."""
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM cloud_scans WHERE project_id=? AND id=?", (project_id, scan_id),
            ).fetchone()
        if row is None:
            return None
        return {**dict(row), **{key: json.loads(row[key]) for key in ("selection", "config", "result")}}

    def get_cloud_scan_header(self, project_id: str, scan_id: str) -> dict[str, Any] | None:
        """Read provenance for one saved collection without loading its records."""
        with self._connect() as db:
            row = db.execute(
                "SELECT id,project_id,created_at,finished_at,state,selection,config "
                "FROM cloud_scans WHERE project_id=? AND id=?",
                (project_id, scan_id),
            ).fetchone()
        if row is None:
            return None
        return {**dict(row), "selection": json.loads(row["selection"]), "config": json.loads(row["config"])}

    def run_cloud_scan_header(self, project_id: str, run_id: str) -> dict[str, Any] | None:
        """Read a derived analysis run's collection origin without loading run items."""
        with self._connect() as db:
            row = db.execute("SELECT settings FROM runs WHERE project_id=? AND id=?", (project_id, run_id)).fetchone()
        scan_id = json.loads(row["settings"]).get("cloud_scan_id") if row is not None else None
        return self.get_cloud_scan_header(project_id, scan_id) if isinstance(scan_id, str) else None

    def project_cloud_scan_summaries(
        self, project_id: str, *, include_inventory: bool = True,
    ) -> list[dict[str, Any]]:
        """Прочитать историю и состав инвентаря без тел правил и запросов."""
        try:
            with self._connect() as db:
                db.execute("BEGIN")
                scans: dict[str, dict[str, Any]] = {}
                for row in db.execute(
                    """SELECT id,project_id,created_at,finished_at,state,selection,config,
                              CASE WHEN json_type(result,'$.errors')='array'
                                   THEN json_extract(result,'$.errors') ELSE '[]' END AS errors,
                              CASE WHEN json_type(result,'$.integrity_warnings')='array'
                                   THEN json_extract(result,'$.integrity_warnings') ELSE '[]'
                              END AS integrity_warnings,
                              coalesce(json_array_length(result,'$.records'),0) AS record_count
                       FROM cloud_scans WHERE project_id=? ORDER BY created_at DESC,rowid DESC""",
                    (project_id,),
                ):
                    scan = dict(row)
                    errors = json.loads(scan.pop("errors"))
                    warnings = json.loads(scan.pop("integrity_warnings"))
                    scan.update(
                        selection=json.loads(row["selection"]), config=json.loads(row["config"]),
                        result={"records": [], "errors": errors, "integrity_warnings": warnings},
                        workspace_projection=True, error_count=len(errors),
                    )
                    scans[row["id"]] = scan
                if not include_inventory:
                    return list(scans.values())
                for row in db.execute(
                    """SELECT scan.id AS scan_id,
                              CASE WHEN entry.type='object' THEN json_object(
                                  'id',json_extract(entry.value,'$.id'),
                                  'type',json_extract(entry.value,'$.type'),
                                  'name',json_extract(entry.value,'$.name'),
                                  'collected_at',json_extract(entry.value,'$.collected_at'),
                                  'has_rule_payload',coalesce(
                                      json_type(entry.value,'$.data.firewall')='object'
                                      OR json_type(entry.value,'$.data.security_rules') IN ('object','array')
                                      OR json_type(entry.value,'$.data.nat')='array',0
                                  ),
                                  'observed_addresses',json((
                                      SELECT json_group_array(term.value)
                                      FROM json_tree(json_object(
                                          'inventory',json_extract(entry.value,'$.inventory'),
                                          'vm_networks',json_extract(entry.value,'$.data.vm_networks')
                                      )) AS term
                                      WHERE term.type='text' AND (
                                          lower(term.key) IN (
                                              'ipaddress','ip_address','private_ip','public_ip','ip','addr',
                                              'ip_addresses','private_ip_address','public_ip_address'
                                          )
                                          OR (typeof(term.key)='integer' AND (
                                              lower(term.path) GLOB '*.ip_addresses'
                                              OR lower(term.path) GLOB '*.ipaddress'
                                              OR lower(term.path) GLOB '*.ip_address'
                                              OR lower(term.path) GLOB '*.private_ip'
                                              OR lower(term.path) GLOB '*.public_ip'
                                              OR lower(term.path) GLOB '*.ip'
                                              OR lower(term.path) GLOB '*.addr'
                                              OR lower(term.path) GLOB '*.private_ip_address'
                                              OR lower(term.path) GLOB '*.public_ip_address'
                                          ))
                                      )
                                  )),
                                  'inventory',json_object(
                                      'vdcName',json_extract(entry.value,'$.inventory.vdcName'),
                                      'vdc',json_extract(entry.value,'$.inventory.vdc'),
                                      'orgVdc',json_extract(entry.value,'$.inventory.orgVdc'),
                                      'ownerRef',json_extract(entry.value,'$.inventory.ownerRef'),
                                      'isVAppTemplate',json_extract(entry.value,'$.inventory.isVAppTemplate')
                                  )
                              ) END AS record
                       FROM cloud_scans AS scan JOIN json_each(scan.result,'$.records') AS entry
                       WHERE scan.project_id=? AND json_type(scan.result,'$.records')='array'
                       ORDER BY scan.rowid,entry.key""",
                    (project_id,),
                ):
                    scan = scans[row["scan_id"]]
                    record = json.loads(row["record"]) if row["record"] is not None else None
                    # Даже пропущенный элемент занимает исходное место в массиве.
                    scan["result"]["records"].append(record)
                return list(scans.values())
        except sqlite3.OperationalError as error:
            if not _cloud_projection_unavailable(error):
                raise
        return self.list_cloud_scans(project_id)

    def read_cloud_resource_records(
        self, project_id: str, references: Sequence[tuple[str, int]],
    ) -> dict[tuple[str, int], dict[str, Any]]:
        """Прочитать выбранные ресурсы по ID сбора и индексу исходной записи."""
        by_scan: dict[str, set[int]] = {}
        for scan_id, index in references:
            if isinstance(index, bool) or not isinstance(index, int) or index < 0:
                raise ValueError("Индекс записи облачного ресурса должен быть неотрицательным целым числом")
            by_scan.setdefault(scan_id, set()).add(index)
        if not by_scan:
            return {}
        records: dict[tuple[str, int], dict[str, Any]] = {}
        try:
            with self._connect() as db:
                db.execute("BEGIN")
                for scan_id, indices in by_scan.items():
                    for row in db.execute(
                        """SELECT entry.key AS record_index,entry.value AS record
                           FROM cloud_scans AS scan JOIN json_each(scan.result,'$.records') AS entry
                           WHERE scan.project_id=? AND scan.id=? AND entry.type='object'
                             AND json_type(scan.result,'$.records')='array'
                             AND entry.key IN (SELECT value FROM json_each(?))""",
                        (project_id, scan_id, _json(sorted(indices))),
                    ):
                        records[scan_id, row["record_index"]] = json.loads(row["record"])
                return records
        except sqlite3.OperationalError as error:
            if not _cloud_projection_unavailable(error):
                raise
        records.clear()
        for scan_id, indices in by_scan.items():
            scan = self.get_cloud_scan(project_id, scan_id)
            values = scan["result"].get("records") if scan is not None else None
            if not isinstance(values, list):
                continue
            for index in indices:
                if index < len(values) and isinstance(values[index], dict):
                    records[scan_id, index] = values[index]
        return records

    def cloud_scan_record_count(self, project_id: str, scan_id: str) -> int | None:
        """Получить размер инвентаря одного сбора для сравнения объёма данных."""
        try:
            with self._connect() as db:
                row = db.execute(
                    "SELECT json_array_length(result,'$.records') AS record_count "
                    "FROM cloud_scans WHERE project_id=? AND id=?",
                    (project_id, scan_id),
                ).fetchone()
            return (row["record_count"] or 0) if row is not None else None
        except sqlite3.OperationalError as error:
            if not str(error).startswith("no such function: json_"):
                raise
        scan = self.get_cloud_scan(project_id, scan_id)
        return len(scan["result"].get("records", ())) if scan is not None else None

    def latest_matrix_cloud_scans(
        self, project_id: str, selected_site_id: str | None, *,
        baseline_run_id: str | None = None, cancelled: Callable[[], bool] | None = None,
        vmware_policy_ids: frozenset[str] = frozenset(), include_security_groups: bool = True,
    ) -> tuple[dict[str, Any], ...]:
        """Прочитать последние сборы области, завершившиеся к началу выбранного запуска."""
        from firewall_compliance.application.matrix_scope_cloud import (
            latest_matrix_cloud_scan_ids,
            matrix_vmware_scan_pairs,
        )

        if (selected_site_id == "" or not (include_security_groups or vmware_policy_ids)
                or (cancelled is not None and cancelled())):
            return ()
        scans: list[dict[str, Any]] = []
        try:
            with self._connect() as db:
                db.execute("BEGIN")
                cut = self._matrix_baseline_cut(db, project_id, baseline_run_id)
                if cancelled is not None:
                    db.set_progress_handler(lambda: int(cancelled()), 10_000)
                cutoff = "AND created_at<=? AND finished_at<=?" if cut is not None else ""
                parameters = (project_id, cut[0], cut[0]) if cut is not None else (project_id,)
                headers = {}
                for row in db.execute(
                    f"""SELECT id,project_id,created_at,finished_at,state,config,selection
                        FROM cloud_scans WHERE project_id=? AND state!='running' {cutoff}
                        ORDER BY created_at DESC,rowid DESC""",
                    parameters,
                ):
                    if cancelled is not None and cancelled():
                        return ()
                    headers[row["id"]] = {**dict(row), **{
                        key: json.loads(row[key]) for key in ("config", "selection")
                    }}
                sg_scans = latest_matrix_cloud_scan_ids(
                    headers.values(), project_id=project_id, selected_site_id=selected_site_id,
                ) if include_security_groups else ()
                for identifier in sg_scans:
                    if cancelled is not None and cancelled():
                        return tuple(scans)
                    row = db.execute(
                        "SELECT result FROM cloud_scans WHERE id=? AND project_id=?", (identifier, project_id),
                    ).fetchone()
                    if row is not None:
                        scans.append({**headers[identifier], "result": json.loads(row["result"])})
                vmware_scans = matrix_vmware_scan_pairs(
                    headers.values(), project_id=project_id, selected_site_id=selected_site_id,
                ) if vmware_policy_ids else ()
                requested_ids = _json(sorted(vmware_policy_ids))
                for identifier, earlier in vmware_scans:
                    if cancelled is not None and cancelled():
                        return tuple(scans)
                    header = headers[identifier]
                    records = self._matrix_vmware_records(
                        db, project_id, identifier, requested_ids, vmware_policy_ids,
                    ) if header["state"] in {"completed", "partial"} else ()
                    missing = vmware_policy_ids.difference(record["id"] for _, record in records)
                    previous_ids = self._previous_matrix_vmware_policy_ids(
                        db, project_id, earlier, missing,
                    ) if earlier is not None and missing else ()
                    scans.append({
                        **header, "matrix_vmware_records": records, "matrix_vmware_previous_policy_ids": previous_ids,
                    })
        except sqlite3.OperationalError as error:
            if not (cancelled is not None and cancelled() and str(error) == "interrupted"):
                raise
        return tuple(scans)

    def latest_matrix_vmware_policy_records(
        self, project_id: str, selected_site_id: str | None, *, cancelled: Callable[[], bool] | None = None,
    ) -> tuple[tuple[dict[str, Any], tuple[dict[str, Any], ...]], ...]:
        """Index selectable Edge policies without decoding complete Firewall bodies."""
        from firewall_compliance.application.matrix_scope_cloud import latest_matrix_vmware_scan_ids

        if selected_site_id == "" or (cancelled is not None and cancelled()):
            return ()
        headers = {row["id"]: row for row in self.list_cloud_scan_headers(project_id)}
        selected = latest_matrix_vmware_scan_ids(
            headers.values(), project_id=project_id, selected_site_id=selected_site_id,
        )
        output = []
        try:
            with self._connect() as db:
                if cancelled is not None:
                    db.set_progress_handler(lambda: int(cancelled()), 10_000)
                for scan_id in selected:
                    if cancelled is not None and cancelled():
                        break
                    header = headers[scan_id]
                    records = self._matrix_vmware_policy_metadata(db, project_id, scan_id) if header["state"] in {
                        "completed", "partial",
                    } else ()
                    output.append((header, records))
        except sqlite3.OperationalError as error:
            if not (cancelled is not None and cancelled() and str(error) == "interrupted"):
                raise
        return tuple(output)

    @staticmethod
    def _matrix_vmware_policy_metadata(
        db: sqlite3.Connection, project_id: str, scan_id: str,
    ) -> tuple[dict[str, Any], ...]:
        try:
            rows = db.execute(
                """WITH edges AS (
                       SELECT entry.key AS record_index, json_extract(entry.value,'$.id') AS id,
                              json_extract(entry.value,'$.name') AS name,
                              COALESCE(json_extract(entry.value,'$.inventory.orgVdc.name'),
                                       json_extract(entry.value,'$.inventory.vdcName'),
                                       json_extract(entry.value,'$.inventory.vdc.name'),
                                       json_extract(entry.value,'$.inventory.ownerRef.name')) AS vdc,
                              json_type(entry.value,'$.data.firewall.userDefinedRules') AS firewall_type
                       FROM cloud_scans AS scan JOIN json_each(scan.result,'$.records') AS entry
                       WHERE scan.project_id=? AND scan.id=? AND json_type(scan.result,'$.records')='array'
                         AND entry.type='object' AND json_extract(entry.value,'$.type')='edges'
                         AND json_type(entry.value,'$.id')='text'
                   ) SELECT id,name,vdc,record_index FROM edges GROUP BY id
                   HAVING count(*)=1 AND firewall_type IS NOT NULL AND firewall_type!='null'
                   ORDER BY record_index""",
                (project_id, scan_id),
            )
            return tuple(dict(row) for row in rows)
        except sqlite3.OperationalError as error:
            if not _cloud_projection_unavailable(error):
                raise
        row = db.execute("SELECT result FROM cloud_scans WHERE project_id=? AND id=?", (project_id, scan_id)).fetchone()
        result = json.loads(row["result"]) if row is not None else None
        records = result.get("records") if isinstance(result, dict) else None
        if not isinstance(records, list):
            return ()
        indexed: dict[str, list[tuple[int, dict[str, Any]]]] = {}
        for index, record in enumerate(records):
            if isinstance(record, dict) and record.get("type") == "edges" and isinstance(record.get("id"), str):
                indexed.setdefault(record["id"], []).append((index, record))
        available = []
        for identifier, matches in indexed.items():
            if len(matches) != 1:
                continue
            index, record = matches[0]
            data, inventory = record.get("data"), record.get("inventory")
            firewall = data.get("firewall") if isinstance(data, dict) else None
            if isinstance(firewall, dict) and firewall.get("userDefinedRules") is not None:
                vdc = None
                if isinstance(inventory, dict):
                    org = inventory.get("orgVdc")
                    other = (inventory.get(key) for key in ("vdc", "ownerRef"))
                    vdc = next((
                        value for value in (
                            org.get("name") if isinstance(org, dict) else None, inventory.get("vdcName"),
                            *(ref.get("name") for ref in other if isinstance(ref, dict)),
                        ) if isinstance(value, str) and value.strip()
                    ), None)
                available.append({
                    "id": identifier, "name": record.get("name"), "record_index": index,
                    "vdc": vdc,
                })
        return tuple(available)

    @staticmethod
    def _matrix_vmware_records(
        db: sqlite3.Connection, project_id: str, scan_id: str,
        requested_ids: str, policy_ids: frozenset[str],
    ) -> tuple[tuple[int, dict[str, Any]], ...]:
        """Проецировать точные ID политик, сохраняя их индексы в исходном сборе."""
        try:
            rows = db.execute(
                """SELECT entry.key AS record_index,entry.value AS record
                   FROM cloud_scans AS scan JOIN json_each(scan.result,'$.records') AS entry
                   WHERE scan.project_id=? AND scan.id=? AND entry.type='object'
                     AND json_type(scan.result,'$.records')='array'
                     AND json_extract(entry.value,'$.type')='edges'
                     AND json_type(entry.value,'$.id')='text'
                     AND json_extract(entry.value,'$.id') IN (SELECT value FROM json_each(?))
                   ORDER BY entry.key""",
                (project_id, scan_id, requested_ids),
            )
            return tuple((row["record_index"], json.loads(row["record"])) for row in rows)
        except sqlite3.OperationalError as error:
            if not _cloud_projection_unavailable(error):
                raise
        row = db.execute("SELECT result FROM cloud_scans WHERE id=? AND project_id=?", (scan_id, project_id)).fetchone()
        result = json.loads(row["result"]) if row is not None else None
        records = result.get("records") if isinstance(result, dict) else None
        return tuple(
            (index, record) for index, record in enumerate(records)
            if isinstance(record, dict) and record.get("type") == "edges"
            and isinstance(record.get("id"), str) and record["id"] in policy_ids
        ) if isinstance(records, list) else ()

    @staticmethod
    def _previous_matrix_vmware_policy_ids(
        db: sqlite3.Connection, project_id: str, scan_id: str, policy_ids: frozenset[str],
    ) -> tuple[str, ...]:
        """Проверить наличие точных ID без загрузки тел прежних правил."""
        requested_ids = _json(sorted(policy_ids))
        try:
            rows = db.execute(
                """SELECT DISTINCT json_extract(entry.value,'$.id') AS policy_id
                   FROM cloud_scans AS scan JOIN json_each(scan.result,'$.records') AS entry
                   WHERE scan.project_id=? AND scan.id=? AND entry.type='object'
                     AND json_type(scan.result,'$.records')='array'
                     AND json_extract(entry.value,'$.type')='edges'
                     AND json_type(entry.value,'$.id')='text'
                     AND json_extract(entry.value,'$.id') IN (SELECT value FROM json_each(?))
                   ORDER BY policy_id""",
                (project_id, scan_id, requested_ids),
            )
            return tuple(row["policy_id"] for row in rows)
        except sqlite3.OperationalError as error:
            if not _cloud_projection_unavailable(error):
                raise
        records = ProjectStore._matrix_vmware_records(db, project_id, scan_id, requested_ids, policy_ids)
        return tuple(sorted({record["id"] for _, record in records}))

    def save_cloud_analysis(
        self, scan_id: str, payloads: list[dict[str, Any]], settings: dict[str, Any]
    ) -> str:
        """Atomically link derived reports to an immutable scan using existing run/item tables."""
        if not payloads or any(
            p.get("cloud_origin", {}).get("scan_id") != scan_id for p in payloads
        ):
            raise ValueError("Результат проверки не соответствует исходному сбору.")
        from firewall_compliance.interfaces.desktop.profile_history import LegacyProfileHistory
        from firewall_compliance.application.source_health import configuration_fingerprint

        run_id = str(uuid4())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            scan = db.execute(
                "SELECT project_id,config,selection,state FROM cloud_scans WHERE id=?", (scan_id,)
            ).fetchone()
            if scan is None:
                raise ValueError("Исходный облачный сбор не найден.")
            snapshot = {**settings, "cloud_scan_id": scan_id, "analysis_source": "cloud_ru_vmware"}
            configuration = json.loads(scan["config"])
            if configuration.get("platform", "vmware") != "vmware":
                raise ValueError("Этот результат не относится к VMware-сбору.")
            snapshot.update({
                "source_id": "cloud_ru_vmware",
                "source_config_fingerprint": configuration_fingerprint(configuration),
                "source_selection_fingerprint": configuration_fingerprint(json.loads(scan["selection"])),
                "source_collection_state": scan["state"],
            })
            if LegacyProfileHistory.is_initialized(db):
                profile = LegacyProfileHistory.record_on_connection(db, scan["project_id"], snapshot)
                snapshot.update({
                    "workspace_profile_version": profile.version,
                    "workspace_profile_fingerprint": profile.fingerprint,
                })
            db.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?)",
                (run_id, scan["project_id"], _now(), _now(), "completed", _json(snapshot)),
            )
            for payload in payloads:
                db.execute(
                    "INSERT INTO items VALUES (?,?,?)", (str(uuid4()), run_id, _json(payload))
                )
        return run_id

    def cloud_analysis_runs(self, scan_id: str, project_id: str) -> list[str]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT id,settings FROM runs WHERE project_id=? "
                "ORDER BY created_at DESC,rowid DESC",
                (project_id,),
            ).fetchall()
        return [
            row["id"] for row in rows if json.loads(row["settings"]).get("cloud_scan_id") == scan_id
        ]

    def list_projects(self) -> list[dict[str, Any]]:
        """Получить проекты, начиная с последнего созданного."""
        with self._connect() as db:
            rows = db.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
        return [{**dict(row), "settings": json.loads(row["settings"])} for row in rows]

    def get_project(self, project_id: str) -> dict[str, Any]:
        """Получить проект или сообщить об отсутствующем идентификаторе."""
        for project in self.list_projects():
            if project["id"] == project_id:
                return project
        raise KeyError("Проект не найден")

    def update_settings(self, project_id: str, settings: dict[str, Any]) -> None:
        """Обновить параметры будущих запусков, сохранив настройки предыдущих."""
        merged = {**self.get_project(project_id)["settings"], **settings}
        with self._connect() as db:
            db.execute("UPDATE projects SET settings=? WHERE id=?", (_json(merged), project_id))

    def create_run(
        self, project_id: str, *, settings: Mapping[str, Any] | None = None
    ) -> str:
        """Зафиксировать параметры запуска и профиль одной транзакцией.

        Явные параметры перекрывают сохранённые только в снимке запуска:
        настройки проекта и решения предыдущих запусков не изменяются.
        """
        from firewall_compliance.interfaces.desktop.profile_history import LegacyProfileHistory

        if settings is not None and not isinstance(settings, Mapping):
            raise TypeError("Параметры запуска должны быть отображением")
        overrides = (
            json.loads(json.dumps(dict(settings), ensure_ascii=False, allow_nan=False))
            if settings is not None else {}
        )
        run_id = str(uuid4())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            project = db.execute("SELECT settings FROM projects WHERE id=?", (project_id,)).fetchone()
            if project is None:
                raise KeyError("Проект не найден")
            snapshot_settings = {**json.loads(project["settings"]), **overrides}
            if LegacyProfileHistory.is_initialized(db):
                profile = LegacyProfileHistory.record_on_connection(
                    db, project_id, snapshot_settings
                )
                snapshot_settings = {
                    **snapshot_settings,
                    "workspace_profile_version": profile.version,
                    "workspace_profile_fingerprint": profile.fingerprint,
                }
            db.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?)",
                (
                    run_id,
                    project_id,
                    _now(),
                    None,
                    "running",
                    _json(snapshot_settings),
                ),
            )
        return run_id

    def finish_run(
        self, run_id: str, state: str = "completed", *, source_collection_state: str | None = None
    ) -> None:
        """Зафиксировать завершение или отмену пакета."""
        if state not in {"completed", "cancelled", "interrupted"}:
            raise ValueError("Неизвестное состояние запуска")
        with self._connect() as db:
            if source_collection_state is None:
                db.execute("UPDATE runs SET state=?,finished_at=? WHERE id=?", (state, _now(), run_id))
                return
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT settings FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                raise ValueError("Запуск не найден")
            settings = {**json.loads(row["settings"]), "source_collection_state": source_collection_state}
            db.execute(
                "UPDATE runs SET state=?,finished_at=?,settings=? WHERE id=?",
                (state, _now(), _json(settings), run_id),
            )

    def _record(self, run_id: str, payload: dict[str, Any]) -> str:
        item_id = str(uuid4())
        with self._connect() as db:
            db.execute("INSERT INTO items VALUES (?,?,?)", (item_id, run_id, _json(payload)))
        return item_id

    def record_session(
        self, run_id: str, session: AnalysisSession, *, collection_warnings: tuple[str, ...] = ()
    ) -> str:
        """Сохранить нормализованный снимок и ограниченные фрагменты доказательств."""
        report = session.report
        partial = (
            bool(report.parse_errors or report.unsupported_constructs)
            or any(
                check.status.value == "partial"
                or any(limit.code == "CHECK_NOT_EXECUTED" for limit in check.limitations)
                for check in report.checks
            )
            or report.parse_coverage.coverage_ratio < 1
        )
        return self._record(
            run_id,
            {
                "path": str(session.path),
                "source_name": session.source.source_name,
                "content_sha256": session.source.content_sha256,
                "status": "partial" if partial else "complete",
                "report": report.model_dump(mode="json"),
                "parse_result": session.parse_result.model_dump(mode="json"),
                "revision": session.revision.model_dump(mode="json"),
                "excerpts": _excerpts(session),
                "collection_warnings": list(collection_warnings),
                "diagnostics": [
                    x.model_dump(mode="json")
                    for x in (
                        *report.parse_warnings,
                        *report.parse_errors,
                        *report.unsupported_constructs,
                    )
                ] + [
                    {"code": "COLLECTION_COUNT_DROP", "message": message}
                    for message in collection_warnings
                ],
            },
        )

    def record_failure(self, run_id: str, path: Path, failure: ParseFailure) -> str:
        """Сохранить явный отказ парсера без создания ложной конфигурации."""
        return self._record(
            run_id,
            {
                "path": str(path),
                "source_name": failure.source_name,
                "content_sha256": failure.content_sha256,
                "status": "unsupported",
                "report": None,
                "parse_result": None,
                "excerpts": [],
                "diagnostics": [
                    x.model_dump(mode="json") for x in (*failure.errors, *failure.warnings)
                ],
            },
        )

    def record_error(self, run_id: str, path: Path, message: str) -> str:
        """Сохранить безопасное сообщение инфраструктурной ошибки."""
        return self._record(
            run_id,
            {
                "path": str(path),
                "source_name": path.name,
                "content_sha256": None,
                "status": "error",
                "report": None,
                "parse_result": None,
                "excerpts": [],
                "diagnostics": [{"code": "IMPORT_ERROR", "message": message}],
            },
        )

    def record_cancelled(self, run_id: str, path: Path) -> str:
        """Зафиксировать файл, отменённый до начала выполнения."""
        return self._record(
            run_id,
            {
                "path": str(path),
                "source_name": path.name,
                "content_sha256": None,
                "status": "canceled",
                "report": None,
                "parse_result": None,
                "excerpts": [],
                "diagnostics": [
                    {"code": "IMPORT_CANCELLED", "message": "Задание отменено до запуска"}
                ],
            },
        )

    def list_runs(self, project_id: str) -> list[dict[str, Any]]:
        """История запусков проекта."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM runs WHERE project_id=? ORDER BY created_at DESC", (project_id,)
            ).fetchall()
            counts = db.execute(
                """SELECT i.run_id,i.payload FROM items i JOIN runs r ON i.run_id=r.id
                   WHERE r.project_id=?""",
                (project_id,),
            ).fetchall()
        totals: dict[str, list[int]] = {}
        for item in counts:
            count = totals.setdefault(item["run_id"], [0, 0])
            count[0] += 1
            report = json.loads(item["payload"])["report"]
            if report:
                count[1] += sum(len(check["findings"]) for check in report["checks"])
        return [
            {
                **dict(row),
                "settings": json.loads(row["settings"]),
                "item_count": totals.get(row["id"], [0, 0])[0],
                "finding_count": totals.get(row["id"], [0, 0])[1],
            }
            for row in rows
        ]

    def get_run(self, run_id: str) -> dict[str, Any]:
        """Загрузить инвентарь, исходные отчёты и отдельные пользовательские решения."""
        with self._connect() as db:
            row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                raise KeyError("Запуск не найден")
            items = db.execute(
                "SELECT id,payload FROM items WHERE run_id=? ORDER BY rowid", (run_id,)
            ).fetchall()
            marks = db.execute("SELECT * FROM marks WHERE run_id=?", (run_id,)).fetchall()
        return {
            **dict(row),
            "settings": json.loads(row["settings"]),
            "items": [{"id": item["id"], **json.loads(item["payload"])} for item in items],
            "marks": {
                mark["finding_id"]: {
                    "status": mark["status"],
                    "comment": mark["comment"],
                    "updated_at": mark["updated_at"],
                }
                for mark in marks
            },
        }

    def get_run_item(
        self, project_id: str, run_id: str, item_id: str,
    ) -> dict[str, Any] | None:
        """Read one saved item within its original project and run."""
        with self._connect() as db:
            row = db.execute(
                """SELECT i.payload,r.created_at FROM items i JOIN runs r ON r.id=i.run_id
                   WHERE r.project_id=? AND r.id=? AND i.id=?""",
                (project_id, run_id, item_id),
            ).fetchone()
        if row is None:
            return None
        return {
            **json.loads(row["payload"]),
            "id": item_id, "run_id": run_id, "run_created_at": row["created_at"],
        }

    def get_run_item_with_header(
        self, project_id: str, run_id: str, item_id: str,
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """Прочитать точный элемент и профиль завершившегося запуска одним запросом."""
        with self._connect() as db:
            row = db.execute(
                """SELECT r.id,r.project_id,r.created_at,r.finished_at,r.state,r.settings,i.payload
                   FROM items i JOIN runs r ON r.id=i.run_id
                   WHERE r.project_id=? AND r.id=? AND i.id=? AND r.state!='running' AND r.finished_at IS NOT NULL""",
                (project_id, run_id, item_id),
            ).fetchone()
        if row is None:
            return None
        header = {key: row[key] for key in ("id", "project_id", "created_at", "finished_at", "state")}
        header["settings"] = json.loads(row["settings"])
        item = {**json.loads(row["payload"]), "id": item_id, "run_id": run_id, "run_created_at": row["created_at"]}
        return header, item

    def list_project_devices(self, project_id: str) -> list[dict[str, Any]]:
        """Последний разобранный снимок каждого устройства во всей истории проекта.

        Ошибки и неподдержанные файлы не создают устройства и не заменяют
        предыдущий пригодный снимок. Частично разобранные снимки остаются видимыми
        со своей диагностикой. Отчёты и пользовательские решения не изменяются.
        """
        self.get_project(project_id)
        with self._connect() as db:
            rows = db.execute(
                """SELECT i.id,i.run_id,i.payload,r.created_at AS run_created_at
                   FROM items i JOIN runs r ON i.run_id=r.id
                   WHERE r.project_id=?
                   ORDER BY r.created_at DESC,r.rowid DESC,i.rowid DESC""",
                (project_id,),
            ).fetchall()
        devices: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows:
            payload = json.loads(row["payload"])
            report = payload.get("report")
            if not report:
                continue
            device_id = report["device_id"]
            if device_id in seen:
                continue
            seen.add(device_id)
            devices.append(
                {
                    **payload,
                    "id": row["id"],
                    "run_id": row["run_id"],
                    "run_created_at": row["run_created_at"],
                }
            )
        return devices

    def set_finding_mark(
        self, run_id: str, finding_id: str, status: str, comment: str = ""
    ) -> None:
        """Atomically save a changed decision and append history, preserving analyzer results."""
        status = FindingStatus(status).value
        if not isinstance(comment, str) or "\x00" in comment:
            raise ValueError("Комментарий должен быть текстом без нулевых символов")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute("SELECT project_id FROM runs WHERE id=?", (run_id,)).fetchone()
            if run is None:
                raise KeyError("Запуск не найден")
            project_id = run["project_id"]
            original = self._finding_state(db, project_id, run_id, finding_id)
            previous = db.execute(
                "SELECT status,comment,updated_at FROM marks WHERE run_id=? AND finding_id=?",
                (run_id, finding_id),
            ).fetchone()
            before = dict(previous) if previous is not None else original
            if (before["status"], before["comment"]) == (status, comment):
                return
            changed_at = _now()
            db.execute(
                "INSERT OR IGNORE INTO finding_mark_baselines VALUES (?,?,?,?,?,?,?,?)",
                (
                    project_id,
                    run_id,
                    finding_id,
                    before["status"],
                    before["comment"],
                    before["updated_at"],
                    "legacy_mark" if previous else "original_report",
                    changed_at,
                ),
            )
            db.execute(
                "INSERT OR REPLACE INTO marks VALUES (?,?,?,?,?)",
                (run_id, finding_id, status, comment, changed_at),
            )
            db.execute(
                "INSERT INTO finding_mark_transitions "
                "(project_id,run_id,finding_id,changed_at,previous_status,previous_comment,"
                "new_status,new_comment) VALUES (?,?,?,?,?,?,?,?)",
                (
                    project_id,
                    run_id,
                    finding_id,
                    changed_at,
                    before["status"],
                    before["comment"],
                    status,
                    comment,
                ),
            )

    @staticmethod
    def _finding_state(
        db: sqlite3.Connection, project_id: str, run_id: str, finding_id: str
    ) -> dict[str, Any]:
        run = db.execute(
            "SELECT id FROM runs WHERE project_id=? AND id=?", (project_id, run_id)
        ).fetchone()
        if run is None:
            raise KeyError("Запуск не найден в выбранном проекте")
        for row in db.execute("SELECT payload FROM items WHERE run_id=?", (run_id,)):
            report = json.loads(row["payload"]).get("report")
            if report:
                for check in report["checks"]:
                    for finding in check["findings"]:
                        if str(finding["finding_id"]) == finding_id:
                            return {"status": finding["status"], "comment": "", "updated_at": None}
        raise KeyError("Находка не принадлежит запуску")

    def list_finding_transitions(
        self, project_id: str, run_id: str | None = None, finding_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Read project-scoped user transitions in commit order, including comment-only edits."""
        with self._connect() as db:
            if db.execute("SELECT id FROM projects WHERE id=?", (project_id,)).fetchone() is None:
                raise KeyError("Проект не найден")
            if (
                run_id is not None
                and db.execute(
                    "SELECT id FROM runs WHERE project_id=? AND id=?", (project_id, run_id)
                ).fetchone()
                is None
            ):
                raise KeyError("Запуск не найден в выбранном проекте")
            rows = db.execute(
                "SELECT t.* FROM finding_mark_transitions t JOIN runs r ON r.id=t.run_id "
                "WHERE t.project_id=? AND r.project_id=? "
                "AND (? IS NULL OR t.run_id=?) AND (? IS NULL OR t.finding_id=?) "
                "ORDER BY t.sequence",
                (project_id, project_id, run_id, run_id, finding_id, finding_id),
            ).fetchall()
            return [dict(row) for row in rows]

    def finding_mark_timeline(
        self, project_id: str, run_id: str, finding_id: str
    ) -> dict[str, Any]:
        """Return a consistent baseline/events/current view without changing stored reports.

        legacy_mark baselines describe a saved state whose earlier history is unknown;
        updated_at is its original timestamp, history_started_at is activation time.
        """
        with self._connect() as db:
            db.execute("BEGIN")
            original = self._finding_state(db, project_id, run_id, finding_id)
            baseline_row = db.execute(
                "SELECT * FROM finding_mark_baselines "
                "WHERE project_id=? AND run_id=? AND finding_id=?",
                (project_id, run_id, finding_id),
            ).fetchone()
            baseline = (
                dict(baseline_row)
                if baseline_row
                else {
                    **original,
                    "kind": "original_report",
                    "history_started_at": None,
                }
            )
            events = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM finding_mark_transitions "
                    "WHERE project_id=? AND run_id=? AND finding_id=? ORDER BY sequence",
                    (project_id, run_id, finding_id),
                )
            ]
            mark = db.execute(
                "SELECT status,comment,updated_at FROM marks WHERE run_id=? AND finding_id=?",
                (run_id, finding_id),
            ).fetchone()
            return {
                "baseline": baseline,
                "events": events,
                "current": dict(mark) if mark else original,
                "history_complete": baseline["kind"] == "original_report",
            }

    def replay_finding_mark(
        self, project_id: str, run_id: str, finding_id: str, through_sequence: int | None = None
    ) -> dict[str, Any]:
        """Replay the saved baseline through a transition; never overwrite marks or report JSON."""
        if through_sequence is not None and (
            type(through_sequence) is not int or through_sequence < 0
        ):
            raise ValueError("Номер перехода должен быть неотрицательным целым числом")
        timeline = self.finding_mark_timeline(project_id, run_id, finding_id)
        state = {key: timeline["baseline"][key] for key in ("status", "comment", "updated_at")}
        for event in timeline["events"]:
            if through_sequence is None or event["sequence"] <= through_sequence:
                state = {
                    "status": event["new_status"],
                    "comment": event["new_comment"],
                    "updated_at": event["changed_at"],
                }
        return state

    def confirm_device(self, project_id: str, source_key: str, device_id: str) -> None:
        """Запомнить только подтверждённое пользователем соответствие."""
        if not source_key.strip() or not device_id.strip():
            raise ValueError("Имя источника и идентификатор устройства обязательны")
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO device_links VALUES (?,?,?)",
                (
                    project_id,
                    source_key.casefold(),
                    device_id.strip(),
                ),
            )

    def suggest_device(self, project_id: str, source_key: str) -> str | None:
        """Вернуть подтверждённое соответствие, не угадывая неоднозначные устройства."""
        with self._connect() as db:
            row = db.execute(
                "SELECT device_id FROM device_links WHERE project_id=? AND source_key=?",
                (project_id, source_key.casefold()),
            ).fetchone()
        return str(row[0]) if row else None

    def attach_source(self, item_id: str, path: Path) -> AnalysisSession:
        """Восстановить сессию только с исходником, совпадающим по SHA-256."""
        with self._connect() as db:
            row = db.execute("SELECT payload FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise KeyError("Снимок не найден")
        item = json.loads(row[0])
        if not item["report"]:
            raise ValueError("Для этого файла нет сохранённого результата анализа")
        source = FileSourceReader().read(path)
        if source.content_sha256 != item["content_sha256"]:
            raise SourceMismatchError(
                "SHA-256 отличается: изменённый файл требует нового запуска анализа"
            )
        source = source.model_copy(update={"source_name": item["source_name"]})
        return AnalysisSession(
            UUID(item_id),
            path.resolve(),
            source,
            ParseResult.model_validate(item["parse_result"]),
            DeviceRevision.model_validate(item["revision"]),
            FirewallAssuranceResult.model_validate(item["report"]),
        )
