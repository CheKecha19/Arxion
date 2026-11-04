"""Локальные проекты и результаты без хранения полного исходного документа."""

import json
import os
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
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
    from firewall_compliance.domain.acl_map import AclMap
    from firewall_compliance.interfaces.desktop.resource_registry import ResourceRegistry
    from firewall_compliance.interfaces.desktop.workspace_store import WorkspaceMetadataStore


class SourceMismatchError(ValueError):
    """Выбранный документ отличается от исходника сохранённого снимка."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def default_database_path() -> Path:
    """Путь в личном профиле Windows; исходные конфигурации сюда не копируются."""
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local" / "share")))
    return base / "FirewallCompliance" / "projects.sqlite3"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


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
    def workspace_metadata(self) -> "WorkspaceMetadataStore":
        """Access optional site metadata without implicitly migrating the database."""
        from firewall_compliance.interfaces.desktop.workspace_store import WorkspaceMetadataStore

        return WorkspaceMetadataStore(self)

    def project_history(self, project_id: str) -> list[dict[str, Any]]:
        """Read full saved run snapshots once for cumulative registry/dashboard projections."""
        with self._connect() as db:
            runs = db.execute(
                "SELECT * FROM runs WHERE project_id=? ORDER BY created_at DESC,rowid DESC",
                (project_id,),
            ).fetchall()
            items = db.execute(
                "SELECT i.id,i.run_id,i.payload FROM items i JOIN runs r ON r.id=i.run_id "
                "WHERE r.project_id=? ORDER BY i.rowid",
                (project_id,),
            ).fetchall()
            marks = db.execute(
                "SELECT m.* FROM marks m JOIN runs r ON r.id=m.run_id WHERE r.project_id=?",
                (project_id,),
            ).fetchall()
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

    def finish_run(self, run_id: str, state: str = "completed") -> None:
        """Зафиксировать завершение или отмену пакета."""
        if state not in {"completed", "cancelled", "interrupted"}:
            raise ValueError("Неизвестное состояние запуска")
        with self._connect() as db:
            db.execute("UPDATE runs SET state=?,finished_at=? WHERE id=?", (state, _now(), run_id))

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
