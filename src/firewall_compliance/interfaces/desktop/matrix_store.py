"""Explicit backed-up append-only matrix history for legacy project origins."""

from collections.abc import Callable, Collection, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from firewall_compliance.application.cloud_sg_policy import ADVANCED_MULTI_ORDERED_PROJECTION
from firewall_compliance.application.cloud_sg_revision import CloudSGSelection, cloud_sg_policy_id
from firewall_compliance.application.matrix_artifact import MatrixAssessmentArtifact
from firewall_compliance.domain.access_matrix import AccessMatrix
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.organization_backup import create_workspace_backup
from firewall_compliance.interfaces.desktop.organization_lock import workspace_lease


@dataclass(frozen=True, slots=True)
class MatrixVersionRecord:
    matrix: AccessMatrix
    created_at: str
    checksum: str


@dataclass(frozen=True, slots=True)
class MatrixVersionSummary:
    version: str
    created_at: str
    checksum: str


@dataclass(frozen=True, slots=True)
class MatrixAssessmentSummary:
    artifact_id: str
    created_at: str
    matrix_version: str
    revision_id: str
    device_label: str


class AccessMatrixStore:
    def __init__(self, store_path: Path) -> None:
        self.path = store_path

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True, timeout=15)
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def _schema_version(db: sqlite3.Connection) -> int:
        if db.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise ValueError("Unsupported legacy workspace")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "org_context" in tables:
            raise ValueError("Transfer matrix history before organization activation")
        if "workspace_matrix_meta" not in tables:
            if {"workspace_matrix_versions", "workspace_matrix_assessments"}.intersection(tables):
                raise ValueError("Incomplete matrix history schema")
            return 0
        rows = db.execute("SELECT singleton,version FROM workspace_matrix_meta").fetchall()
        if rows not in ([(1, 1)], [(1, 2)]) or "workspace_matrix_versions" not in tables:
            raise ValueError("Unsupported matrix history schema")
        version = int(rows[0][1])
        if version == 2 and "workspace_matrix_assessments" not in tables:
            raise ValueError("Incomplete matrix assessment schema")
        if version == 1 and "workspace_matrix_assessments" in tables:
            raise ValueError("Unversioned matrix assessment schema")
        return version

    def initialize(self) -> Path | None:
        with workspace_lease(self.path):
            db = self._connect()
            try:
                if self._schema_version(db) == 2:
                    return None
                backup = self.path.with_name(f"{self.path.name}.before-matrices-{uuid4().hex}.sqlite3")
                create_workspace_backup(self.path, backup)
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    version = self._schema_version(db)
                    if version == 2:
                        return backup
                    if version == 0:
                        self._create_history(db)
                    db.execute("CREATE TABLE workspace_matrix_assessments ("
                               "artifact_id TEXT PRIMARY KEY,project_id TEXT NOT NULL,"
                               "matrix_version INTEGER NOT NULL,revision_id TEXT NOT NULL,"
                               "device_label TEXT NOT NULL,created_at TEXT NOT NULL,"
                               "origin_run_id TEXT,"
                               "payload TEXT NOT NULL,checksum TEXT NOT NULL,"
                               "FOREIGN KEY(project_id,matrix_version) "
                               "REFERENCES workspace_matrix_versions(project_id,version))")
                    db.execute("CREATE INDEX workspace_matrix_assessments_project "
                               "ON workspace_matrix_assessments(project_id,created_at)")
                    db.execute("CREATE INDEX workspace_matrix_assessments_run "
                               "ON workspace_matrix_assessments(project_id,origin_run_id)")
                    self._immutable(db, "workspace_matrix_assessments")
                    db.execute("UPDATE workspace_matrix_meta SET version=2 WHERE singleton=1")
                return backup
            finally:
                db.close()

    @staticmethod
    def _immutable(db: sqlite3.Connection, table: str) -> None:
        statements = {
            "workspace_matrix_versions": (
                "CREATE TRIGGER workspace_matrix_versions_no_update BEFORE UPDATE ON "
                "workspace_matrix_versions BEGIN SELECT RAISE(ABORT,'Matrix history is immutable'); END",
                "CREATE TRIGGER workspace_matrix_versions_no_delete BEFORE DELETE ON "
                "workspace_matrix_versions BEGIN SELECT RAISE(ABORT,'Matrix history is immutable'); END",
            ),
            "workspace_matrix_assessments": (
                "CREATE TRIGGER workspace_matrix_assessments_no_update BEFORE UPDATE ON "
                "workspace_matrix_assessments BEGIN SELECT RAISE(ABORT,'Assessment is immutable'); END",
                "CREATE TRIGGER workspace_matrix_assessments_no_delete BEFORE DELETE ON "
                "workspace_matrix_assessments BEGIN SELECT RAISE(ABORT,'Assessment is immutable'); END",
            ),
        }
        if table not in statements:
            raise ValueError("Unknown immutable matrix table")
        for statement in statements[table]:
            db.execute(statement)

    @classmethod
    def _create_history(cls, db: sqlite3.Connection) -> None:
        db.execute("CREATE TABLE workspace_matrix_meta "
                   "(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL)")
        db.execute("INSERT INTO workspace_matrix_meta VALUES(1,1)")
        db.execute("CREATE TABLE workspace_matrix_versions ("
                   "project_id TEXT NOT NULL REFERENCES projects(id),"
                   "version INTEGER NOT NULL CHECK(version>0),"
                   "payload TEXT NOT NULL,checksum TEXT NOT NULL,created_at TEXT NOT NULL,"
                   "PRIMARY KEY(project_id,version))")
        cls._immutable(db, "workspace_matrix_versions")

    def list_versions(self, project_id: str) -> tuple[MatrixVersionRecord, ...]:
        db = self._connect()
        try:
            if not self._schema_version(db):
                return ()
            rows = db.execute(
                "SELECT version,payload,checksum,created_at FROM workspace_matrix_versions "
                "WHERE project_id=? ORDER BY version", (project_id,),
            ).fetchall()
        finally:
            db.close()
        return tuple(self._decode_version(*row) for row in rows)

    @staticmethod
    def _decode_version(version: int, payload: str, checksum: str, created_at: str) -> MatrixVersionRecord:
        if sha256(payload.encode("utf-8")).hexdigest() != checksum:
            raise ValueError("Matrix checksum mismatch")
        matrix = AccessMatrix.model_validate_json(payload)
        if matrix.version != str(version):
            raise ValueError("Matrix version mismatch")
        return MatrixVersionRecord(matrix, created_at, checksum)

    def list_version_summaries(self, project_id: str) -> tuple[MatrixVersionSummary, ...]:
        db = self._connect()
        try:
            if not self._schema_version(db):
                return ()
            rows = db.execute(
                "SELECT version,created_at,checksum FROM workspace_matrix_versions "
                "WHERE project_id=? ORDER BY version", (project_id,),
            ).fetchall()
            return tuple(MatrixVersionSummary(str(version), created_at, checksum) for version, created_at, checksum in rows)
        finally:
            db.close()

    def get_version(self, project_id: str, version: str) -> MatrixVersionRecord:
        db = self._connect()
        try:
            row = db.execute(
                "SELECT version,payload,checksum,created_at FROM workspace_matrix_versions "
                "WHERE project_id=? AND version=?", (project_id, version),
            ).fetchone() if self._schema_version(db) else None
            if row is None:
                raise ValueError("Matrix version was not found in this project")
            return self._decode_version(*row)
        finally:
            db.close()

    def append(self, project_id: str, matrix: AccessMatrix) -> MatrixVersionRecord:
        matrix = AccessMatrix.model_validate(matrix.model_dump(mode="python"))
        db = self._connect()
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                if not self._schema_version(db):
                    raise ValueError("Initialize matrix history explicitly before saving")
                previous = db.execute(
                    "SELECT version FROM workspace_matrix_versions WHERE project_id=? "
                    "ORDER BY version DESC LIMIT 1", (project_id,),
                ).fetchone()
                version = previous[0] + 1 if previous else 1
                payload = matrix.model_dump(mode="json")
                payload["version"] = str(version)
                saved = AccessMatrix.model_validate(payload)
                encoded = json.dumps(saved.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
                checksum = sha256(encoded.encode("utf-8")).hexdigest()
                created_at = datetime.now(UTC).isoformat()
                db.execute("INSERT INTO workspace_matrix_versions VALUES(?,?,?,?,?)",
                           (project_id, version, encoded, checksum, created_at))
            return MatrixVersionRecord(saved, created_at, checksum)
        finally:
            db.close()

    def save_assessment(self, artifact: MatrixAssessmentArtifact) -> str:
        artifact = MatrixAssessmentArtifact.model_validate(artifact.model_dump(mode="python"))
        encoded = json.dumps(artifact.model_dump(mode="json"), sort_keys=True, ensure_ascii=False)
        checksum = sha256(encoded.encode("utf-8")).hexdigest()
        db = self._connect()
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                if self._schema_version(db) != 2:
                    raise ValueError("Initialize assessment history explicitly before saving")
                row = db.execute(
                    "SELECT payload,checksum FROM workspace_matrix_versions "
                    "WHERE project_id=? AND version=?",
                    (artifact.origin_project_id, artifact.matrix.version),
                ).fetchone()
                if row is None or sha256(row[0].encode("utf-8")).hexdigest() != row[1]:
                    raise ValueError("Saved matrix version is missing or corrupted")
                if AccessMatrix.model_validate_json(row[0]) != artifact.matrix:
                    raise ValueError("Assessment matrix differs from the saved version")
                if artifact.origin_run_id is not None:
                    origin = db.execute(
                        "SELECT project_id FROM runs WHERE id=?", (artifact.origin_run_id,),
                    ).fetchone()
                    if origin is None or origin[0] != artifact.origin_project_id:
                        raise ValueError("Assessment origin was not found in this project")
                    item = db.execute(
                        "SELECT payload FROM items WHERE id=? AND run_id=?",
                        (artifact.origin_item_id, artifact.origin_run_id),
                    ).fetchone()
                    if item is None:
                        raise ValueError("Assessment input item was not found in the run")
                    original = DeviceRevision.model_validate(json.loads(item[0]).get("revision"))
                    if original != artifact.revision:
                        raise ValueError("Assessment revision differs from the saved input item")
                elif artifact.cloud_selection is not None:
                    self._validate_cloud_input(db, artifact)
                device = artifact.revision.device
                db.execute(
                    "INSERT INTO workspace_matrix_assessments "
                    "(artifact_id,project_id,matrix_version,revision_id,device_label,created_at,"
                    "origin_run_id,payload,checksum) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        str(artifact.artifact_id), artifact.origin_project_id,
                        int(artifact.matrix.version), str(artifact.revision.revision_id),
                        device.hostname or device.device_id, artifact.created_at.isoformat(),
                        artifact.origin_run_id, encoded, checksum,
                    ),
                )
            return str(artifact.artifact_id)
        finally:
            db.close()

    @staticmethod
    def _validate_cloud_input(db: sqlite3.Connection, artifact: MatrixAssessmentArtifact) -> None:
        from firewall_compliance.application.cloud_security_groups import security_group_snapshot
        from firewall_compliance.application.cloud_sg_revision import cloud_sg_revision

        selection = artifact.cloud_selection
        if selection is None:
            raise ValueError("Cloud selection was not supplied")
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT * FROM cloud_scans WHERE id=? AND project_id=?",
            (selection.scan_id, artifact.origin_project_id),
        ).fetchone()
        if row is None:
            raise ValueError("Облачный источник сверки не найден в этом проекте")
        scan = {**dict(row), **{key: json.loads(row[key]) for key in ("config", "selection", "result")}}
        snapshot = security_group_snapshot(scan)
        if artifact.assessment.scope_id not in (artifact.origin_project_id, *snapshot.workspace_site_ids):
            raise ValueError("В сохранённом сборе нет привязки к площадке сверки")
        original = cloud_sg_revision(
            snapshot, selection, imported_at=artifact.revision.imported_at,
        )
        if original != artifact.revision:
            raise ValueError("Ревизия сверки отличается от сохранённых облачных данных")

    def list_assessments(
        self, project_id: str, *, limit: int = 100, offset: int = 0,
    ) -> tuple[MatrixAssessmentSummary, ...]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("Assessment history limit must be between 1 and 500")
        if type(offset) is not int or offset < 0:
            raise ValueError("Assessment history offset must be nonnegative")
        db = self._connect()
        try:
            if self._schema_version(db) < 2:
                return ()
            rows = db.execute(
                "SELECT artifact_id,created_at,matrix_version,revision_id,device_label "
                "FROM workspace_matrix_assessments WHERE project_id=? "
                "ORDER BY created_at DESC,artifact_id DESC LIMIT ? OFFSET ?", (project_id, limit, offset),
            ).fetchall()
            return tuple(MatrixAssessmentSummary(
                identifier, created_at, str(version), revision_id, label,
            ) for identifier, created_at, version, revision_id, label in rows)
        finally:
            db.close()

    def assessment_count(self, project_id: str) -> int:
        db = self._connect()
        try:
            if self._schema_version(db) < 2:
                return 0
            return int(db.execute(
                "SELECT count(*) FROM workspace_matrix_assessments WHERE project_id=?", (project_id,),
            ).fetchone()[0])
        finally:
            db.close()

    def assessment_summaries_for_version(
        self, project_id: str, version: str,
    ) -> tuple[MatrixAssessmentSummary, ...]:
        db = self._connect()
        try:
            if self._schema_version(db) < 2:
                return ()
            rows = db.execute(
                "SELECT artifact_id,created_at,matrix_version,revision_id,device_label "
                "FROM workspace_matrix_assessments WHERE project_id=? AND matrix_version=? "
                "ORDER BY created_at DESC,artifact_id DESC", (project_id, version),
            )
            return tuple(MatrixAssessmentSummary(
                identifier, created_at, str(saved_version), revision_id, label,
            ) for identifier, created_at, saved_version, revision_id, label in rows)
        finally:
            db.close()

    def assessment_ids_for_run(self, project_id: str, run_id: str) -> tuple[str, ...]:
        db = self._connect()
        try:
            if self._schema_version(db) < 2:
                return ()
            return tuple(row[0] for row in db.execute(
                "SELECT artifact_id FROM workspace_matrix_assessments "
                "WHERE project_id=? AND origin_run_id=? ORDER BY created_at,artifact_id",
                (project_id, run_id),
            ))
        finally:
            db.close()

    def cloud_order_selections(
        self, project_id: str, scope_id: str, scan_ids: Iterable[str], policy_ids: Collection[str], *,
        cancelled: Callable[[], bool] | None = None,
    ) -> tuple[CloudSGSelection, ...]:
        """Прочитать подтверждённые порядки Advanced из истории той же области."""
        requested_scans = set(scan_ids)
        if not requested_scans or not policy_ids or (cancelled is not None and cancelled()):
            return ()
        selections = []
        seen_orders = set()
        db = self._connect()
        if cancelled is not None:
            db.set_progress_handler(lambda: int(cancelled()), 10_000)
        try:
            if self._schema_version(db) < 2:
                return ()
            for identifier, payload in self._cloud_order_metadata(
                db, project_id, scope_id, requested_scans, cancelled=cancelled,
            ):
                if cancelled is not None and cancelled():
                    break
                try:
                    selection = CloudSGSelection.model_validate_json(payload)
                except ValueError:
                    continue
                order = selection.order_evidence
                if order is None:
                    continue
                policy = cloud_sg_policy_id(
                    selection.scope_id, "interface/" + selection.interface_id, selection.direction, selection.family,
                )
                key = (
                    selection.scan_id, policy, order.snapshot_sha256, order.observed_at, order.group_ids,
                )
                if policy not in policy_ids or key in seen_orders:
                    continue
                try:
                    artifact = self.get_assessment(project_id, identifier)
                except ValueError:
                    continue
                configuration = artifact.revision.parse_result.configuration
                if (
                    artifact.cloud_selection != selection or artifact.assessment.scope_id != scope_id
                    or configuration.parser_version != ADVANCED_MULTI_ORDERED_PROJECTION
                    or configuration.content_sha256 != order.snapshot_sha256
                    or configuration.captured_at != order.observed_at
                    or not any(rule.enabled and rule.policy_id == policy for rule in artifact.revision.parse_result.rules)
                ):
                    continue
                seen_orders.add(key)
                selections.append(selection)
        except sqlite3.OperationalError as error:
            if cancelled is None or not cancelled() or getattr(error, "sqlite_errorcode", None) != sqlite3.SQLITE_INTERRUPT:
                raise
        finally:
            db.close()
        return tuple(selections)

    @staticmethod
    def _cloud_order_metadata(
        db: sqlite3.Connection, project_id: str, scope_id: str, scan_ids: set[str], *,
        cancelled: Callable[[], bool] | None,
    ) -> Iterator[tuple[str, str]]:
        try:
            rows = db.execute(
                "SELECT artifact_id,json_extract(payload,'$.cloud_selection') "
                "FROM workspace_matrix_assessments WHERE project_id=? AND origin_run_id IS NULL "
                "AND CASE WHEN json_valid(payload) THEN "
                "json_extract(payload,'$.assessment.scope_id')=? "
                "AND json_type(payload,'$.cloud_selection.order_evidence')='object' "
                "AND json_extract(payload,'$.cloud_selection.scan_id') IN (SELECT value FROM json_each(?)) "
                "ELSE 0 END ORDER BY created_at DESC,artifact_id DESC",
                (project_id, scope_id, json.dumps(sorted(scan_ids))),
            )
        except sqlite3.OperationalError as error:
            if not str(error).startswith(("no such function: json_", "no such table: json_each")):
                raise
        else:
            yield from rows
            return
        for identifier, payload in db.execute(
            "SELECT artifact_id,payload FROM workspace_matrix_assessments "
            "WHERE project_id=? AND origin_run_id IS NULL ORDER BY created_at DESC,artifact_id DESC",
            (project_id,),
        ):
            if cancelled is not None and cancelled():
                return
            try:
                value = json.loads(payload)
            except ValueError:
                continue
            if not isinstance(value, dict):
                continue
            selection, assessment = value.get("cloud_selection"), value.get("assessment")
            if (
                isinstance(selection, dict) and isinstance(assessment, dict)
                and assessment.get("scope_id") == scope_id
                and isinstance(scan_id := selection.get("scan_id"), str) and scan_id in scan_ids
                and isinstance(selection.get("order_evidence"), dict)
            ):
                yield identifier, json.dumps(selection, ensure_ascii=False)

    def get_assessment(self, project_id: str, artifact_id: str) -> MatrixAssessmentArtifact:
        db = self._connect()
        try:
            if self._schema_version(db) < 2:
                raise ValueError("Assessment history has not been initialized")
            row = db.execute(
                "SELECT payload,checksum,matrix_version,revision_id,origin_run_id,created_at,device_label "
                "FROM workspace_matrix_assessments "
                "WHERE project_id=? AND artifact_id=?", (project_id, artifact_id),
            ).fetchone()
            if row is None:
                raise ValueError("Assessment was not found in this project")
            payload, checksum, version, revision_id, origin_run_id, created_at, device_label = row
            if sha256(payload.encode("utf-8")).hexdigest() != checksum:
                raise ValueError("Assessment checksum mismatch")
            artifact = MatrixAssessmentArtifact.model_validate_json(payload)
            if (
                artifact.origin_project_id != project_id or str(artifact.artifact_id) != artifact_id
                or artifact.matrix.version != str(version)
                or str(artifact.revision.revision_id) != revision_id
                or artifact.origin_run_id != origin_run_id
                or artifact.created_at.isoformat() != created_at
                or (artifact.revision.device.hostname or artifact.revision.device.device_id) != device_label
            ):
                raise ValueError("Assessment history metadata mismatch")
            return artifact
        finally:
            db.close()
