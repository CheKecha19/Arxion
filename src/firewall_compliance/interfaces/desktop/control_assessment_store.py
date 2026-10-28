"""Append-only technical-control snapshots linked to exact saved project evidence."""

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import UUID

from firewall_compliance.application.analysis_result import AnalysisResult
from firewall_compliance.application.control_assessment import ControlAssessment


def _canonical(value: ControlAssessment) -> str:
    return json.dumps(
        value.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _digest(metadata: tuple[str, ...], payload: str) -> str:
    return sha256(
        json.dumps([*metadata, payload], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class ControlAssessmentStore:
    """Independent connections are safe for the panel worker and project restarts."""

    def __init__(self, database_path: Path) -> None:
        self.path = Path(database_path)
        with closing(self._connect()) as connection, connection:
            tables = {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if not {"projects", "runs", "analysis_results"}.issubset(tables):
                raise ValueError("An existing project database with analysis results is required")
            connection.execute("""CREATE TABLE IF NOT EXISTS control_assessments (
                assessment_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(id),
                analysis_id TEXT NOT NULL REFERENCES analysis_results(analysis_id),
                created_at TEXT NOT NULL,
                assessed_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL)""")
            connection.execute("""CREATE INDEX IF NOT EXISTS control_assessments_project
                ON control_assessments(project_id,created_at)""")
            connection.execute("""CREATE TRIGGER IF NOT EXISTS control_assessments_no_update
                BEFORE UPDATE ON control_assessments
                BEGIN SELECT RAISE(ABORT,'control assessments are immutable'); END""")
            connection.execute("""CREATE TRIGGER IF NOT EXISTS control_assessments_no_delete
                BEFORE DELETE ON control_assessments
                BEGIN SELECT RAISE(ABORT,'control assessments are immutable'); END""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True, timeout=15)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            if db.execute("PRAGMA user_version").fetchone()[0] > 1:
                raise ValueError("Unsupported project database version")
            return db
        except BaseException:
            db.close()
            raise

    @staticmethod
    def _project(db: sqlite3.Connection, project_id: str) -> None:
        if db.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone() is None:
            raise KeyError("Unknown project")

    @staticmethod
    def _source_scope(db: sqlite3.Connection, project_id: str, source: AnalysisResult) -> None:
        ControlAssessmentStore._project(db, project_id)
        row = db.execute(
            "SELECT * FROM analysis_results WHERE analysis_id=? AND project_id=?",
            (str(source.analysis_id), project_id),
        ).fetchone()
        if row is None:
            raise ValueError("The exact source analysis must already be saved in this project")
        if len(row["payload"].encode("utf-8")) > 64 * 1024 * 1024:
            raise ValueError("Saved source analysis exceeds assessment input budget")
        if sha256(row["payload"].encode("utf-8")).hexdigest() != row["payload_sha256"]:
            raise ValueError("Saved source analysis checksum differs")
        retained = AnalysisResult.model_validate_json(row["payload"])
        if retained != source or retained.project_reference not in (None, project_id):
            raise ValueError("Assessment source does not equal this saved project analysis")
        if (
            str(retained.analysis_id) != row["analysis_id"]
            or retained.run_reference != row["run_id"]
        ):
            raise ValueError("Saved source analysis identity differs")
        if retained.run_reference is not None:
            run = db.execute(
                "SELECT project_id FROM runs WHERE id=?", (retained.run_reference,)
            ).fetchone()
            if run is None or run[0] != project_id:
                raise ValueError("Saved source run belongs to a different project")

    def save(self, project_id: str, result: ControlAssessment) -> str:
        if not isinstance(result, ControlAssessment):
            raise TypeError("Expected a ControlAssessment")
        validated = ControlAssessment.model_validate_json(result.model_dump_json())
        payload = _canonical(validated)
        if len(payload.encode("utf-8")) > 64 * 1024 * 1024:
            raise ValueError("Control assessment exceeds 64 MiB")
        identifier = str(validated.assessment_id)
        with closing(self._connect()) as db, db:
            self._source_scope(db, project_id, validated.source)
            previous = db.execute(
                "SELECT * FROM control_assessments WHERE assessment_id=?", (identifier,)
            ).fetchone()
            if previous is not None:
                if previous["project_id"] != project_id or previous["payload"] != payload:
                    raise ValueError("Assessment ID already names different content or project")
                self._read(db, project_id, previous)
                return identifier
            metadata = (
                identifier,
                project_id,
                str(validated.source.analysis_id),
                datetime.now(UTC).isoformat(),
                validated.assessed_at.isoformat(),
            )
            inserted = db.execute(
                "INSERT INTO control_assessments VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(assessment_id) DO NOTHING",
                (*metadata, payload, _digest(metadata, payload)),
            )
            if inserted.rowcount == 0:
                concurrent = db.execute(
                    "SELECT * FROM control_assessments WHERE assessment_id=?", (identifier,)
                ).fetchone()
                if (
                    concurrent is None
                    or concurrent["project_id"] != project_id
                    or concurrent["payload"] != payload
                ):
                    raise ValueError("Assessment ID already names different content or project")
                self._read(db, project_id, concurrent)
        return identifier

    @staticmethod
    def _read(db: sqlite3.Connection, project_id: str, row: sqlite3.Row) -> ControlAssessment:
        metadata = tuple(
            row[name]
            for name in ("assessment_id", "project_id", "analysis_id", "created_at", "assessed_at")
        )
        payload = row["payload"]
        if len(payload.encode("utf-8")) > 64 * 1024 * 1024:
            raise ValueError("Stored control assessment exceeds 64 MiB")
        if _digest(metadata, payload) != row["payload_sha256"]:
            raise ValueError("Stored control assessment checksum differs")
        result = ControlAssessment.model_validate_json(payload)
        if (
            str(result.assessment_id) != row["assessment_id"]
            or row["project_id"] != project_id
            or str(result.source.analysis_id) != row["analysis_id"]
            or result.assessed_at.isoformat() != row["assessed_at"]
        ):
            raise ValueError("Stored assessment identity does not match envelope")
        date = datetime.fromisoformat(row["created_at"])
        if date.utcoffset() is None:
            raise ValueError("Stored assessment creation date requires timezone")
        ControlAssessmentStore._source_scope(db, project_id, result.source)
        return result

    def get(self, project_id: str, assessment_id: str) -> ControlAssessment:
        identifier = str(UUID(assessment_id))
        with closing(self._connect()) as db:
            self._project(db, project_id)
            row = db.execute(
                "SELECT * FROM control_assessments WHERE project_id=? AND assessment_id=?",
                (project_id, identifier),
            ).fetchone()
            if row is None:
                raise KeyError("Unknown assessment in this project")
            return self._read(db, project_id, row)

    def list(self, project_id: str) -> list[dict[str, Any]]:
        with closing(self._connect()) as db:
            self._project(db, project_id)
            rows = db.execute(
                "SELECT * FROM control_assessments WHERE project_id=? "
                "ORDER BY created_at DESC,rowid DESC",
                (project_id,),
            ).fetchall()
            result = []
            for row in rows:
                value = self._read(db, project_id, row)
                result.append(
                    {
                        "assessment_id": str(value.assessment_id),
                        "project_id": project_id,
                        "analysis_id": str(value.source.analysis_id),
                        "created_at": row["created_at"],
                        "assessed_at": value.assessed_at.isoformat(),
                        "profile_id": value.profile.profile_id,
                        "profile_version": value.profile.version,
                        "catalogue_id": value.catalogue.catalogue_id,
                        "catalogue_version": value.catalogue.version,
                        "coverage": value.coverage.model_dump(mode="json")
                        if value.coverage
                        else {},
                    }
                )
            return result
