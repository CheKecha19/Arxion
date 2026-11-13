"""Неизменяемая история сверок области в локальном проекте."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from collections.abc import Callable, Iterable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from firewall_compliance.application.cloud_analysis import vmware_scope_revision
from firewall_compliance.application.cloud_security_groups import security_group_snapshot
from firewall_compliance.application.cloud_sg_revision import CloudSGRevisionProjector
from firewall_compliance.application.matrix_policy import matrix_catalog_switch_policy_contexts
from firewall_compliance.application.matrix_scope_assessment import (
    HISTORICAL_BASELINE_NOTE,
    MatrixScopeAssessment,
    MatrixScopeSource,
    MatrixScopeTarget,
    matrix_scope_checksum,
    matrix_scope_revision_checksum,
    verify_scope_rows,
    verify_scope_session_resolutions,
)
from firewall_compliance.domain.access_matrix import AccessMatrix
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.matrix_store import AccessMatrixStore
from firewall_compliance.interfaces.desktop.organization_backup import create_workspace_backup
from firewall_compliance.interfaces.desktop.organization_lock import workspace_lease
from firewall_compliance.interfaces.desktop.project_store import (
    ProjectStore, matrix_scope_revision_json, matrix_scope_stored_checksum,
)

type _VMwareRows = dict[tuple[str, int], tuple[dict[str, Any], dict[str, Any]]]
type _AssessmentRow = tuple[str, str, int, str, str, str, int, int]

_RUN_ITEM_QUERY = (
    "FROM items i JOIN runs r ON r.id=i.run_id "
    "WHERE r.project_id=? AND r.id=? AND i.id=? AND r.state!='running'"
)
_PATH_ONLY_REVISION = (
    "AND json_type(i.payload,'$.revision.parse_result.switch_facts')='object' "
    "AND json_type(i.payload,'$.revision.parse_result.rules')='array' "
    "AND json_array_length(i.payload,'$.revision.parse_result.rules')=0"
)


def _json_unavailable(error: sqlite3.OperationalError) -> bool:
    return str(error).startswith(("no such function: json_", "no such table: json_each"))


@dataclass(frozen=True, slots=True)
class MatrixScopeSummary:
    artifact_id: str
    created_at: str
    matrix_version: str
    status: str
    requirement_count: int
    source_count: int


class MatrixScopeStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._matrices = AccessMatrixStore(path)

    @staticmethod
    def _ready(db: sqlite3.Connection) -> bool:
        version = AccessMatrixStore._schema_version(db)
        objects = set(db.execute(
            "SELECT type,name FROM sqlite_master WHERE tbl_name='workspace_matrix_scope_assessments'"
        ))
        if not objects:
            return False
        expected = {
            ("table", "workspace_matrix_scope_assessments"),
            ("index", "workspace_matrix_scope_assessments_scope"),
            ("trigger", "workspace_matrix_scope_assessments_no_update"),
            ("trigger", "workspace_matrix_scope_assessments_no_delete"),
        }
        if not version or not expected.issubset(objects):
            raise ValueError("Неполная схема истории сверок области")
        return True

    @staticmethod
    def _create(db: sqlite3.Connection) -> None:
        db.execute(
            "CREATE TABLE workspace_matrix_scope_assessments ("
            "artifact_id TEXT PRIMARY KEY NOT NULL, project_id TEXT NOT NULL, "
            "matrix_version INTEGER NOT NULL, scope_id TEXT NOT NULL, selected_site_id TEXT, "
            "created_at TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('complete','partial','cancelled')), "
            "requirement_count INTEGER NOT NULL CHECK(requirement_count>=0), "
            "source_count INTEGER NOT NULL CHECK(source_count>=0), payload TEXT NOT NULL, checksum TEXT NOT NULL, "
            "CHECK(scope_id=coalesce(nullif(selected_site_id,''),project_id)), "
            "FOREIGN KEY(project_id,matrix_version) REFERENCES workspace_matrix_versions(project_id,version))"
        )
        db.execute(
            "CREATE INDEX workspace_matrix_scope_assessments_scope "
            "ON workspace_matrix_scope_assessments(project_id,selected_site_id,created_at DESC,artifact_id DESC)"
        )
        db.execute(
            "CREATE TRIGGER workspace_matrix_scope_assessments_no_update "
            "BEFORE UPDATE ON workspace_matrix_scope_assessments "
            "BEGIN SELECT RAISE(ABORT,'Scope assessment is immutable'); END"
        )
        db.execute(
            "CREATE TRIGGER workspace_matrix_scope_assessments_no_delete "
            "BEFORE DELETE ON workspace_matrix_scope_assessments "
            "BEGIN SELECT RAISE(ABORT,'Scope assessment is immutable'); END"
        )

    @staticmethod
    def _approved_matrix(db: sqlite3.Connection, result: MatrixScopeAssessment) -> AccessMatrix:
        if result.scope_id != (result.selected_site_id or result.project_id):
            raise ValueError("Область сверки не соответствует выбору площадки")
        if not AccessMatrixStore._schema_version(db):
            raise ValueError("В проекте нет утверждённой версии матрицы")
        row = db.execute(
            "SELECT version,payload,checksum,created_at FROM workspace_matrix_versions "
            "WHERE project_id=? AND version=?",
            (result.project_id, result.matrix_version),
        ).fetchone()
        if row is None:
            raise ValueError("Версия матрицы не найдена в этом проекте")
        record = AccessMatrixStore._decode_version(*row)
        matrix = record.matrix
        if (
            matrix.schema_version != "2.0.0"
            or (matrix.matrix_id, matrix.version) != (result.matrix_id, result.matrix_version)
            or matrix_scope_checksum(matrix) != result.matrix_checksum
        ):
            raise ValueError("Сверка относится к другой версии утверждённой матрицы")
        return matrix

    @staticmethod
    def _rule_refs(
        result: MatrixScopeAssessment, *, revision_id: UUID | None = None,
    ) -> dict[UUID, set[tuple[str | None, str]]]:
        rule_refs: dict[UUID, set[tuple[str | None, str]]] = {}
        for row in result.requirements:
            if revision_id is not None and row.revision_id != revision_id:
                continue
            references = {(row.policy_id, identifier) for evidence in row.assessment.evidence
                          for identifier in evidence.related_rule_ids}
            if references:
                if row.revision_id is None:
                    raise ValueError("Ссылка на правило не связана с исходной ревизией")
                rule_refs.setdefault(row.revision_id, set()).update(references)
        return rule_refs

    @staticmethod
    def _policy_vrfs(
        result: MatrixScopeAssessment, *, revision_id: UUID | None = None,
    ) -> dict[UUID, dict[str, str]]:
        vrfs: dict[UUID, dict[str, str]] = {}
        for row in result.requirements:
            if (
                row.revision_id is not None and row.policy_id is not None and row.policy_vrf is not None
                and (revision_id is None or row.revision_id == revision_id)
            ):
                vrfs.setdefault(row.revision_id, {})[row.policy_id] = row.policy_vrf
        return vrfs

    @staticmethod
    def _verify_revision(
        source: MatrixScopeSource, revision: DeviceRevision, references: set[tuple[str | None, str]],
        policy_vrfs: dict[str, str], *, stored_checksum: str | None = None,
    ) -> None:
        config, device = revision.parse_result.configuration, revision.device
        switch = revision.parse_result.switch_facts
        labels = {device.hostname or device.device_id,
                  device.hostname or (switch.hostname if switch else None) or device.device_id}
        if (
            revision.revision_id != source.revision_id
            or (device.device_id, device.platform, device.context)
            != (source.device_id, source.platform, source.device_context)
            or source.device_label not in labels
            or (config.content_sha256, config.parser_version, config.captured_at)
            != (source.configuration_sha256, source.parser_version, source.captured_at)
            or (source.imported_at is not None and revision.imported_at != source.imported_at)
            or (
                stored_checksum if source.revision_checksum_kind == "stored_json"
                else matrix_scope_revision_checksum(revision)
            ) != source.revision_checksum
        ):
            raise ValueError("Источник сверки отличается от сохранённой ревизии")
        if source.revision_checksum_kind == "stored_json" and (switch is None or revision.parse_result.rules):
            raise ValueError("Источник разбора пути должен содержать сетевые факты без правил")
        if references and not references.issubset((rule.policy_id, rule.rule_id) for rule in revision.parse_result.rules):
            raise ValueError("Доказательство ссылается на правило из другой политики или ревизии")
        binding_vrfs = {binding.vrf for binding in source.bindings if binding.vrf is not None}
        if policy_vrfs or binding_vrfs:
            confirmed = matrix_catalog_switch_policy_contexts(revision)
            if not policy_vrfs.items() <= confirmed.items() or not binding_vrfs.issubset(confirmed.values()):
                raise ValueError("VRF политики или каталога отличается от сохранённой конфигурации")

    @staticmethod
    def _verify_stored_identity(
        source: MatrixScopeSource, identity: list[Any],
    ) -> None:
        (
            revision_id, device_id, platform, context, hostname, switch_hostname,
            parser_version, captured_at, configuration_sha256, revision_checksum,
        ) = identity
        try:
            if not isinstance(revision_id, str) or not isinstance(captured_at, str):
                raise ValueError
            saved_identity = UUID(revision_id), datetime.fromisoformat(captured_at)
        except ValueError:
            raise ValueError("Происхождение источника разбора пути не подтверждено") from None
        if (
            saved_identity != (source.revision_id, source.captured_at)
            or (device_id, platform, context) != (source.device_id, source.platform, source.device_context)
            or source.device_label not in (hostname or switch_hostname or device_id, hostname or device_id)
            or (parser_version, configuration_sha256, revision_checksum)
            != (source.parser_version, source.configuration_sha256, source.revision_checksum)
        ):
            raise ValueError("Источник разбора пути отличается от сохранённой ревизии")

    @staticmethod
    def _verify_stored_sources(
        db: sqlite3.Connection, project_id: str, sources: tuple[MatrixScopeSource, ...],
    ) -> None:
        if not sources:
            return
        by_origin = {(source.run_id, source.item_id): source for source in sources}
        db.create_function("matrix_scope_stored_checksum", 1, matrix_scope_stored_checksum, deterministic=True)
        try:
            rows = db.execute(
                """SELECT r.id,i.id,json_extract(i.payload,'$.revision.revision_id'),
                          json_extract(i.payload,'$.revision.device.device_id'),
                          json_extract(i.payload,'$.revision.device.platform'),
                          json_extract(i.payload,'$.revision.device.context'),
                          json_extract(i.payload,'$.revision.device.hostname'),
                          json_extract(i.payload,'$.revision.parse_result.switch_facts.hostname'),
                          json_extract(i.payload,'$.revision.parse_result.configuration.parser_version'),
                          json_extract(i.payload,'$.revision.parse_result.configuration.captured_at'),
                          json_extract(i.payload,'$.revision.parse_result.configuration.content_sha256'),
                          matrix_scope_stored_checksum(json_extract(i.payload,'$.revision'))
                   FROM json_each(?) wanted
                   JOIN items i ON i.id=json_extract(wanted.value,'$[1]')
                   JOIN runs r ON r.id=i.run_id AND r.id=json_extract(wanted.value,'$[0]')
                   WHERE r.project_id=? AND r.state!='running' """ + _PATH_ONLY_REVISION,
                (json.dumps(tuple(by_origin)), project_id),
            )
            seen = set()
            for run_id, item_id, *identity in rows:
                key = run_id, item_id
                MatrixScopeStore._verify_stored_identity(by_origin[key], identity)
                seen.add(key)
            if seen != by_origin.keys():
                raise ValueError("Исходная запись разбора пути не найдена или содержит правила")
        except sqlite3.OperationalError as error:
            if not _json_unavailable(error):
                raise
            for source in sources:
                revision, checksum = MatrixScopeStore._stored_path_revision(db, project_id, source)
                MatrixScopeStore._verify_revision(source, revision, set(), {}, stored_checksum=checksum)

    @staticmethod
    def _stored_path_revision(
        db: sqlite3.Connection, project_id: str, source: MatrixScopeSource,
    ) -> tuple[DeviceRevision, str]:
        parameters = project_id, source.run_id, source.item_id
        try:
            row = db.execute(
                f"SELECT json_extract(i.payload,'$.revision') {_RUN_ITEM_QUERY} {_PATH_ONLY_REVISION}", parameters,
            ).fetchone()
            raw = row[0] if row is not None else None
        except sqlite3.OperationalError as error:
            if not _json_unavailable(error):
                raise
            row = db.execute("SELECT i.payload " + _RUN_ITEM_QUERY, parameters).fetchone()
            revision = json.loads(row[0]).get("revision") if row is not None else None
            parsed = revision.get("parse_result") if isinstance(revision, dict) else None
            raw = None
            if (
                isinstance(revision, dict) and isinstance(parsed, dict)
                and parsed.get("rules") == [] and isinstance(parsed.get("switch_facts"), dict)
            ):
                raw = matrix_scope_revision_json(revision)
        if not isinstance(raw, str):
            raise ValueError("Позиция запуска не найдена в этом проекте")
        checksum = matrix_scope_stored_checksum(raw)
        if checksum != source.revision_checksum:
            raise ValueError("Контрольная сумма источника разбора пути не совпадает")
        return DeviceRevision.model_validate_json(raw), checksum

    @staticmethod
    def _verify_sources(db: sqlite3.Connection, result: MatrixScopeAssessment, matrix: AccessMatrix) -> None:
        site_id = result.selected_site_id
        project_id = result.project_id
        sites_exist = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='workspace_device_sites'"
        ).fetchone()
        assignments = dict(db.execute(
            "SELECT device_id,site_id FROM workspace_device_sites WHERE origin_project_id=?",
            (project_id,),
        )) if site_id is not None and sites_exist else {}
        if site_id and (not sites_exist or db.execute(
            "SELECT 1 FROM workspace_sites WHERE id=?", (site_id,),
        ).fetchone() is None):
            raise ValueError("Выбранная площадка не найдена")
        rule_refs = MatrixScopeStore._rule_refs(result)
        policy_vrfs = MatrixScopeStore._policy_vrfs(result)
        contextual: set[str] = set()
        if result.context_inputs is not None:
            contextual = {row.requirement_id for row in matrix.requirements
                          if row.scope_id == result.scope_id and row.access_context is not None}
        context_sources = {row.revision_id for row in result.requirements
                           if row.kind == "requirement" and row.requirement_id in contextual}
        context_revisions: dict[UUID, DeviceRevision] = {}
        cloud: dict[str, CloudSGRevisionProjector] = {}
        vmware = MatrixScopeStore._vmware_rows(db, project_id, result.sources)
        stored_sources = []
        for source in result.sources:
            if source.vmware_origin is not None:
                revision = MatrixScopeStore._vmware_revision(result, source, vmware)
            elif source.cloud_selection is not None:
                revision = MatrixScopeStore._cloud_revision(db, project_id, site_id, source, cloud)
            else:
                if site_id is not None and assignments.get(source.device_id, "") != site_id:
                    raise ValueError("Исходное устройство не относится к выбранной площадке")
                if source.revision_checksum_kind == "stored_json":
                    stored_sources.append(source)
                    continue
                revision = MatrixScopeStore._run_revision(db, project_id, source)
            MatrixScopeStore._verify_revision(
                source, revision, rule_refs.get(source.revision_id, set()), policy_vrfs.get(source.revision_id, {}),
            )
            if source.revision_id in context_sources:
                context_revisions[source.revision_id] = revision
        MatrixScopeStore._verify_stored_sources(db, project_id, tuple(stored_sources))
        verify_scope_session_resolutions(matrix, result, context_revisions)

    def get_source_revision(
        self, result: MatrixScopeAssessment, revision_id: UUID, *, matrix: AccessMatrix | None = None,
    ) -> DeviceRevision:
        """Прочитать точный снимок сверки по его исходной записи."""
        source = next((item for item in result.sources if item.revision_id == revision_id), None)
        if source is None:
            raise ValueError("Снимок не входит в выбранную сверку области")
        if result.scope_id != (result.selected_site_id or result.project_id):
            raise ValueError("Область сверки не соответствует выбору площадки")
        with closing(self._matrices._connect()) as db:
            stored_checksum = None
            if source.vmware_origin is not None:
                db.execute("BEGIN")
                rows = self._vmware_rows(db, result.project_id, (source,))
                revision = self._vmware_revision(result, source, rows)
            elif source.cloud_selection is not None:
                revision = self._cloud_revision(db, result.project_id, result.selected_site_id, source, {})
            elif source.revision_checksum_kind == "stored_json":
                revision, stored_checksum = self._stored_path_revision(db, result.project_id, source)
            else:
                # Состав площадки мог измениться после сохранения результата.
                revision = self._run_revision(db, result.project_id, source)
            references = self._rule_refs(result, revision_id=revision_id).get(revision_id, set())
            policy_vrfs = self._policy_vrfs(result, revision_id=revision_id).get(revision_id, {})
            self._verify_revision(source, revision, references, policy_vrfs, stored_checksum=stored_checksum)
            if matrix is None and result.context_inputs is not None:
                matrix = self._approved_matrix(db, result)
            if matrix is not None:
                if matrix_scope_checksum(matrix) != result.matrix_checksum:
                    raise ValueError("Сверка относится к другой версии утверждённой матрицы")
                verify_scope_rows(matrix, result)
                verify_scope_session_resolutions(matrix, result, {revision_id: revision})
            return revision

    @staticmethod
    def _run_revision(
        db: sqlite3.Connection, project_id: str, source: MatrixScopeSource,
    ) -> DeviceRevision:
        row = db.execute(
            "SELECT i.payload " + _RUN_ITEM_QUERY,
            (project_id, source.run_id, source.item_id),
        ).fetchone()
        if row is None:
            raise ValueError("Позиция запуска не найдена в этом проекте")
        return DeviceRevision.model_validate(json.loads(row[0]).get("revision"))

    @staticmethod
    def _cloud_scan(db: sqlite3.Connection, project_id: str, scan_id: str) -> dict[str, Any]:
        row = db.execute(
            "SELECT id,project_id,created_at,finished_at,state,selection,config,result FROM cloud_scans "
            "WHERE id=? AND project_id=? AND state IN ('completed','partial','failed','cancelled','interrupted')",
            (scan_id, project_id),
        ).fetchone()
        if row is None:
            raise ValueError("Облачный сбор не найден в этом проекте")
        keys = ("id", "project_id", "created_at", "finished_at", "state", "selection", "config", "result")
        scan = dict(zip(keys, row, strict=True))
        scan.update((key, json.loads(scan[key])) for key in ("selection", "config", "result"))
        return scan

    @staticmethod
    def _vmware_rows(
        db: sqlite3.Connection, project_id: str, sources: Iterable[MatrixScopeSource],
    ) -> _VMwareRows:
        by_scan: dict[str, set[int]] = {}
        for source in sources:
            if (origin := source.vmware_origin) is not None:
                by_scan.setdefault(origin.scan_id, set()).add(origin.record_index)
        rows: _VMwareRows = {}
        for scan_id, indices in by_scan.items():
            header = db.execute(
                "SELECT created_at,state,selection,config FROM cloud_scans "
                "WHERE id=? AND project_id=? AND state IN ('completed','partial')",
                (scan_id, project_id),
            ).fetchone()
            if header is None:
                raise ValueError("Сбор VMware не найден в этом проекте")
            created_at, state, selection, config = header
            scan = {
                "id": scan_id, "project_id": project_id, "created_at": created_at, "state": state,
                "selection": json.loads(selection), "config": json.loads(config),
            }
            try:
                projected = dict(db.execute(
                    "SELECT entry.key,entry.value FROM cloud_scans AS scan "
                    "JOIN json_each(scan.result,'$.records') AS entry "
                    "WHERE scan.id=? AND scan.project_id=? AND entry.type='object' "
                    "AND json_type(scan.result,'$.records')='array' "
                    "AND entry.key IN (SELECT value FROM json_each(?))",
                    (scan_id, project_id, json.dumps(sorted(indices))),
                ))
                for index, raw in projected.items():
                    rows[scan_id, index] = scan, json.loads(raw)
            except sqlite3.OperationalError as error:
                if str(error) not in {"no such table: json_each", "no such function: json_type"}:
                    raise
                full = MatrixScopeStore._cloud_scan(db, project_id, scan_id)
                result = full.get("result")
                records = result.get("records") if isinstance(result, dict) else None
                if isinstance(records, list):
                    for index in indices:
                        if index < len(records) and isinstance(records[index], dict):
                            rows[scan_id, index] = scan, records[index]
        return rows

    @staticmethod
    def _vmware_revision(
        result: MatrixScopeAssessment, source: MatrixScopeSource, rows: _VMwareRows,
    ) -> DeviceRevision:
        origin = source.vmware_origin
        if origin is None or source.imported_at is None:
            raise ValueError("Источник сверки VMware не содержит точной ссылки на сбор")
        row = rows.get((origin.scan_id, origin.record_index))
        if row is None:
            raise ValueError("Запись Edge Gateway не найдена в сохранённом сборе")
        scan, record = row
        return vmware_scope_revision(
            scan, origin, project_id=result.project_id, site_id=result.selected_site_id,
            imported_at=source.imported_at, application_version=result.application_version, record=record,
        )

    @staticmethod
    def _cloud_revision(
        db: sqlite3.Connection, project_id: str, site_id: str | None, source: MatrixScopeSource,
        cloud: dict[str, CloudSGRevisionProjector],
    ) -> DeviceRevision:
        selection = source.cloud_selection
        if selection is None or source.imported_at is None or site_id == "":
            raise ValueError("Облачный сбор не относится к выбранной области")
        projector = cloud.get(selection.scan_id)
        if projector is None:
            scan = MatrixScopeStore._cloud_scan(db, project_id, selection.scan_id)
            snapshot = security_group_snapshot(scan)
            if site_id is not None and site_id not in snapshot.workspace_site_ids:
                raise ValueError("Облачный сбор не привязан к выбранной площадке")
            projector = CloudSGRevisionProjector(snapshot)
            cloud[selection.scan_id] = projector
        return projector.project(selection, imported_at=source.imported_at)

    def save(self, result: MatrixScopeAssessment) -> str:
        result = MatrixScopeAssessment.model_validate(result.model_dump(mode="python"))
        payload = result.model_dump_json()
        artifact_id = str(uuid4())
        with closing(self._matrices._connect()) as db:
            if self._ready(db):
                self._append(db, artifact_id, result, payload)
            else:
                with workspace_lease(self.path):
                    if not self._ready(db):
                        self._approved_matrix(db, result)
                        backup = self.path.with_name(f"{self.path.name}.before-matrix-scope-{uuid4().hex}.sqlite3")
                        create_workspace_backup(self.path, backup)
                    self._append(db, artifact_id, result, payload, initialize=True)
        return artifact_id

    def _append(
        self, db: sqlite3.Connection, artifact_id: str, result: MatrixScopeAssessment, payload: str,
        *, initialize: bool = False,
    ) -> None:
        with db:
            db.execute("BEGIN IMMEDIATE")
            ready = self._ready(db)
            matrix = self._approved_matrix(db, result)
            if result.baseline_run_id is not None:
                ProjectStore._matrix_baseline_cut(db, result.project_id, result.baseline_run_id)
            verify_scope_rows(matrix, result)
            self._verify_sources(db, result, matrix)
            if not ready:
                if not initialize:
                    raise ValueError("История сверок области недоступна")
                self._create(db)
            db.execute(
                "INSERT INTO workspace_matrix_scope_assessments "
                "(artifact_id,project_id,matrix_version,scope_id,selected_site_id,created_at,status,"
                "requirement_count,source_count,payload,checksum) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (artifact_id, result.project_id, int(result.matrix_version), result.scope_id,
                 result.selected_site_id, result.created_at.astimezone(UTC).isoformat(), result.status,
                 len(result.requirements), len(result.sources), payload, sha256(payload.encode("utf-8")).hexdigest()),
            )

    def get(self, project_id: str, artifact_id: str, *, selected_site_id: str | None) -> MatrixScopeAssessment:
        with closing(self._matrices._connect()) as db:
            if not self._ready(db):
                raise ValueError("В проекте ещё нет истории сверок области")
            row = db.execute(
                "SELECT payload,checksum,matrix_version,scope_id,created_at,status,requirement_count,source_count "
                "FROM workspace_matrix_scope_assessments "
                "WHERE project_id=? AND artifact_id=? AND selected_site_id IS ?",
                (project_id, artifact_id, selected_site_id),
            ).fetchone()
            if row is None:
                raise ValueError("Сверка не найдена в выбранной области проекта")
            result = self._decode_assessment(row, project_id, selected_site_id)
            matrix = self._approved_matrix(db, result)
            if result.context_inputs is not None or any(row.policy_vrf is not None for row in result.requirements):
                verify_scope_rows(matrix, result)
            return result

    def assessments_for_run_report(
        self, project_id: str, run_id: str,
    ) -> tuple[list[tuple[str, MatrixScopeAssessment, AccessMatrix]], list[str]]:
        """Читать сохранённые сверки, для которых запуск был срезом или источником строки."""
        query = (
            "SELECT artifact_id,selected_site_id,payload,checksum,matrix_version,scope_id,created_at,"
            "status,requirement_count,source_count FROM workspace_matrix_scope_assessments WHERE project_id=?"
        )
        order = " ORDER BY created_at DESC,artifact_id DESC"
        matches: list[tuple[str, MatrixScopeAssessment, AccessMatrix]] = []
        rejected: list[str] = []
        matrices: dict[tuple[str, str, str], AccessMatrix] = {}
        historical_run_valid = False
        with closing(self._matrices._connect()) as db:
            if not self._ready(db):
                return matches, rejected
            try:
                rows = db.execute(query + """
                    AND CASE WHEN json_valid(payload) THEN
                        json_extract(payload,'$.baseline_run_id')=?
                        OR EXISTS (SELECT 1 FROM json_each(payload,'$.diagnostics')
                            WHERE CASE WHEN type='object' THEN json_extract(value,'$.code') END=?
                            AND instr(CASE WHEN type='object' THEN json_extract(value,'$.message') END,
                                      ' · ' || ? || ' · ')>0)
                        OR (json_extract(payload,'$.baseline_run_id') IS NULL
                            AND EXISTS (SELECT 1 FROM json_each(payload,'$.sources')
                                WHERE CASE WHEN type='object' THEN json_extract(value,'$.run_id') END=?))
                    ELSE 1 END
                    """ + order, (project_id, run_id, HISTORICAL_BASELINE_NOTE, run_id, run_id))
            except sqlite3.OperationalError as error:
                if not _json_unavailable(error):
                    raise
                rows = db.execute(query + order, (project_id,))
            for artifact_id, site_id, *row in rows:
                try:
                    result = self._decode_assessment(tuple(row), project_id, site_id)
                    relation = result.run_report_relation(run_id)
                    if relation is None:
                        continue
                    if relation == "historical_baseline" and not historical_run_valid:
                        ProjectStore._matrix_baseline_cut(db, project_id, run_id)
                        historical_run_valid = True
                    key = result.scope_id, result.matrix_version, result.matrix_checksum
                    if key not in matrices:
                        matrices[key] = self._approved_matrix(db, result)
                    matrix = matrices[key]
                    if matrix.matrix_id != result.matrix_id:
                        raise ValueError("Сверка относится к другой утверждённой матрице")
                    verify_scope_rows(matrix, result)
                    matches.append((artifact_id, result, matrix))
                except (ValueError, TypeError):
                    rejected.append(artifact_id)
        return matches, rejected

    @staticmethod
    def _decode_assessment(row: _AssessmentRow, project_id: str, selected_site_id: str | None) -> MatrixScopeAssessment:
        payload, checksum, version, scope, created_at, status, requirement_count, source_count = row
        if sha256(payload.encode("utf-8")).hexdigest() != checksum:
            raise ValueError("Контрольная сумма сверки области не совпадает")
        result = MatrixScopeAssessment.model_validate_json(payload)
        if (
            (result.project_id, result.scope_id, result.selected_site_id) != (project_id, scope, selected_site_id)
            or scope != (selected_site_id or project_id)
            or result.matrix_version != str(version)
            or result.created_at.astimezone(UTC).isoformat() != created_at
            or (result.status, len(result.requirements), len(result.sources)) != (status, requirement_count, source_count)
        ):
            raise ValueError("Метаданные истории сверки области не совпадают")
        return result

    @staticmethod
    def _current_assessment_row(
        db: sqlite3.Connection, project_id: str, site_id: str | None, version: str,
        cancelled: Callable[[], bool],
    ) -> _AssessmentRow | None:
        query = (
            "SELECT payload,checksum,matrix_version,scope_id,created_at,status,requirement_count,source_count "
            "FROM workspace_matrix_scope_assessments WHERE project_id=? AND selected_site_id IS ? "
            "AND matrix_version=? AND status IN ('complete','partial') "
        )
        parameters = (project_id, site_id, version)
        order = " ORDER BY created_at DESC,artifact_id DESC"
        try:
            return db.execute(
                query + "AND CASE WHEN json_valid(payload) THEN "
                "json_extract(payload,'$.baseline_run_id') IS NULL AND "
                "NOT EXISTS (SELECT 1 FROM json_each(payload,'$.diagnostics') "
                "WHERE CASE WHEN type='object' THEN json_extract(value,'$.code') END=?) ELSE 1 END"
                + order + " LIMIT 1",
                (*parameters, HISTORICAL_BASELINE_NOTE),
            ).fetchone()
        except sqlite3.OperationalError as error:
            if not str(error).startswith(("no such function: json_", "no such table: json_each")):
                raise
        for row in db.execute(query + order, parameters):
            if cancelled():
                return None
            raw = json.loads(row[0])
            diagnostics = raw.get("diagnostics") if isinstance(raw, dict) else None
            if isinstance(raw, dict) and raw.get("baseline_run_id") is not None:
                continue
            if not isinstance(diagnostics, list) or not any(
                isinstance(item, dict) and item.get("code") == HISTORICAL_BASELINE_NOTE
                for item in diagnostics
            ):
                return row
        return None

    def latest_current_targets(
        self, project_id: str, matrix: AccessMatrix, *, selected_site_id: str | None,
        cancelled: Callable[[], bool],
    ) -> dict[str, MatrixScopeTarget] | None:
        """Взять явные назначения из последней актуальной сверки утверждённой версии."""
        if cancelled():
            return None
        checksum = matrix_scope_checksum(matrix)
        try:
            with closing(self._matrices._connect()) as db:
                if not self._ready(db):
                    return None
                db.set_progress_handler(lambda: int(cancelled()), 10_000)
                row = self._current_assessment_row(db, project_id, selected_site_id, matrix.version, cancelled)
                if row is None or cancelled():
                    return None
                result = self._decode_assessment(row, project_id, selected_site_id)
        except sqlite3.OperationalError as error:
            if cancelled() and getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_INTERRUPT:
                return None
            raise
        if (result.matrix_id, result.matrix_version, result.matrix_checksum) != (matrix.matrix_id, matrix.version, checksum):
            raise ValueError("Сверка относится к другой версии утверждённой матрицы")
        if result.status == "cancelled" or result.historical:
            raise ValueError("Сохранённая сверка не относится к последним снимкам области")
        verify_scope_rows(matrix, result)
        targets = result.targets_by_requirement
        if targets:
            counts = Counter(row.requirement_id for row in matrix.requirements)
            counts.update(row.boundary_id for row in matrix.boundaries)
            eligible = {row.requirement_id for row in result.requirements if row.policy_id and counts[row.requirement_id] == 1}
            if targets.keys() - eligible:
                raise ValueError("Сохранённые назначения относятся к другим требованиям или политикам")
        return dict(targets)

    def list_summaries(
        self, project_id: str, *, selected_site_id: str | None,
    ) -> tuple[MatrixScopeSummary, ...]:
        with closing(self._matrices._connect()) as db:
            if not self._ready(db):
                return ()
            return tuple(
                MatrixScopeSummary(artifact_id, created_at, str(version), status, rows, sources)
                for artifact_id, created_at, version, status, rows, sources in db.execute(
                    "SELECT artifact_id,created_at,matrix_version,status,requirement_count,source_count "
                    "FROM workspace_matrix_scope_assessments "
                    "WHERE project_id=? AND selected_site_id IS ? ORDER BY created_at DESC,artifact_id DESC",
                    (project_id, selected_site_id),
                )
            )
