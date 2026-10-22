"""Локальные проекты и результаты без хранения полного исходного документа."""

import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from firewall_compliance.domain.assurance import FirewallAssuranceResult
from firewall_compliance.domain.enums import FindingStatus
from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.infrastructure.windows_secrets import protect_secret, unprotect_secret
from firewall_compliance.interfaces.desktop.backend import AnalysisSession, source_preview
from firewall_compliance.parsers import ParseFailure


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
                PRAGMA user_version=1;
            """)

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
                "SELECT provider,config FROM integrations WHERE project_id=? ORDER BY provider",
                (project_id,),
            ).fetchall()
        return [{"provider": row["provider"], "config": json.loads(row["config"])} for row in rows]

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

    def create_run(self, project_id: str) -> str:
        """Начать новый запуск без переноса статусов предыдущего запуска."""
        project = self.get_project(project_id)
        run_id = str(uuid4())
        with self._connect() as db:
            db.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?,?)",
                (
                    run_id,
                    project_id,
                    _now(),
                    None,
                    "running",
                    _json(project["settings"]),
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

    def record_session(self, run_id: str, session: AnalysisSession) -> str:
        """Сохранить нормализованный снимок и ограниченные фрагменты доказательств."""
        report = session.report
        partial = (
            bool(report.parse_errors or report.unsupported_constructs)
            or any(check.status.value == "partial" for check in report.checks)
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
                "diagnostics": [
                    x.model_dump(mode="json")
                    for x in (
                        *report.parse_warnings,
                        *report.parse_errors,
                        *report.unsupported_constructs,
                    )
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
        """Изменить решение пользователя, не меняя результат анализатора."""
        FindingStatus(status)
        run = self.get_run(run_id)
        if not any(
            str(f["finding_id"]) == finding_id
            for item in run["items"]
            if item["report"]
            for check in item["report"]["checks"]
            for f in check["findings"]
        ):
            raise KeyError("Находка не принадлежит запуску")
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO marks VALUES (?,?,?,?,?)",
                (
                    run_id,
                    finding_id,
                    status,
                    comment,
                    _now(),
                ),
            )

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
