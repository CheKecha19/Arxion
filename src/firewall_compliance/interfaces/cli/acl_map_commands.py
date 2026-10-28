"""Explicit ACL-map CLI workflows; no Qt runtime or cloud requests."""

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

import typer

from firewall_compliance.analysis.acl_map import AclMapFilter, build_acl_map
from firewall_compliance.application.acl_map import (
    AclMapBatchFailure,
    build_acl_map_batch,
    export_acl_map_dot,
    export_acl_map_html,
    export_acl_map_json,
)
from firewall_compliance.application.acl_map_store import AclMapStore
from firewall_compliance.application.firewall_assurance import build_source_revision
from firewall_compliance.domain.acl_map import AclMap
from firewall_compliance.domain.enums import Protocol
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.parsers import ParseFailure, SourceDocument
from firewall_compliance.parsers.catalog import create_default_registry

app = typer.Typer(no_args_is_help=True, help="Карта заданных условий ACL, не достижимости.")


def _read_bytes(path: Path) -> bytes:
    with path.open("rb") as stream:
        content = stream.read(64 * 1024 * 1024 + 1)
    if len(content) > 64 * 1024 * 1024:
        raise ValueError("Input exceeds 64 MiB")
    return content


def _read(path: Path) -> str:
    return _read_bytes(path).decode("utf-8-sig")


def _separate(output: Path, *inputs: Path) -> None:
    for source in inputs:
        if output.resolve() == source.resolve() or (output.exists() and output.samefile(source)):
            raise ValueError("Output must be separate from inputs")


def _failure() -> None:
    typer.echo(
        "Не удалось выполнить операцию карты: проверьте вход, область проекта и путь вывода.",
        err=True,
    )
    raise typer.Exit(2)


def _revision(path: Path, revision_json: bool) -> DeviceRevision | ParseFailure:
    if revision_json:
        return DeviceRevision.model_validate_json(_read(path))
    content = _read_bytes(path)
    source = SourceDocument(
        source_name=path.name,
        content=content,
        captured_at=datetime.now(UTC),
        file_modified_at=datetime.fromtimestamp(path.stat().st_mtime, tz=UTC),
    )
    return build_source_revision(source, create_default_registry(), imported_at=datetime.now(UTC))


@app.command("build")
def build(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")],
    revision_json: Annotated[bool, typer.Option("--revision-json")] = False,
) -> None:
    """Создать автономную карту из конфигурации либо сохранённой DeviceRevision."""
    try:
        _separate(output, path)
        revision = _revision(path, revision_json)
        if isinstance(revision, ParseFailure):
            raise ValueError("Parser rejected input")
        graph = build_acl_map(revision, built_at=datetime.now(UTC))
        output.write_text(export_acl_map_json(graph), encoding="utf-8")
    except (OSError, ValueError, UnicodeError):
        _failure()


@app.command("batch")
def batch(
    paths: Annotated[list[Path], typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")],
    revision_json: Annotated[bool, typer.Option("--revision-json")] = False,
) -> None:
    """Построить независимые карты всех входов, сохраняя явные отказы."""
    try:
        _separate(output, *paths)
        if len(paths) > 1000:
            raise ValueError("Batch input budget exceeded")
        revisions: list[tuple[str, DeviceRevision]] = []
        failures: list[AclMapBatchFailure] = []
        for index, path in enumerate(paths):
            reference = f"{index + 1}:{path.name}"
            try:
                revision = _revision(path, revision_json)
                if isinstance(revision, ParseFailure):
                    failures.append(
                        AclMapBatchFailure(
                            input_reference=reference,
                            code="PARSE_FAILURE",
                            message="Источник не распознан в поддерживаемой области парсеров.",
                            source_name=revision.source_name,
                            content_sha256=revision.content_sha256,
                            diagnostics=(*revision.errors, *revision.warnings),
                        )
                    )
                else:
                    revisions.append((reference, revision))
            except (OSError, ValueError, UnicodeError):
                failures.append(
                    AclMapBatchFailure(
                        input_reference=reference,
                        code="INPUT_ERROR",
                        message="Не удалось прочитать или подтвердить ревизию.",
                    )
                )
        result = build_acl_map_batch(
            revisions, built_at=datetime.now(UTC), failures=tuple(failures)
        )
        output.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    except (OSError, ValueError, UnicodeError):
        _failure()
    if result.failures:
        typer.echo("Часть входов не обработана; причины сохранены в пакете.", err=True)
        raise typer.Exit(2)


@app.command("export")
def export(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")],
    format_name: Annotated[Literal["json", "dot", "html"], typer.Option("--format")] = "html",
    source: Annotated[str | None, typer.Option("--source")] = None,
    destination: Annotated[str | None, typer.Option("--destination")] = None,
    protocol: Annotated[Protocol | None, typer.Option("--protocol")] = None,
    port: Annotated[int | None, typer.Option("--port")] = None,
    include_unknown: Annotated[bool, typer.Option("--include-unknown/--exclude-unknown")] = True,
) -> None:
    """Экспортировать сохранённую карту; сетевые фильтры применяются к HTML."""
    try:
        _separate(output, path)
        graph = AclMap.model_validate_json(_read(path))
        filters = AclMapFilter(
            source_cidr=source,
            destination_cidr=destination,
            protocol=protocol,
            destination_port=port,
            include_unknown=include_unknown,
        )
        if format_name != "html" and filters != AclMapFilter():
            raise ValueError("Filters require HTML; JSON/DOT preserve complete snapshots")
        if format_name == "html":
            content = export_acl_map_html(graph, filters=filters)
        elif format_name == "dot":
            content = export_acl_map_dot(graph)
        else:
            content = export_acl_map_json(graph)
        output.write_text(content, encoding="utf-8")
    except (OSError, ValueError, UnicodeError):
        _failure()


@app.command("save")
def save(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    database: Annotated[Path, typer.Option("--database", exists=True, dir_okay=False)],
    project: Annotated[str, typer.Option("--project")],
    run: Annotated[str | None, typer.Option("--run")] = None,
    item: Annotated[str | None, typer.Option("--item")] = None,
) -> None:
    """Сохранить карту в существующем проекте; run/item проверяются по снимку."""
    try:
        _separate(database, path)
        graph = AclMap.model_validate_json(_read(path))
        with (
            closing(
                sqlite3.connect(database.resolve().as_uri() + "?mode=rw", uri=True)
            ) as connection,
            connection,
        ):
            connection.execute("PRAGMA foreign_keys=ON")
            identifier = AclMapStore(connection).save(project, graph, run_id=run, item_id=item)
    except (OSError, ValueError, KeyError, UnicodeError, sqlite3.Error):
        _failure()
    typer.echo(identifier)


@app.command("load")
def load(
    database: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    project: Annotated[str, typer.Option("--project")],
    map_id: Annotated[str, typer.Option("--map-id")],
    output: Annotated[Path, typer.Option("--output", "-o")],
) -> None:
    """Прочитать неизменяемую карту указанного проекта без исходной конфигурации."""
    try:
        _separate(output, database)
        with closing(
            sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
        ) as connection:
            graph = AclMapStore(connection, initialize=False).get(project, map_id)
        output.write_text(export_acl_map_json(graph), encoding="utf-8")
    except (OSError, ValueError, KeyError, UnicodeError, sqlite3.Error):
        _failure()


@app.command("list")
def list_maps(
    database: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    project: Annotated[str, typer.Option("--project")],
) -> None:
    """Вывести проверенный каталог карт проекта в JSON."""
    try:
        with closing(
            sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
        ) as connection:
            records = AclMapStore(connection, initialize=False).list(project)
    except (OSError, ValueError, KeyError, UnicodeError, sqlite3.Error):
        _failure()
    typer.echo(json.dumps(records, ensure_ascii=False, indent=2))
