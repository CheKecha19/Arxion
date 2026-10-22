"""Локальный CLI для запуска анализа экспортированных конфигураций."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from firewall_compliance import __version__
from firewall_compliance.application.firewall_assurance import analyze_source
from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.parsers import ParseFailure, SourceDocument
from firewall_compliance.parsers.catalog import create_default_registry

app = typer.Typer(
    add_completion=False,
    help="Локальная система анализа конфигураций сетевого оборудования.",
    no_args_is_help=True,
)


@app.callback()
def callback() -> None:
    """Инициализировать командный интерфейс."""


@app.command()
def version() -> None:
    """Вывести версию приложения."""
    typer.echo(__version__)


@app.command()
def analyze(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=True, dir_okay=False)],
    require_logging: Annotated[bool, typer.Option("--require-logging/--no-require-logging")] = True,
    require_comments: Annotated[
        bool, typer.Option("--require-comments/--no-require-comments")
    ] = True,
    management_profile: Annotated[
        Path | None, typer.Option("--management-profile", exists=True, dir_okay=False)
    ] = None,
    complete_config: Annotated[
        bool,
        typer.Option(
            "--complete-config", help="Подтверждаю, что файл содержит полный экспорт конфигурации."
        ),
    ] = False,
) -> None:
    """Проверить локальную конфигурацию и вывести результат Firewall Assurance в JSON."""
    try:
        source = FileSourceReader().read(path)
        source = SourceDocument.model_validate(
            {**source.model_dump(), "configuration_complete": complete_config}
        )
        profile = (
            ManagementProfile.model_validate_json(
                management_profile.read_text(encoding="utf-8-sig")
            )
            if management_profile
            else ManagementProfile()
        )
    except OSError:
        typer.echo("Не удалось прочитать входной файл.", err=True)
        raise typer.Exit(2) from None
    except (ValidationError, UnicodeError):
        typer.echo(
            "Некорректный профиль управления: проверьте JSON, адреса и типы значений.", err=True
        )
        raise typer.Exit(2) from None
    result = analyze_source(
        source,
        create_default_registry(),
        imported_at=datetime.now(UTC),
        require_logging=require_logging,
        require_comments=require_comments,
        management_profile=profile,
    )
    typer.echo(result.model_dump_json(indent=2))
    if isinstance(result, ParseFailure):
        raise typer.Exit(2)


def main() -> None:
    """Запустить командный интерфейс."""
    app()
