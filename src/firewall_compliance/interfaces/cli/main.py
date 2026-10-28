"""Локальный CLI для запуска анализа экспортированных конфигураций."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

import typer
from pydantic import ValidationError

from firewall_compliance import __version__
from firewall_compliance.application.firewall_assurance import analyze_source
from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.infrastructure.source_reader import FileSourceReader
from firewall_compliance.interfaces.cli.acl_map_commands import app as acl_map_app
from firewall_compliance.interfaces.cli.control_commands import app as controls_app
from firewall_compliance.interfaces.cli.governance_commands import app as governance_app
from firewall_compliance.parsers import ParseFailure, SourceDocument
from firewall_compliance.parsers.catalog import create_default_registry

app = typer.Typer(
    add_completion=False,
    help="Локальная система анализа конфигураций сетевого оборудования.",
    no_args_is_help=True,
)
app.add_typer(acl_map_app, name="acl-map")
app.add_typer(controls_app, name="controls")
app.add_typer(governance_app, name="governance")


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
    extended_policy_checks: Annotated[
        bool,
        typer.Option(
            "--extended-policy-checks",
            help="Частичное/составное затенение и проверки заданной политики сервисов.",
        ),
    ] = False,
    policy_exposure_profile: Annotated[
        Path | None, typer.Option("--policy-exposure-profile", exists=True, dir_okay=False)
    ] = None,
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
        exposure = (
            PolicyExposureProfile.model_validate_json(
                policy_exposure_profile.read_text(encoding="utf-8-sig")
            )
            if policy_exposure_profile
            else None
        )
    except OSError:
        typer.echo("Не удалось прочитать входной файл.", err=True)
        raise typer.Exit(2) from None
    except (ValidationError, UnicodeError):
        typer.echo(
            "Некорректный профиль проверок: проверьте JSON, адреса и типы значений.", err=True
        )
        raise typer.Exit(2) from None
    result = analyze_source(
        source,
        create_default_registry(),
        imported_at=datetime.now(UTC),
        require_logging=require_logging,
        require_comments=require_comments,
        management_profile=profile,
        extended_policy_checks=extended_policy_checks or exposure is not None,
        policy_exposure_profile=exposure,
    )
    typer.echo(result.model_dump_json(indent=2))
    if isinstance(result, ParseFailure):
        raise typer.Exit(2)


def _analysis_input(path: Path) -> str:
    """Read an explicitly selected UTF-8 artifact with a bounded byte budget."""
    limit = 64 * 1024 * 1024
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Размер общего результата превышает 64 МиБ.")
    return data.decode("utf-8-sig")


def _require_separate_output(output: Path, *inputs: Path | None) -> None:
    """Protect selected inputs, including aliases which resolve to the same inode."""
    for source in inputs:
        if source is not None and (
            output.resolve() == source.resolve() or (output.exists() and output.samefile(source))
        ):
            raise ValueError("Сохраните отчёт отдельно от входных файлов.")


@app.command()
def analyze_bundle(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")],
    extended_policy_checks: Annotated[bool, typer.Option("--extended-policy-checks")] = False,
    management_profile: Annotated[
        Path | None, typer.Option("--management-profile", exists=True, dir_okay=False)
    ] = None,
    policy_exposure_profile: Annotated[
        Path | None, typer.Option("--policy-exposure-profile", exists=True, dir_okay=False)
    ] = None,
    complete_config: Annotated[bool, typer.Option("--complete-config")] = False,
    require_logging: Annotated[bool, typer.Option("--require-logging/--no-require-logging")] = True,
    require_comments: Annotated[
        bool, typer.Option("--require-comments/--no-require-comments")
    ] = True,
) -> None:
    """Сохранить общий результат со снимком, параметрами и диагностикой в JSON."""
    from firewall_compliance.application.analysis_reports import export_analysis_json
    from firewall_compliance.application.analysis_workflow import analyze_source_result

    try:
        _require_separate_output(output, path, management_profile, policy_exposure_profile)
        source = FileSourceReader().read(path)
        source = SourceDocument.model_validate(
            {**source.model_dump(), "configuration_complete": complete_config}
        )
        management = (
            ManagementProfile.model_validate_json(_analysis_input(management_profile))
            if management_profile
            else None
        )
        exposure = (
            PolicyExposureProfile.model_validate_json(_analysis_input(policy_exposure_profile))
            if policy_exposure_profile
            else None
        )
        result = analyze_source_result(
            source,
            create_default_registry(),
            imported_at=datetime.now(UTC),
            require_logging=require_logging,
            require_comments=require_comments,
            management_profile=management,
            extended_policy_checks=extended_policy_checks or exposure is not None,
            policy_exposure_profile=exposure,
        )
        output.write_text(export_analysis_json(result), encoding="utf-8")
    except (OSError, ValueError, UnicodeError):
        typer.echo(
            "Не удалось сохранить общий результат: проверьте вход, профиль и путь отчёта.", err=True
        )
        raise typer.Exit(2) from None
    typer.echo(str(result.analysis_id))
    if result.state == "failed":
        typer.echo("Разбор не выполнен; диагностика сохранена в результате.", err=True)
        raise typer.Exit(2)


@app.command()
def analysis_export(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")],
    format_name: Annotated[Literal["json", "csv", "html"], typer.Option("--format")] = "html",
) -> None:
    """Проверить сохранённый общий результат и экспортировать без чтения конфигурации."""
    from firewall_compliance.application.analysis_reports import (
        export_analysis_csv,
        export_analysis_html,
        export_analysis_json,
    )
    from firewall_compliance.application.analysis_result import AnalysisResult

    try:
        _require_separate_output(output, path)
        result = AnalysisResult.model_validate_json(_analysis_input(path))
        renderers = {
            "json": export_analysis_json,
            "csv": export_analysis_csv,
            "html": export_analysis_html,
        }
        output.write_text(renderers[format_name](result), encoding="utf-8")
    except (OSError, ValueError, UnicodeError):
        typer.echo(
            "Не удалось экспортировать результат: проверьте формат, версию и путь файла.", err=True
        )
        raise typer.Exit(2) from None
    typer.echo(str(result.analysis_id))


def main() -> None:
    """Запустить командный интерфейс."""
    app()
