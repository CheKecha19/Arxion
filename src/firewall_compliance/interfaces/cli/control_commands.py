"""Explicit local technical-control profiles, assessment and export."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

import typer

from firewall_compliance.application.analysis_result import AnalysisResult
from firewall_compliance.application.control_assessment import (
    ControlAssessment,
    assess_controls,
    export_control_assessment_csv,
    export_control_assessment_html,
    export_control_assessment_json,
    internal_control_catalogue,
)
from firewall_compliance.domain.controls import (
    ControlCatalogue,
    ControlRequirement,
    OrganizationControlProfile,
)

app = typer.Typer(no_args_is_help=True, help="Технические свидетельства для внутренних контролей.")


def _read(path: Path) -> str:
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("Input exceeds 64 MiB")
    return data.decode("utf-8-sig")


def _separate(output: Path, *inputs: Path | None) -> None:
    for path in inputs:
        if path is not None and (
            output.resolve() == path.resolve() or output.exists() and output.samefile(path)
        ):
            raise ValueError("Output must be separate from selected inputs")


def _failure() -> None:
    typer.echo(
        "Не удалось обработать свидетельства: проверьте профиль, область, версию и путь вывода.",
        err=True,
    )
    raise typer.Exit(2)


@app.command("catalogue")
def catalogue(output: Annotated[Path, typer.Option("--output", "-o")]) -> None:
    """Сохранить ограниченный внутренний каталог без внешних сопоставлений NIST/CIS."""
    try:
        output.write_text(internal_control_catalogue().model_dump_json(indent=2), encoding="utf-8")
    except (ValueError, OSError, UnicodeError):
        _failure()


@app.command("profile-template")
def profile_template(
    output: Annotated[Path, typer.Option("--output", "-o")],
    organization: Annotated[str, typer.Option("--organization")],
    scope_reference: Annotated[str, typer.Option("--scope-reference")],
    profile_id: Annotated[str, typer.Option("--profile-id")],
    controls: Annotated[list[str], typer.Option("--control")],
    justification: Annotated[str, typer.Option("--justification")],
    version: Annotated[str, typer.Option("--version")] = "1",
    applicable: Annotated[bool, typer.Option("--applicable/--not-applicable")] = True,
) -> None:
    """Создать профиль из явно выбранных требований; команда не утверждает его за организацию."""
    try:
        known = {value.control_id for value in internal_control_catalogue().controls}
        if set(controls) - known:
            raise ValueError("Control is not present in internal catalogue")
        profile = OrganizationControlProfile(
            profile_id=profile_id,
            version=version,
            organization=organization,
            scope_reference=scope_reference,
            requirements=tuple(
                ControlRequirement(
                    control_id=control, applicable=applicable, justification=justification
                )
                for control in controls
            ),
        )
        output.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
    except (ValueError, OSError, UnicodeError):
        _failure()


@app.command("assess")
def assess(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    profile: Annotated[Path, typer.Option("--profile", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")],
    catalogue_path: Annotated[
        Path | None, typer.Option("--catalogue", exists=True, dir_okay=False)
    ] = None,
    assessed_at: Annotated[str | None, typer.Option("--assessed-at")] = None,
) -> None:
    """Оценить сохранённый AnalysisResult с точным профилем и каталогом без исходных файлов."""
    try:
        _separate(output, path, profile, catalogue_path)
        source = AnalysisResult.model_validate_json(_read(path))
        selected = OrganizationControlProfile.model_validate_json(_read(profile))
        catalogue = (
            ControlCatalogue.model_validate_json(_read(catalogue_path))
            if catalogue_path
            else internal_control_catalogue()
        )
        date = datetime.fromisoformat(assessed_at) if assessed_at else datetime.now(UTC)
        result = assess_controls(source, selected, catalogue, assessed_at=date)
        output.write_text(export_control_assessment_json(result), encoding="utf-8")
    except (ValueError, OSError, UnicodeError):
        _failure()
    typer.echo(str(result.assessment_id))


@app.command("export")
def export(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")],
    format_name: Annotated[Literal["json", "csv", "html"], typer.Option("--format")] = "html",
) -> None:
    """Проверить исторические свидетельства и экспортировать их без текущих настроек."""
    try:
        _separate(output, path)
        result = ControlAssessment.model_validate_json(_read(path))
        renderers = {
            "json": export_control_assessment_json,
            "csv": export_control_assessment_csv,
            "html": export_control_assessment_html,
        }
        output.write_text(renderers[format_name](result), encoding="utf-8")
    except (ValueError, OSError, UnicodeError):
        _failure()
    typer.echo(str(result.assessment_id))
