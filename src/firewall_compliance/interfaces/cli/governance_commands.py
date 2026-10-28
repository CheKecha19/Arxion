"""Local governance assessment of saved revisions; no Qt, SQLite or source rereads."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from firewall_compliance.application.analysis_reports import export_analysis_json
from firewall_compliance.application.analysis_result import AnalysisResult
from firewall_compliance.application.governance_workflow import assess_governance
from firewall_compliance.domain.policy_governance import (
    PolicyGovernanceInputs,
    PolicyGovernanceProfile,
)

app = typer.Typer(
    no_args_is_help=True,
    help="Проверка метаданных и статистики правил точной сохранённой ревизии.",
)


def _read(path: Path) -> str:
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("Input exceeds 64 MiB")
    return data.decode("utf-8-sig")


def _separate(output: Path, *inputs: Path | None) -> None:
    for source in inputs:
        if source is not None and (
            output.resolve() == source.resolve() or output.exists() and output.samefile(source)
        ):
            raise ValueError("Output must be separate from selected inputs")


@app.command("assess")
def assess(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    component: Annotated[str, typer.Option("--component")],
    profile: Annotated[Path, typer.Option("--profile", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")],
    inputs: Annotated[Path | None, typer.Option("--inputs", exists=True, dir_okay=False)] = None,
    assessed_at: Annotated[str | None, typer.Option("--assessed-at")] = None,
    max_operations: Annotated[int, typer.Option("--max-operations", min=1, max=10000000)] = 100000,
) -> None:
    """Создать новый общий результат без изменения исходного bundle и конфигурации."""
    try:
        _separate(output, path, profile, inputs)
        source = AnalysisResult.model_validate_json(_read(path))
        selected = PolicyGovernanceProfile.model_validate_json(_read(profile))
        evidence = PolicyGovernanceInputs.model_validate_json(_read(inputs)) if inputs else None
        date = datetime.fromisoformat(assessed_at) if assessed_at else datetime.now(UTC)
        result = assess_governance(
            source,
            component,
            selected,
            evidence,
            assessed_at=date,
            max_operations=max_operations,
        )
        output.write_text(export_analysis_json(result), encoding="utf-8")
    except (OSError, ValueError, UnicodeError):
        typer.echo(
            "Не удалось оценить правила: проверьте компонент, ревизию, "
            "профиль, дату и путь вывода.",
            err=True,
        )
        raise typer.Exit(2) from None
    typer.echo(str(result.analysis_id))
