"""Локальный CLI для запуска анализа экспортированных конфигураций."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

import typer
from pydantic import ValidationError

from firewall_compliance import __version__
from firewall_compliance.application.firewall_assurance import build_source_revision
from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.domain.policy_scope import PolicyScopeProfile
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


@app.command("usergate-collect")
def usergate_collect(
    host: Annotated[str, typer.Argument()],
    output: Annotated[Path, typer.Argument()],
    family: Annotated[str, typer.Option("--family")] = "7",
    transport: Annotated[str, typer.Option("--transport")] = "tcp",
    username: Annotated[str, typer.Option("--username")] = "Admin",
    ca_file: Annotated[Path | None, typer.Option("--ca-file", exists=True)] = None,
) -> None:
    """Прочитать UserGate 6.1.5+/7 в JSON для обычного импорта и анализа."""
    from firewall_compliance.infrastructure.usergate import UserGateError, UserGateReader

    if family not in {"6", "7"} or transport not in {"tcp", "https"}:
        raise typer.BadParameter("family: 6 или 7; transport: tcp или https")
    if output.exists():
        raise typer.BadParameter("Файл назначения уже существует.")
    password = typer.prompt("Пароль UserGate", hide_input=True)
    try:
        reader = UserGateReader(
            host,
            family="6" if family == "6" else "7",
            transport="https" if transport == "https" else "tcp",
            ca_file=str(ca_file) if ca_file else None,
        )
        snapshot = reader.collect(username, password)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(snapshot, stream, ensure_ascii=False, indent=2)
    except (UserGateError, ValueError, OSError) as exc:
        typer.echo(
            str(exc) if isinstance(exc, (UserGateError, ValueError)) else "Ошибка записи файла.",
            err=True,
        )
        raise typer.Exit(1) from None
    typer.echo(f"Снимок UserGate сохранён: {output}")


@app.command("ideco-collect")
def ideco_collect(
    host: Annotated[str, typer.Argument()],
    output: Annotated[Path, typer.Argument()],
    username: Annotated[str, typer.Option("--username")] = "admin",
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8443,
    ca_file: Annotated[Path | None, typer.Option("--ca-file", exists=True)] = None,
) -> None:
    """Прочитать Ideco v23 (классический VCE) в JSON для обычного импорта и анализа."""
    from firewall_compliance.infrastructure.ideco import IdecoError, IdecoReader

    if output.exists():
        raise typer.BadParameter("Файл назначения уже существует.")
    password = typer.prompt("Пароль Ideco", hide_input=True)
    try:
        reader = IdecoReader(
            host,
            port=port,
            ca_file=str(ca_file) if ca_file else None,
        )
        snapshot = reader.collect(username, password)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(snapshot, stream, ensure_ascii=False, indent=2)
    except (IdecoError, ValueError, OSError) as exc:
        typer.echo(
            str(exc) if isinstance(exc, (IdecoError, ValueError)) else "Ошибка записи файла.",
            err=True,
        )
        raise typer.Exit(1) from None
    typer.echo(f"Снимок Ideco сохранён: {output}")


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
    configuration_view: Annotated[
        Literal["unknown", "local", "effective", "effective_detail", "pending"],
        typer.Option("--configuration-view", help="Область экспорта, заявленная оператором."),
    ] = "unknown",
    node_path: Annotated[str | None, typer.Option("--node-path")] = None,
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
    policy_scope_profile: Annotated[
        Path | None, typer.Option("--policy-scope-profile", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Проверить локальную конфигурацию и вывести результат Firewall Assurance в JSON."""
    try:
        source = FileSourceReader().read(path)
        source = SourceDocument.model_validate(
            {
                **source.model_dump(), "configuration_complete": complete_config,
                "configuration_view": configuration_view, "configuration_node_path": node_path,
            }
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
        scope = (
            PolicyScopeProfile.model_validate_json(
                policy_scope_profile.read_text(encoding="utf-8-sig")
            )
            if policy_scope_profile
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
    revision = build_source_revision(
        source,
        create_default_registry(),
        imported_at=datetime.now(UTC),
    )
    if isinstance(revision, ParseFailure):
        typer.echo(revision.model_dump_json(indent=2))
        raise typer.Exit(2)
    from firewall_compliance.analysis.firewall_assurance import analyze_firewall

    _echo_switch_summary(revision.parse_result)
    _echo_controller_summary(revision.parse_result)
    result = analyze_firewall(
        revision,
        require_logging=require_logging,
        require_comments=require_comments,
        management_profile=profile,
        extended_policy_checks=extended_policy_checks or exposure is not None or scope is not None,
        policy_exposure_profile=exposure,
        policy_scope_profile=scope,
    )
    typer.echo(result.model_dump_json(indent=2))


def _echo_switch_summary(parsed: ParseResult) -> None:
    """Сводка импорта идёт в stderr, сохраняя JSON-контракт stdout."""
    policies = parsed.switch_policies
    if policies is None:
        return
    summary = policies.summary
    typer.echo(
        f"Импорт {parsed.configuration.platform}: ACL {summary.acl_count}, "
        f"исходных ACE {summary.ace_count}, привязок {summary.binding_count}; "
        f"управление {summary.management_bindings}, транзит {summary.transit_bindings}, "
        f"authorized managers {summary.manager_count}; "
        f"непривязанных ACL {summary.unbound_acls}, некорректных ACE {summary.invalid_entries}.",
        err=True,
    )
    if summary.transit_bindings == 0:
        typer.echo("Транзитные ACL в представленном файле не обнаружены.", err=True)


def _echo_controller_summary(parsed: ParseResult) -> None:
    """Обозначить область импорта без добавления полей в прежний JSON stdout."""
    inventory = parsed.controller_inventory
    if inventory is None:
        return
    typer.echo(
        f"ArubaOS Controller: объектов {len(inventory.objects)}, "
        f"связей {len(inventory.references)}, правил {len(parsed.rules)}, "
        f"диагностик {len(inventory.issues)}; "
        "настройки не доказывают активные назначения ролей или сквозную доступность.",
        err=True,
    )


@app.command("controller-inspect")
def controller_inspect(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=True, dir_okay=False)],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    format_name: Annotated[Literal["json", "csv", "html"], typer.Option("--format")] = "json",
    complete_config: Annotated[bool, typer.Option("--complete-config")] = False,
    configuration_view: Annotated[
        Literal["unknown", "local", "effective", "effective_detail", "pending"],
        typer.Option("--configuration-view"),
    ] = "unknown",
    node_path: Annotated[str | None, typer.Option("--node-path")] = None,
) -> None:
    """Экспортировать объекты, связи и ограниченный анализ конфигурации Controller."""
    from firewall_compliance.application.controller_reports import (
        controller_report_payload,
        export_controller_csv,
        export_controller_html,
    )

    try:
        if output is not None:
            _require_separate_output(output, path)
        source = FileSourceReader().read(path)
        source = SourceDocument.model_validate({
            **source.model_dump(), "configuration_complete": complete_config,
            "configuration_view": configuration_view, "configuration_node_path": node_path,
        })
        revision = build_source_revision(
            source, create_default_registry(), imported_at=datetime.now(UTC),
        )
        if isinstance(revision, ParseFailure):
            typer.echo(revision.model_dump_json(indent=2))
            raise typer.Exit(2)
        payload = controller_report_payload(revision.parse_result)
        if payload is None:
            raise ValueError("Источник не является поддержанным Controller export")
        text = (
            export_controller_csv(payload) if format_name == "csv"
            else export_controller_html(payload) if format_name == "html"
            else json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False)
        )
        if output is None:
            typer.echo(text)
        else:
            output.write_text(text, encoding="utf-8")
        _echo_controller_summary(revision.parse_result)
    except (OSError, ValueError, UnicodeError):
        typer.echo("Не удалось прочитать или экспортировать Controller-конфигурацию.", err=True)
        raise typer.Exit(2) from None


@app.command("controller-role")
def controller_role(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=True, dir_okay=False)],
    role: Annotated[str, typer.Option("--role")],
    source_ip: Annotated[str, typer.Option("--source")],
    destination_ip: Annotated[str, typer.Option("--destination")],
    protocol: Annotated[str, typer.Option("--protocol")] = "tcp",
    port: Annotated[int | None, typer.Option("--port", min=0, max=65535)] = None,
    source_port: Annotated[int | None, typer.Option("--source-port", min=0, max=65535)] = None,
    at_time: Annotated[datetime | None, typer.Option("--at-time")] = None,
    user_ip: Annotated[str | None, typer.Option("--user-ip")] = None,
    local_ip: Annotated[str | None, typer.Option("--local-ip")] = None,
    user_roles: Annotated[
        Path | None, typer.Option("--user-roles", exists=True, file_okay=True, dir_okay=False),
    ] = None,
    ap_group: Annotated[str | None, typer.Option("--ap-group")] = None,
    complete_config: Annotated[bool, typer.Option("--complete-config")] = False,
    configuration_view: Annotated[
        Literal["unknown", "local", "effective", "effective_detail", "pending"],
        typer.Option("--configuration-view"),
    ] = "unknown",
    node_path: Annotated[str | None, typer.Option("--node-path")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Оценить заданный пакет в роли с trace; результат не является reachability."""
    from firewall_compliance.analysis.controller_policy import evaluate_controller_role

    try:
        if output is not None:
            _require_separate_output(output, path, user_roles)
        context_roles: dict[str, str] | None = None
        if user_roles is not None:
            value = json.loads(user_roles.read_text(encoding="utf-8-sig"))
            if not isinstance(value, dict) or any(
                not isinstance(key, str) or not isinstance(role_name, str)
                for key, role_name in value.items()
            ):
                raise ValueError("user-roles must be an IP-to-role mapping")
            context_roles = value
        if at_time is not None and at_time.tzinfo is None:
            raise ValueError("at-time requires explicit timezone")
        source = FileSourceReader().read(path)
        source = SourceDocument.model_validate({
            **source.model_dump(), "configuration_complete": complete_config,
            "configuration_view": configuration_view, "configuration_node_path": node_path,
        })
        revision = build_source_revision(
            source, create_default_registry(), imported_at=datetime.now(UTC),
        )
        if isinstance(revision, ParseFailure):
            typer.echo(revision.model_dump_json(indent=2))
            raise typer.Exit(2)
        decision = evaluate_controller_role(
            revision.parse_result, role, source_ip, destination_ip, protocol, port,
            source_port=source_port, at_time=at_time, user_ip=user_ip, local_ip=local_ip,
            user_roles=context_roles, ap_group=ap_group,
        )
        text = decision.model_dump_json(indent=2)
        if output is None:
            typer.echo(text)
        else:
            output.write_text(text, encoding="utf-8")
    except (OSError, ValueError, UnicodeError):
        typer.echo("Не удалось оценить роль: проверьте экспорт, параметры и часовой пояс.", err=True)
        raise typer.Exit(2) from None


@app.command("switch-inspect")
def switch_inspect(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=True, dir_okay=False)],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    format_name: Annotated[Literal["json", "csv", "html"], typer.Option("--format")] = "json",
    complete_config: Annotated[bool, typer.Option("--complete-config")] = False,
) -> None:
    """Прочитать политики и структуру коммутатора без запуска проверок."""
    from firewall_compliance.application.switch_reports import (
        export_switch_csv,
        export_switch_html,
        switch_report_payload,
    )
    from firewall_compliance.application.switch_topology import build_switch_topology

    try:
        if output is not None:
            _require_separate_output(output, path)
        source = FileSourceReader().read(path)
        source = SourceDocument.model_validate(
            {**source.model_dump(), "configuration_complete": complete_config}
        )
        revision = build_source_revision(
            source, create_default_registry(), imported_at=datetime.now(UTC)
        )
        if isinstance(revision, ParseFailure):
            typer.echo(revision.model_dump_json(indent=2))
            raise typer.Exit(2)
        parsed = revision.parse_result
        payload = switch_report_payload(parsed, topology=build_switch_topology((revision,)))
        if payload is None:
            raise ValueError("Для файла не получены сведения конфигурации коммутатора.")
        if format_name == "csv":
            text = export_switch_csv(payload)
        elif format_name == "html":
            text = export_switch_html(payload)
        else:
            text = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False)
        if output is not None:
            output.write_text(text, encoding="utf-8")
        else:
            typer.echo(text)
        _echo_switch_summary(parsed)
    except (OSError, ValueError, UnicodeError):
        typer.echo(
            "Не удалось прочитать или экспортировать конфигурацию коммутатора; "
            "проверьте формат и путь файла.",
            err=True,
        )
        raise typer.Exit(2) from None


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
    policy_scope_profile: Annotated[
        Path | None, typer.Option("--policy-scope-profile", exists=True, dir_okay=False)
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
        _require_separate_output(
            output, path, management_profile, policy_exposure_profile, policy_scope_profile
        )
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
        scope = (
            PolicyScopeProfile.model_validate_json(_analysis_input(policy_scope_profile))
            if policy_scope_profile
            else None
        )
        result = analyze_source_result(
            source,
            create_default_registry(),
            imported_at=datetime.now(UTC),
            require_logging=require_logging,
            require_comments=require_comments,
            management_profile=management,
            extended_policy_checks=extended_policy_checks
            or exposure is not None
            or scope is not None,
            policy_exposure_profile=exposure,
            policy_scope_profile=scope,
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
