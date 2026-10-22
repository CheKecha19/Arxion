"""Проверки базового поведения командного интерфейса."""

from typer.testing import CliRunner

from firewall_compliance import __version__
from firewall_compliance.interfaces.cli.main import app


def test_version_command_prints_package_version() -> None:
    """Команда version выводит версию установленного пакета."""
    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == __version__
