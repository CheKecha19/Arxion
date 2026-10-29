"""Ноль находок и отсутствие выполнения не смешиваются в представлении."""

from firewall_compliance.interfaces.desktop.batch_reports import render_batch_html
from firewall_compliance.interfaces.desktop.check_presentation import (
    check_execution_status,
    check_reasons,
    check_status_label,
)


def test_zero_findings_does_not_mean_not_executed() -> None:
    check = {"status": "complete", "findings": [], "limitations": []}
    assert check_execution_status(check) == "complete"
    assert check_status_label(check) == "Выполнена в поддержанной области"


def test_partial_with_findings_keeps_partial_execution() -> None:
    check = {
        "status": "partial",
        "findings": [],
        "limitations": [{"code": "UNKNOWN", "message": "Неизвестное условие"}],
    }
    assert check_status_label(check) == "Выполнена частично"
    assert check_reasons(check) == "UNKNOWN: Неизвестное условие"


def test_explicit_not_executed_preserves_serialized_status() -> None:
    check = {
        "status": "partial",
        "findings": [],
        "limitations": [{"code": "CHECK_NOT_EXECUTED", "message": "Нет пригодных ACL"}],
    }
    assert check_execution_status(check) == "not_executed"
    assert check_status_label(check) == "Не выполнена"
    assert check["status"] == "partial"


def test_html_distinguishes_execution_and_escapes_reason() -> None:
    checks = [
        {
            "check_id": "FW-DUPLICATE",
            "status": "partial",
            "findings": [],
            "limitations": [{"code": "CHECK_NOT_EXECUTED", "message": "<no ACL>"}],
        },
        {"check_id": "FW-ANY-ANY", "status": "complete", "findings": [], "limitations": []},
    ]
    package = {
        "project": {"name": "Test"},
        "run": {"created_at": "today", "state": "completed"},
        "summary": {
            "files": 1,
            "findings_by_severity": {},
            "imports": {"partial": 1},
            "checks_by_status": {"partial": 1, "complete": 1},
        },
        "limitations": [],
        "fragments_included": False,
        "user_decisions": {},
        "items": [
            {
                "item_id": "i",
                "source_name": "x.cfg",
                "content_sha256": "abc",
                "status": "partial",
                "diagnostics": [],
                "excerpts": [],
                "result": {
                    "device_id": "d",
                    "revision_id": "r",
                    "parser_version": "1",
                    "parse_coverage": {
                        "recognized_constructs": 1,
                        "discovered_constructs": 1,
                        "unsupported_constructs": 0,
                    },
                    "checks": checks,
                },
            }
        ],
    }
    rendered = render_batch_html(package)
    assert "Не выполнена: 1" in rendered
    assert "Выполнена в поддержанной области: 1" in rendered
    assert "CHECK_NOT_EXECUTED: &lt;no ACL&gt;" in rendered
    assert "<no ACL>" not in rendered
    assert checks[0]["status"] == "partial"
