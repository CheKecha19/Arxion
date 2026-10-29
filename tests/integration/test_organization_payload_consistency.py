"""Independent direct-SQL negatives for the two reopened slice 1 payload findings."""

import copy
import json
import sqlite3
from pathlib import Path

import pytest
from tests.organization_oracle_fixtures import SCHEMA, STAMP

from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.interfaces.desktop.organization_inspection import inspect_workspace


def _payload() -> dict:
    golden = Path(__file__).resolve().parents[1] / "golden/expected/device_revision_complete.json"
    revision = json.loads(golden.read_text(encoding="utf-8"))
    parse = copy.deepcopy(revision["parse_result"])
    configuration = parse["configuration"]
    return {
        "status": "complete",
        "source_name": configuration["source_name"],
        "content_sha256": configuration["content_sha256"],
        "parse_result": parse,
        "revision": revision,
        "report": {
            "schema_version": "1.0.0",
            "revision_id": revision["revision_id"],
            "configuration_id": configuration["configuration_id"],
            "device_id": configuration["device_id"],
            "application_version": revision["application_version"],
            "parser_version": configuration["parser_version"],
            "check_catalog_version": "1.0.0",
            "require_logging": True,
            "require_comments": False,
            "max_pair_rules": 1000,
            "analyzed_at": configuration["imported_at"],
            "checks": [],
            "parse_coverage": copy.deepcopy(parse["coverage"]),
            "parse_warnings": copy.deepcopy(parse.get("warnings", [])),
            "parse_errors": copy.deepcopy(parse.get("errors", [])),
            "unsupported_constructs": copy.deepcopy(parse.get("unsupported_constructs", [])),
        },
    }


def _store(path: Path, payload: dict) -> bytes:
    with sqlite3.connect(path) as db:
        db.executescript(SCHEMA)
        db.execute("INSERT INTO projects VALUES(?,?,?,?)", ("origin", "SQL fixture", STAMP, "{}"))
        db.execute(
            "INSERT INTO runs VALUES(?,?,?,?,?,?)",
            (
                "run",
                "origin",
                STAMP,
                STAMP,
                "completed",
                "{}",
            ),
        )
        db.execute(
            "INSERT INTO items VALUES(?,?,?)",
            (
                "item",
                "run",
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            ),
        )
    return path.read_bytes()


def test_consistent_static_payload_is_accepted_without_rewriting_bytes(tmp_path: Path):
    path = tmp_path / "consistent.sqlite3"
    before = _store(path, _payload())

    result = inspect_workspace(path)

    assert result.phase == "legacy", result.issues
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("field", "value", "phase"),
    [
        ("parse_result", {}, "invalid"),
        ("revision", {"schema_version": "2.0.0"}, "invalid"),
        ("revision", {"schema_version": "99.0.0"}, "unsupported"),
        ("parse_result", {"schema_version": "99.0.0"}, "unsupported"),
    ],
)
def test_present_payload_is_validated_even_when_report_is_null(
    tmp_path: Path,
    field: str,
    value: dict,
    phase: str,
):
    payload = {"status": "error", "report": None, field: value}
    path = tmp_path / "report-null.sqlite3"
    before = _store(path, payload)

    result = inspect_workspace(path)

    assert result.phase == phase, result.issues
    assert result.issues
    assert path.read_bytes() == before


@pytest.mark.parametrize("field", ["parse_result", "revision"])
def test_valid_present_payload_without_report_remains_readable(tmp_path: Path, field: str):
    payload = {"status": "error", "report": None, field: _payload()[field]}
    path = tmp_path / "known-without-report.sqlite3"
    before = _store(path, payload)

    result = inspect_workspace(path)

    assert result.phase == "legacy", result.issues
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("device_id", "OTHER-DEVICE"),
        ("content_sha256", "b" * 64),
        ("source_name", "different-source.cfg"),
        ("parser_version", "different-parser"),
        ("platform", "other-platform"),
    ],
)
def test_same_configuration_uuid_does_not_hide_conflicting_top_parse_facts(
    tmp_path: Path,
    field: str,
    replacement: str,
):
    payload = _payload()
    payload["parse_result"]["configuration"][field] = replacement
    path = tmp_path / "same-id-conflict.sqlite3"
    before = _store(path, payload)

    result = inspect_workspace(path)

    assert result.phase == "invalid", result.issues
    assert any(issue.table == "items" and issue.severity == "error" for issue in result.issues)
    assert path.read_bytes() == before


def test_unknown_sibling_version_does_not_hide_malformed_known_parse(tmp_path: Path):
    payload = {
        "status": "error",
        "report": {"schema_version": "99.0.0"},
        "parse_result": {},
    }
    path = tmp_path / "unknown-and-malformed.sqlite3"
    before = _store(path, payload)

    result = inspect_workspace(path)

    assert result.phase == "invalid", result.issues
    assert any(issue.severity == "error" for issue in result.issues)
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "fact", ["rules", "source_map", "coverage", "envelope_hash", "report_parser"]
)
def test_shared_non_identity_facts_cannot_disagree_at_same_uuid(tmp_path: Path, fact: str):
    payload = _payload()
    if fact == "rules":
        payload["parse_result"]["rules"] = []
    elif fact == "source_map":
        payload["parse_result"]["source_map"]["review-extra"] = {
            "source_name": "fixture.config",
            "line_start": 1,
        }
        ParseResult.model_validate(payload["parse_result"])
        ParseResult.model_validate(payload["revision"]["parse_result"])
    elif fact == "coverage":
        payload["parse_result"]["coverage"]["discovered_constructs"] += 1
    elif fact == "envelope_hash":
        payload["content_sha256"] = "c" * 64
    else:
        payload["report"]["parser_version"] = "different-parser"
    path = tmp_path / "shared-facts.sqlite3"
    before = _store(path, payload)

    result = inspect_workspace(path)

    assert result.phase == "invalid", result.issues
    if fact == "source_map":
        assert any(issue.code == "ITEM_PARSE_RESULT_MISMATCH" for issue in result.issues)
    assert any(issue.table == "items" and issue.severity == "error" for issue in result.issues)
    assert path.read_bytes() == before
