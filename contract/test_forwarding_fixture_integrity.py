"""Подготовленные фрагменты не являются полными аппаратными экспортами."""

import json
from hashlib import sha256
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1] / "fixtures" / "forwarding_asa"
MANIFEST = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))


def test_forwarding_manifest_scope_and_inventory() -> None:
    assert MANIFEST["schema_version"] == "1.0.0"
    assert MANIFEST["contains_customer_data"] is False
    assert MANIFEST["declared_version"] == "9.16"
    assert MANIFEST["origin"]
    scenarios = MANIFEST["scenarios"]
    assert len(scenarios) >= 6
    identifiers = [scenario["id"] for scenario in scenarios]
    assert len(set(identifiers)) == len(identifiers)
    listed = [source["path"] for scenario in scenarios for source in scenario["sources"]]
    assert len(set(listed)) == len(listed)
    assert {(ROOT / path).resolve() for path in listed} == {
        path.resolve() for path in ROOT.rglob("*.cfg")
    }
    assert (ROOT / "README.md").is_file()


@pytest.mark.parametrize("scenario", MANIFEST["scenarios"], ids=lambda item: item["id"])
def test_forwarding_payload_integrity_and_unproven_absence(scenario: dict) -> None:
    assert scenario["observed_at"] is None
    assert scenario["feature_evidence"]["system_nat"] == "unknown"
    assert "absent" not in scenario["feature_evidence"].values()
    assert scenario["sources"]
    for source in scenario["sources"]:
        path = (ROOT / source["path"]).resolve()
        assert path.is_relative_to(ROOT.resolve())
        data = path.read_bytes()
        assert sha256(data).hexdigest() == source["sha256"]
        assert len(data) == source["byte_length"]
        assert data.decode("ascii")
        assert b"\r" not in data and data.endswith(b"\n")
        assert data.startswith(b"ASA Version 9.16(4)\n")
        assert source["source_kind"] == "asa_forwarding_config"
        assert source["command"] in {"show running-config", "show running-config all"}
        assert source["selection"] == "authored_excerpt"
        assert source["extent"] in {"excerpt", "truncated"}
        assert source["complete"] is False
        assert source["observed_at"] is None
