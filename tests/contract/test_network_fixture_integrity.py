"""Контроль происхождения и точных байтов подготовленных сетевых входов."""

import json
from hashlib import sha256
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1] / "fixtures" / "network_asa"


@pytest.mark.parametrize(
    "scenario_id", ["connected_static_default", "narrower_null0", "partial_unsupported"]
)
def test_network_fixture_hashes_and_partial_scope(scenario_id: str) -> None:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["contains_customer_data"] is False
    assert manifest["declared_version"] == "9.16"
    scenario = next(item for item in manifest["scenarios"] if item["id"] == scenario_id)
    assert scenario["observed_at"] is None
    paths: set[Path] = set()
    for source in scenario["sources"]:
        path = (ROOT / source["path"]).resolve()
        assert path.is_relative_to(ROOT.resolve())
        assert path not in paths
        paths.add(path)
        data = path.read_bytes()
        assert len(data) == source["byte_length"]
        assert sha256(data).hexdigest() == source["sha256"]
        assert data.decode("ascii") and b"\r" not in data and data.endswith(b"\n")
        assert source["observed_at"] is None and source["complete"] is False
        assert source["extent"] in {"excerpt", "truncated"}
    assert paths == {
        path.resolve() for path in (ROOT / scenario_id).iterdir() if path.suffix in {".cfg", ".txt"}
    }
