"""Получение документа не доказывает состояние устройства."""

from datetime import timedelta
from typing import Any

from tests.fakes import FixtureParser, make_fixture_request
from tests.revision_fixtures import OBSERVATION

from firewall_compliance.application import firewall_assurance
from firewall_compliance.domain import DeviceRevision
from firewall_compliance.parsers import ParserRegistry


def test_application_preserves_explicit_observation_and_unknown_default(monkeypatch: Any) -> None:
    revisions: list[DeviceRevision] = []

    def capture(revision: DeviceRevision, **options: Any) -> Any:
        revisions.append(revision)
        return revision

    monkeypatch.setattr(firewall_assurance, "analyze_firewall", capture)
    request = make_fixture_request()
    source = request.source.model_copy(
        update={"file_modified_at": request.source.captured_at - timedelta(days=100)}
    )
    firewall_assurance.analyze_source(
        source, ParserRegistry([FixtureParser()]), imported_at=request.imported_at
    )
    assert revisions[0].observed_at is None
    assert revisions[0].sources[0].file_modified_at == source.file_modified_at
    source = source.model_copy(update={"observation": OBSERVATION})
    firewall_assurance.analyze_source(
        source, ParserRegistry([FixtureParser()]), imported_at=request.imported_at
    )
    assert revisions[1].observed_at == OBSERVATION.observed_at
    assert revisions[1].sources[0].observation == OBSERVATION
