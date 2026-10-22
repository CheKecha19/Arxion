"""R1 presentation must preserve historical contracts and incomplete import evidence."""

from copy import deepcopy
from pathlib import Path
from typing import Any

from firewall_compliance.interfaces.desktop.backend import AnalysisSession, analyze_file
from firewall_compliance.interfaces.desktop.batch_reports import (
    build_batch_report,
    render_batch_html,
)
from firewall_compliance.interfaces.desktop.project_store import ProjectStore

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _at_path(value: Any, path: str) -> Any:
    for token in path.strip("/").split("/"):
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def test_historical_partial_report_is_not_rewritten_by_projection_or_html(tmp_path: Path) -> None:
    from firewall_compliance.interfaces.desktop.result_presentation import project_item_limitations

    session = analyze_file(FIXTURES / "candidates/cisco-asa/asa_nat_unsupported.cfg")
    assert isinstance(session, AnalysisSession)
    store = ProjectStore(tmp_path / "history.sqlite3")
    run_id = store.create_run(store.create_project("Synthetic R1 history"))
    store.record_session(run_id, session)
    store.finish_run(run_id)
    historical = deepcopy(store.get_run(run_id))
    package = build_batch_report(store, run_id)
    original = deepcopy(package)

    groups = project_item_limitations(package["items"][0])
    rendered = render_batch_html(package)

    assert groups, "The NAT import is partial and must retain its limitations"
    nat_groups = [group for group in groups if group.code == "nat"]
    assert len(nat_groups) == 1, "Stored parser diagnostics alias the same report cause"
    assert nat_groups[0].occurrence_count == 2
    nat_diagnostic = session.report.unsupported_constructs[0].model_dump(mode="json")
    diagnostic_index = package["items"][0]["diagnostics"].index(nat_diagnostic)
    assert {reference.path for reference in nat_groups[0].raw_refs} == {
        f"/diagnostics/{diagnostic_index}",
        "/result/unsupported_constructs/0",
    }
    for group in groups:
        for reference in group.raw_refs:
            assert _at_path(package["items"][0], reference.path) == reference.raw
    historical_groups = project_item_limitations(historical["items"][0])
    stored_nat = [group for group in historical_groups if group.code == "nat"]
    assert len(stored_nat) == 1
    assert {reference.path for reference in stored_nat[0].raw_refs} == {
        f"/diagnostics/{diagnostic_index}",
        "/report/unsupported_constructs/0",
    }
    assert [(g.code, g.occurrence_count) for g in historical_groups] == [
        (g.code, g.occurrence_count) for g in groups
    ]
    for group in historical_groups:
        for reference in group.raw_refs:
            assert _at_path(historical["items"][0], reference.path) == reference.raw
    assert "INCOMPLETE_PARSE" in rendered
    assert "nat" in rendered.lower()
    assert package == original
    assert store.get_run(run_id) == historical
    assert package["schema_version"] == "1.0.0"
    assert package["items"][0]["result"] == session.report.model_dump(mode="json")


def test_fragment_exclusion_still_retains_unknown_diagnostics_and_original_report(
    tmp_path: Path,
) -> None:
    from firewall_compliance.interfaces.desktop.result_presentation import project_item_limitations

    session = analyze_file(FIXTURES / "candidates/cisco-asa/asa_nat_unsupported.cfg")
    assert isinstance(session, AnalysisSession)
    store = ProjectStore(tmp_path / "history.sqlite3")
    run_id = store.create_run(store.create_project("Synthetic R1 fragment exclusion"))
    store.record_session(run_id, session)
    store.finish_run(run_id)
    with_fragments = build_batch_report(store, run_id, include_fragments=True)
    without_fragments = build_batch_report(store, run_id, include_fragments=False)

    original_groups = project_item_limitations(with_fragments["items"][0])
    redacted_groups = project_item_limitations(without_fragments["items"][0])

    assert without_fragments["items"][0]["excerpts"] == []
    assert without_fragments["items"][0]["result"] == with_fragments["items"][0]["result"]
    assert without_fragments["items"][0]["diagnostics"] == with_fragments["items"][0]["diagnostics"]
    assert [(g.code, g.occurrence_count) for g in redacted_groups] == [
        (g.code, g.occurrence_count) for g in original_groups
    ]


def test_real_unsupported_comware_condition_keeps_aggregate_uncertainty(tmp_path: Path) -> None:
    from firewall_compliance.interfaces.desktop.object_presentation import (
        rule_details,
        rule_endpoint_summary,
        rule_service_summary,
    )

    source = tmp_path / "synthetic-comware.cfg"
    source.write_text(
        "version 7.1.045\nsysname SYNTHETIC-R1\nacl advanced 3000\n"
        " rule 5 permit tcp source-port eq 1234 destination 192.0.2.1 0 destination-port eq 443\n",
        encoding="utf-8",
    )
    session = analyze_file(source)
    assert isinstance(session, AnalysisSession)
    assert session.parse_result.unsupported_constructs
    rule = session.parse_result.rules[0].model_dump(mode="json")
    original = deepcopy(rule)

    source_summary = rule_endpoint_summary(rule, "sources")
    service_summary = rule_service_summary(rule)
    details = dict(rule_details(rule))

    for text in (source_summary, service_summary, details["Откуда"], details["Сервис"]):
        assert "Любой адрес" not in text
        assert "все порты" not in text.lower()
        assert "не определ" in text.lower() or "не подтвержден" in text.lower()
    assert rule == original
