"""Presentation groups are reversible, scoped, deterministic and conservative."""

import copy
import json
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from firewall_compliance.interfaces.desktop.result_presentation import (
    check_limitations,
    finding_limitations,
    group_details,
    group_summary,
    project_item_limitations,
)


def _item() -> dict[str, Any]:
    return {
        "id": "item-a",
        "source_name": "same.cfg",
        "content_sha256": "a" * 64,
        "diagnostics": [{"code": "PARSER", "message": "Общее ограничение"}],
        "report": {
            "device_id": "d",
            "revision_id": "r",
            "checks": [
                {
                    "check_id": "A",
                    "limitations": [
                        {"code": "UNKNOWN", "message": "Объект office", "rule_ids": ["r1"]},
                        {"code": "UNKNOWN", "message": "Объект office", "rule_ids": ["r2"]},
                        {"code": "SCOPE", "message": "Часть источника неизвестна", "rule_ids": []},
                    ],
                    "findings": [
                        {
                            "finding_id": "f1",
                            "affected_rule_ids": ["r1"],
                            "evidence": {
                                "related_rule_ids": [],
                                "limitations": ["Условие ограничено"],
                            },
                        }
                    ],
                },
                {
                    "check_id": "B",
                    "limitations": [
                        {"code": "UNKNOWN", "message": "Объект office", "rule_ids": ["r1"]},
                    ],
                    "findings": [],
                },
            ],
        },
    }


def test_scope_counts_raw_pointers_and_input_are_preserved() -> None:
    item = _item()
    before = copy.deepcopy(item)
    groups = project_item_limitations(item)
    assert sum(group.occurrence_count for group in groups) == 6
    assert len(groups) == 5
    shared = next(
        group for group in groups if group.rule_ids == ("r1",) and group.origin == "check"
    )
    assert shared.check_ids == ("A", "B")
    assert shared.occurrence_count == 2
    assert "Затронуто правил: 1" in group_summary(shared)
    assert "проверок: 2" in group_summary(shared)
    assert len(json.loads(group_details(shared))["raw_records"]) == 2
    paths = []
    for group in groups:
        for ref in group.raw_refs:
            current: Any = item
            for component in ref.path.strip("/").split("/"):
                current = (
                    current[int(component)] if isinstance(current, list) else current[component]
                )
            assert current == ref.raw
            paths.append(ref.path)
    assert len(set(paths)) == len(paths)
    assert item == before


def test_finding_selection_separates_unrelated_local_and_common() -> None:
    item = _item()
    check = item["report"]["checks"][0]
    selected = finding_limitations(item, check, check["findings"][0])
    assert len(selected.local) == 2
    assert {group.code for group in selected.local} == {"UNKNOWN", "EVIDENCE_LIMITATION"}
    assert {group.code for group in selected.common} == {"PARSER", "SCOPE"}
    assert selected.unrelated_count == 1
    assert all("r2" not in group.rule_ids for group in selected.local)
    assert len(check_limitations(item, check)) == 3
    assert "Затронутые правила не указаны" in group_summary(selected.common[0])


def test_export_and_storage_share_group_keys_but_have_real_raw_paths() -> None:
    item = _item()
    exported = {
        "item_id": item["id"],
        **{key: value for key, value in item.items() if key not in {"id", "report"}},
        "result": item["report"],
    }
    stored = project_item_limitations(item)
    groups = project_item_limitations(exported)
    assert [group.key for group in stored] == [group.key for group in groups]
    assert any(ref.path.startswith("/report/") for group in stored for ref in group.raw_refs)
    assert any(ref.path.startswith("/result/") for group in groups for ref in group.raw_refs)


def test_context_params_origin_and_negative_wording_never_collapse() -> None:
    item = _item()
    checks = item["report"]["checks"]
    checks[0]["limitations"].extend(
        [
            {"code": "UNKNOWN", "message": "Объект office не разрешён", "rule_ids": ["r1"]},
            {
                "code": "UNKNOWN",
                "message": "Объект office",
                "rule_ids": ["r1"],
                "scope": "management",
            },
        ]
    )
    groups = project_item_limitations(item)
    assert len(groups) == 7
    changed = copy.deepcopy(item)
    changed["report"]["revision_id"] = "other-revision"
    assert {group.key for group in groups}.isdisjoint(
        group.key for group in project_item_limitations(changed)
    )
    reordered = copy.deepcopy(item)
    reordered["report"]["checks"].reverse()
    assert {group.key for group in groups} == {
        group.key for group in project_item_limitations(reordered)
    }


@given(
    st.lists(st.text(min_size=1).filter(lambda value: value.strip() != ""), min_size=1, max_size=25)
)
def test_raw_occurrence_round_trip_for_arbitrary_messages(messages: list[str]) -> None:
    item = {
        "report": {
            "checks": [
                {
                    "check_id": "A",
                    "limitations": [
                        {"code": "RAW", "message": message, "rule_ids": ["r"]}
                        for message in messages
                    ],
                }
            ]
        }
    }
    groups = project_item_limitations(item)
    assert sum(group.occurrence_count for group in groups) == len(messages)
    restored = {ref.path: ref.raw for group in groups for ref in group.raw_refs}
    for index, message in enumerate(messages):
        raw = restored[f"/report/checks/0/limitations/{index}"]
        assert isinstance(raw, dict)
        assert raw["message"] == message


def test_malformed_raw_records_still_have_a_diagnostic_and_reference() -> None:
    item = {"diagnostics": [None, {"code": "MISSING_MESSAGE"}, "unexpected"]}
    groups = project_item_limitations(item)
    assert len(groups) == 3
    assert [group.raw_refs[0].raw for group in groups] == item["diagnostics"]


def test_stored_parser_diagnostic_alias_has_one_group_and_both_raw_origins() -> None:
    raw = {
        "code": "NAT_UNSUPPORTED",
        "message": "NAT condition not analysed",
        "level": "warning",
        "source_location": {"source_name": "a.cfg", "line_start": 10},
    }
    item = {"diagnostics": [copy.deepcopy(raw)], "report": {"parse_warnings": [raw]}}
    before = copy.deepcopy(item)
    groups = project_item_limitations(item)
    assert len(groups) == 1
    assert groups[0].origin == "parse_warnings"
    assert groups[0].occurrence_count == 2
    assert {ref.origin for ref in groups[0].raw_refs} == {"diagnostic", "parse_warnings"}
    assert {ref.path for ref in groups[0].raw_refs} == {
        "/diagnostics/0",
        "/report/parse_warnings/0",
    }
    assert item == before


def test_parser_alias_requires_full_raw_equality_and_unambiguous_provenance() -> None:
    raw = {
        "code": "NAT_UNSUPPORTED",
        "message": "NAT condition not analysed",
        "source_location": {"source_name": "a.cfg", "line_start": 10},
    }
    elsewhere = {**raw, "source_location": {"source_name": "a.cfg", "line_start": 11}}
    item = {"diagnostics": [elsewhere], "report": {"parse_warnings": [raw]}}
    assert len(project_item_limitations(item)) == 2
    item = {"diagnostics": [{**raw, "scope": "management"}], "report": {"parse_warnings": [raw]}}
    assert len(project_item_limitations(item)) == 2
    ambiguous = {"diagnostics": [raw], "report": {"parse_warnings": [raw], "parse_errors": [raw]}}
    assert len(project_item_limitations(ambiguous)) == 3
