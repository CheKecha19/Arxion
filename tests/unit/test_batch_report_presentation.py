"""Offline HTML shares groups with Qt helpers and retains raw report provenance."""

import copy
from html.parser import HTMLParser
from typing import Any

from firewall_compliance.interfaces.desktop.batch_reports import render_batch_html
from firewall_compliance.interfaces.desktop.result_presentation import project_item_limitations


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.targets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(str(values["id"]))
        if tag == "a" and str(values.get("href", "")).startswith("#"):
            self.targets.append(str(values["href"])[1:])


def _package() -> dict[str, Any]:
    finding = {
        "finding_id": "f1",
        "severity": "high",
        "title": "<title>",
        "description": "<script>bad</script>",
        "recommendation": "Review source",
        "affected_rule_ids": ["r1"],
        "evidence": {
            "summary": "Evidence summary",
            "related_rule_ids": ["r1"],
            "source_locations": [{"source_name": "test.cfg", "line_start": 8}],
            "facts": {"untruncated": "<raw-fact>"},
            "limitations": ["Evidence caveat"],
        },
    }
    limits = [
        {"code": "LOCAL", "message": "Selected rule caveat", "rule_ids": ["r1"]},
        {"code": "OTHER", "message": "Unrelated local caveat", "rule_ids": ["r2"]},
        {"code": "COMMON", "message": "Source incomplete", "rule_ids": []},
    ]
    return {
        "project": {"name": "Synthetic"},
        "run": {"created_at": "today", "state": "completed"},
        "summary": {"files": 1, "findings_by_severity": {"high": 1}, "imports": {"partial": 1}},
        "limitations": ["No whole-device safety claim"],
        "fragments_included": False,
        "user_decisions": {},
        "items": [
            {
                "item_id": "i1",
                "source_name": "test.cfg",
                "content_sha256": "a" * 64,
                "status": "partial",
                "diagnostics": [],
                "excerpts": [],
                "result": {
                    "device_id": "d1",
                    "revision_id": "r",
                    "parser_version": "1",
                    "parse_coverage": {
                        "recognized_constructs": 1,
                        "discovered_constructs": 2,
                        "unsupported_constructs": 1,
                    },
                    "checks": [
                        {
                            "check_id": "A",
                            "status": "partial",
                            "limitations": limits,
                            "findings": [finding],
                        },
                        {
                            "check_id": "B",
                            "status": "partial",
                            "limitations": [limits[0]],
                            "findings": [],
                        },
                    ],
                },
            }
        ],
    }


def test_html_matches_projection_counts_and_has_one_anchor_for_each_group() -> None:
    package = _package()
    before = copy.deepcopy(package)
    rendered = render_batch_html(package)
    links = _Links()
    links.feed(rendered)
    groups = project_item_limitations(package["items"][0])
    assert {group.key for group in groups} == {key for key in links.ids if key.startswith("lim-")}
    assert len(set(links.ids)) == len(links.ids)
    assert set(links.targets) <= set(links.ids)
    assert "Затронуто правил: 1; проверок: 2; исходных записей: 2" in rendered
    assert "Выполнена частично: 2" in rendered
    assert "/result/checks/0/limitations/0" in rendered
    assert "/result/checks/1/limitations/0" in rendered
    assert package == before


def test_finding_has_only_relevant_reason_links_and_safe_human_evidence() -> None:
    rendered = render_batch_html(_package())
    article = rendered.split("<article>", 1)[1].split("</article>", 1)[0]
    assert "Selected rule caveat" in article
    assert "Unrelated local caveat" not in article
    assert "Source incomplete" in article
    assert "Общие ограничения источника и проверки: 1 групп" in article
    assert "Evidence summary" in article
    assert "test.cfg" in article
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "&lt;raw-fact&gt;" in article
    assert "<details open>" not in article
    assert '<html lang="ru">' in rendered
    assert 'src="http' not in rendered
