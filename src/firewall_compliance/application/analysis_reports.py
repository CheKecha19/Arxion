"""Pure exports of already validated bundles; exporters never execute an analysis engine."""

import csv
import html
import io
import json
from collections.abc import Iterator
from typing import Any

from firewall_compliance.application.analysis_result import (
    AnalysisComponent,
    AnalysisResult,
    AttemptComponent,
    ForwardingComponent,
    PolicyComponent,
    RevisionDiffComponent,
    component_revisions,
    component_state,
)
from firewall_compliance.application.controller_reports import (
    controller_report_payload,
    controller_report_records,
)
from firewall_compliance.application.switch_reports import switch_report_payload, switch_report_records
from firewall_compliance.application.switch_topology import build_switch_topology

CSV_COLUMNS = (
    "row_type",
    "component_id",
    "family",
    "operation",
    "state",
    "entity_id",
    "check_id",
    "severity",
    "decision_status",
    "title",
    "source_refs",
    "evidence_json",
    "details_json",
)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)


def _require_result(result: AnalysisResult) -> None:
    if not isinstance(result, AnalysisResult) or not getattr(result, "_snapshot_locked", False):
        raise TypeError("export requires a validated immutable AnalysisResult")
    if result.summary is None or result.state is None:
        raise ValueError("analysis summary/state have not been validated")


def export_analysis_json(result: AnalysisResult, *, indent: int | None = 2) -> str:
    _require_result(result)
    return result.model_dump_json(indent=indent)


def component_family(component: AnalysisComponent) -> str:
    if isinstance(component, AttemptComponent):
        return component.family
    if isinstance(component, (PolicyComponent, RevisionDiffComponent)):
        return component.kind
    return "network"


def _details(component: AnalysisComponent) -> dict[str, Any]:
    if isinstance(component, PolicyComponent):
        return {
            "options": component.options.model_dump(mode="json"),
            "revision_id": str(component.revision.revision_id),
            "report_schema_version": component.result.schema_version,
            "check_catalog_version": component.result.check_catalog_version,
            "parser_version": component.result.parser_version,
            "application_version": component.result.application_version,
            "analyzed_at": component.result.analyzed_at.isoformat(),
            "parse_coverage": component.result.parse_coverage.model_dump(mode="json"),
        }
    if isinstance(component, RevisionDiffComponent):
        return {
            "before_revision_id": str(component.before.revision_id),
            "after_revision_id": str(component.after.revision_id),
            "diff_schema_version": component.result.schema_version,
        }
    if isinstance(component, AttemptComponent):
        return component.model_dump(mode="json", exclude={"revision", "imported"})
    details: dict[str, Any] = {"result": component.result.model_dump(mode="json")}
    query = getattr(component, "query", None)
    if query is not None:
        details["query"] = query.model_dump(mode="json")
    binding = getattr(component, "binding", None)
    if binding is not None:
        details["binding"] = binding.model_dump(mode="json")
    if component.imported is not None:
        details["network_import"] = component.imported.model_dump(mode="json")
    if isinstance(component, ForwardingComponent):
        details.update(
            profile_id=component.profile_id,
            egress_basis=component.egress_basis,
            flow=component.flow.model_dump(mode="json"),
        )
    return details


def _component_sources(component: AnalysisComponent) -> list[str]:
    sources = [
        str(source.source_document_id)
        for revision in component_revisions(component)
        for source in revision.sources
    ]
    if isinstance(component, AttemptComponent):
        sources.extend(str(value) for value in component.source_ids)
    return list(dict.fromkeys(sources))


def _records(result: AnalysisResult) -> Iterator[dict[str, Any]]:
    yield {
        "row_type": "analysis",
        "entity_id": str(result.analysis_id),
        "state": result.state,
        "title": "AnalysisResult",
        "details_json": {
            "schema_version": result.schema_version,
            "application_version": result.application_version,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat(),
            "project_reference": result.project_reference,
            "run_reference": result.run_reference,
            "summary": result.summary.model_dump(mode="json") if result.summary else None,
        },
    }
    for limitation in result.limitations:
        yield {
            "row_type": "limitation",
            "entity_id": limitation.code,
            "title": limitation.message,
            "state": "partial",
        }
    for source in result.sources:
        yield {
            "row_type": "source",
            "entity_id": str(source.source_document_id),
            "title": source.source_name,
            "source_refs": [str(source.source_document_id)],
            "details_json": source.model_dump(mode="json", exclude={"canonical_api_record"}),
        }
    decisions = {(value.component_id, value.finding_id): value for value in result.decisions}
    switch_revisions = [
        revision
        for component in result.components
        for revision in component_revisions(component)
        if revision.parse_result.switch_facts is not None
    ]
    if switch_revisions:
        topology = build_switch_topology(switch_revisions, built_at=result.finished_at)
        for record in switch_report_records({"switch_topology": topology.model_dump(mode="json")}):
            yield {
                "row_type": "switch_topology",
                "family": "network",
                "operation": "configured_topology",
                "entity_id": record["entity_id"],
                "title": record["section"],
                "details_json": record["details"],
            }
    for component in result.components:
        base = {
            "component_id": component.component_id,
            "family": component_family(component),
            "operation": component.operation
            if isinstance(component, AttemptComponent)
            else component.kind,
            "state": component_state(component),
            "source_refs": _component_sources(component),
        }
        yield {**base, "row_type": "component", "details_json": _details(component)}
        for limitation in component.limitations:
            yield {
                **base,
                "row_type": "limitation",
                "entity_id": limitation.code,
                "title": limitation.message,
            }
        if isinstance(component, PolicyComponent):
            report = component.result
            controller = controller_report_payload(component.revision.parse_result)
            if controller is not None:
                for record in controller_report_records(controller):
                    yield {
                        **base,
                        "row_type": "controller_configuration",
                        "entity_id": record["entity_id"],
                        "title": record["section"],
                        "details_json": record["details"],
                    }
            switch = switch_report_payload(component.revision.parse_result)
            if switch is not None:
                for record in switch_report_records(switch):
                    yield {
                        **base,
                        "row_type": "switch_configuration",
                        "entity_id": record["entity_id"],
                        "title": record["section"],
                        "details_json": record["details"],
                    }
            for issue in (*report.parse_warnings, *report.parse_errors):
                yield {
                    **base,
                    "row_type": "limitation",
                    "entity_id": issue.code,
                    "title": issue.message,
                    "details_json": issue.model_dump(mode="json"),
                }
            for unsupported in report.unsupported_constructs:
                yield {
                    **base,
                    "row_type": "limitation",
                    "entity_id": unsupported.construct_type,
                    "title": unsupported.message,
                    "details_json": unsupported.model_dump(mode="json"),
                }
            for check in report.checks:
                state = (
                    "not_executed"
                    if any(value.code == "CHECK_NOT_EXECUTED" for value in check.limitations)
                    else check.status.value
                )
                yield {
                    **base,
                    "row_type": "check",
                    "check_id": check.check_id,
                    "state": state,
                    "details_json": {
                        "check_version": check.check_version,
                        "findings": len(check.findings),
                    },
                }
                for check_limit in check.limitations:
                    yield {
                        **base,
                        "row_type": "limitation",
                        "check_id": check.check_id,
                        "entity_id": check_limit.code,
                        "title": check_limit.message,
                        "details_json": check_limit.model_dump(mode="json"),
                    }
                for finding in check.findings:
                    decision = decisions.get((component.component_id, finding.finding_id))
                    yield {
                        **base,
                        "row_type": "finding",
                        "entity_id": str(finding.finding_id),
                        "check_id": check.check_id,
                        "severity": finding.severity.value,
                        "decision_status": decision.status.value
                        if decision
                        else finding.status.value,
                        "title": finding.title,
                        "evidence_json": finding.evidence.model_dump(mode="json"),
                        "details_json": {
                            "recommendation": finding.recommendation,
                            "description": finding.description,
                            "original_status": finding.status.value,
                        },
                    }
        elif isinstance(component, RevisionDiffComponent):
            for section in (
                "changes",
                "provenance_changes",
                "normalization_changes",
                "completeness_changes",
            ):
                for change in getattr(component.result, section):
                    yield {
                        **base,
                        "row_type": "change",
                        "entity_id": change.entity_id,
                        "title": change.evidence.summary,
                        "evidence_json": change.evidence.model_dump(mode="json"),
                        "details_json": {
                            "section": section,
                            "change": change.model_dump(mode="json"),
                        },
                    }
            for diff_limit in component.result.limitations:
                yield {**base, "row_type": "limitation", "title": diff_limit}
        elif isinstance(component, AttemptComponent):
            yield {
                **base,
                "row_type": "limitation",
                "entity_id": component.diagnostic.code,
                "title": component.diagnostic.message,
            }
        else:
            for reason in getattr(component.result, "reasons", ()):
                yield {
                    **base,
                    "row_type": "limitation",
                    "entity_id": reason.code,
                    "title": reason.message,
                    "details_json": reason.model_dump(mode="json"),
                }
    for decision in result.decisions:
        yield {
            "row_type": "decision",
            "component_id": decision.component_id,
            "family": "policy",
            "entity_id": str(decision.finding_id),
            "decision_status": decision.status.value,
            "title": decision.comment,
            "details_json": decision.model_dump(mode="json"),
        }


def _safe_cell(value: str) -> str:
    if value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r")):
        return "'" + value
    return value


def export_analysis_csv(result: AnalysisResult) -> str:
    _require_result(result)
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS, lineterminator="\r\n")
    writer.writeheader()
    for record in _records(result):
        writer.writerow(
            {
                key: _safe_cell(
                    _json(value)
                    if isinstance(value, (dict, list, tuple))
                    else str(value)
                    if value is not None
                    else ""
                )
                for key, value in record.items()
            }
        )
    return stream.getvalue()


def export_analysis_html(result: AnalysisResult) -> str:
    _require_result(result)
    escape = html.escape
    parts = [
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">',
        "<title>AnalysisResult</title><style>"
        "body{font:15px sans-serif;max-width:1200px;margin:2em auto;}",
        "table{border-collapse:collapse;width:100%;}"
        "td,th{border:1px solid #aaa;padding:.4em;text-align:left;}",
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;}"
        "section{margin:2em 0;}</style></head><body>",
        "<h1>Общий результат анализа</h1>",
        "<p>Это результаты заданных проверок и локальных сетевых этапов; "
        "полнота операции не означает безопасность или доказанную достижимость.</p>",
        f"<p>ID: {result.analysis_id}; схема: {escape(result.schema_version)}; "
        f"приложение: {escape(result.application_version)}; "
        f"состояние: {escape(str(result.state))}</p>",
        f"<p>{escape(result.started_at.isoformat())} — "
        f"{escape(result.finished_at.isoformat())}</p>",
    ]
    current_component: str | None = None
    for record in _records(result):
        row_type = record["row_type"]
        if row_type == "source":
            continue
        component_id = record.get("component_id")
        if row_type == "component":
            if current_component is not None:
                parts.append("</section>")
            current_component = component_id
            parts.append(
                f"<section><h2>{escape(str(component_id))} · "
                f"{escape(record['family'])} / {escape(record['operation'])}</h2>"
            )
        title = record.get("title", "")
        parts.append(
            f"<h3>{escape(row_type)} {escape(record.get('check_id', ''))} {escape(str(title))}</h3>"
        )
        text = {key: value for key, value in record.items() if key not in {"title", "row_type"}}
        parts.append(f"<pre>{escape(_json(text))}</pre>")
    if current_component is not None:
        parts.append("</section>")
    parts.append(
        "<h2>Источники и основание хеша</h2><table><tr>"
        "<th>ID</th><th>Источник</th><th>SHA-256</th><th>Основание</th>"
        "<th>Получение и наблюдение</th></tr>"
    )
    for source in result.sources:
        parts.append(
            f'<tr id="source-{source.source_document_id}"><td>{source.source_document_id}</td>'
            f"<td>{escape(source.source_name)}</td><td>{escape(source.content_sha256)}</td>"
            f"<td>{escape(source.hash_basis)}</td><td><pre>"
            + escape(
                _json(
                    source.model_dump(
                        mode="json",
                        exclude={
                            "source_document_id",
                            "source_name",
                            "content_sha256",
                            "hash_basis",
                            "canonical_api_record",
                        },
                    )
                )
            )
            + "</pre></td></tr>"
        )
    parts.append("</table></body></html>")
    return "".join(parts)
