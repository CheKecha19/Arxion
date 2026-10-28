"""Pure, replayable technical control evidence over a retained analysis bundle."""

import csv
import io
from datetime import datetime
from hashlib import sha256
from html import escape
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import Field, model_validator

from firewall_compliance.application.analysis_result import (
    AnalysisResult,
    AttemptComponent,
    PolicyComponent,
)
from firewall_compliance.domain.controls import (
    CheckControlMapping,
    ControlCatalogue,
    ControlCheckEvidence,
    ControlCoverage,
    ControlDefinition,
    ControlEvaluation,
    ControlModel,
    ControlRequirement,
    OrganizationControlProfile,
)

DISCLAIMER = (
    "Технические свидетельства для выбранных частей внутренних контролей; "
    "не сертификация NIST/CIS и не оценка организационных процедур или сетевой достижимости."
)


def internal_control_catalogue() -> ControlCatalogue:
    """Bounded internal claims, not fabricated mappings to an external standard."""
    entries = (
        ("TECH-BROAD-ALLOW", "Широкие разрешающие условия", "FW-ANY-ANY"),
        ("TECH-POLICY-LOGGING", "Требование журналирования правил", "FW-LOGGING"),
        ("TECH-POLICY-COMMENTS", "Требование комментария правила", "FW-COMMENTS"),
        ("TECH-DANGEROUS-SERVICES", "Запрещённые организацией сервисы", "FW-DANGEROUS-SERVICES"),
        ("TECH-ADMIN-SOURCES", "Административные источники", "FW-ADMIN-UNTRUSTED"),
    )
    limits = (
        "Только нормализованная поддержанная область выбранной проверки.",
        "Не доказывает эффективный путь, отсутствие NAT или безопасность всей конфигурации.",
        "Внутренняя техническая часть; архитектурные и организационные требования не оценены.",
    )
    return ControlCatalogue(
        catalogue_id="arxion-internal-technical",
        version="1.0.0",
        controls=tuple(
            ControlDefinition(
                control_id=identifier,
                title=title,
                statement=f"Оценить вывод {check} в явно выбранном организационном профиле.",
                limitations=limits,
            )
            for identifier, title, check in entries
        ),
        mappings=tuple(
            CheckControlMapping(
                mapping_id=f"internal:{check}",
                control_id=identifier,
                check_id=check,
                check_versions=("1.0.0", "1.1.0"),
                source=(
                    "Arxion internal technical catalogue; REQUIREMENTS_TRACEABILITY.md A-06/S-07"
                ),
                edition="1.0.0",
                source_control_id=identifier,
                rationale="Сохраняет техническое свидетельство и ограничения отдельной проверки.",
                covered_part=f"Только конкретное утверждение {check}, не весь baseline A-06/S-07.",
                limits=limits,
            )
            for identifier, _, check in entries
        ),
    )


def _check_evidence(
    source: AnalysisResult,
    component: PolicyComponent | None,
    requirement: ControlRequirement,
    mapping: CheckControlMapping,
    profile: OrganizationControlProfile,
    assessed_at: datetime,
) -> ControlCheckEvidence:
    if component is None:
        return ControlCheckEvidence(
            mapping_id=mapping.mapping_id,
            check_id=mapping.check_id,
            execution="missing",
            sufficient=False,
            limitations=("POLICY_RESULT_MISSING",),
        )
    check = next(
        (item for item in component.result.checks if item.check_id == mapping.check_id), None
    )
    if check is None:
        return ControlCheckEvidence(
            mapping_id=mapping.mapping_id,
            check_id=mapping.check_id,
            execution="missing",
            sufficient=False,
            limitations=("CHECK_MISSING",),
        )
    limitations = [f"{item.code}: {item.message}" for item in check.limitations]
    if check.check_version not in mapping.check_versions:
        limitations.append("CHECK_VERSION_UNMAPPED")
    options = component.options.model_dump(mode="json")
    for name, expected in requirement.parameters.items():
        if options[name] != expected:
            limitations.append(f"PARAMETER_MISMATCH:{name}")
    if mapping.check_id == "FW-LOGGING" and not component.options.require_logging:
        limitations.append("REQUIRED_LOGGING_DISABLED")
    if mapping.check_id == "FW-COMMENTS" and not component.options.require_comments:
        limitations.append("REQUIRED_COMMENTS_DISABLED")
    limitations.extend(f"{value.code}: {value.message}" for value in component.limitations)
    limitations.extend(f"{value.code}: {value.message}" for value in source.limitations)
    execution: Literal["complete", "partial", "not_applicable", "not_executed", "missing"] = (
        check.status.value
    )
    if any(item.code == "CHECK_NOT_EXECUTED" for item in check.limitations):
        execution = "not_executed"
    finding_ids = tuple(finding.finding_id for finding in check.findings)
    exceptions = tuple(
        value.exception_id
        for value in profile.exceptions
        if value.control_id == requirement.control_id
        and value.component_id == component.component_id
        and value.finding_id in finding_ids
        and value.approved_at <= assessed_at < value.expires_at
    )
    return ControlCheckEvidence(
        mapping_id=mapping.mapping_id,
        check_id=mapping.check_id,
        check_version=check.check_version,
        execution=execution,
        sufficient=execution == "complete" and not limitations,
        finding_ids=finding_ids,
        active_exception_ids=exceptions,
        limitations=tuple(limitations),
    )


def _evaluate(
    source: AnalysisResult,
    profile: OrganizationControlProfile,
    catalogue: ControlCatalogue,
    assessed_at: datetime,
) -> tuple[tuple[ControlEvaluation, ...], ControlCoverage]:
    if assessed_at.utcoffset() is None or assessed_at < source.finished_at:
        raise ValueError("assessment requires timezone and cannot precede source completion")
    definitions = {value.control_id for value in catalogue.controls}
    if any(value.control_id not in definitions for value in profile.requirements):
        raise ValueError("profile references an unknown catalogue control")
    components = {component.component_id: component for component in source.components}
    selected = profile.component_ids
    if selected is None:
        selected = tuple(
            component.component_id
            for component in source.components
            if isinstance(component, PolicyComponent)
            or isinstance(component, AttemptComponent)
            and component.family == "policy"
        )
    scope: tuple[str | None, ...] = selected or (None,)
    if len(scope) * len(profile.requirements) > 10000:
        raise ValueError("assessment exceeds 10000 control/component evaluations")
    if len(scope) * len(catalogue.mappings) > 100000:
        raise ValueError("assessment exceeds 100000 check evaluations")
    findings = {
        (component.component_id, finding.finding_id)
        for component in source.components
        if isinstance(component, PolicyComponent)
        for check in component.result.checks
        for finding in check.findings
    }
    if any(
        value.component_id not in selected or (value.component_id, value.finding_id) not in findings
        for value in profile.exceptions
    ):
        raise ValueError("exception must reference a retained finding within selected scope")
    for exception in profile.exceptions:
        checks = {
            value.check_id
            for value in catalogue.mappings
            if value.control_id == exception.control_id
        }
        exception_component = components[exception.component_id]
        if not isinstance(exception_component, PolicyComponent) or not any(
            check.check_id in checks
            and any(finding.finding_id == exception.finding_id for finding in check.findings)
            for check in exception_component.result.checks
        ):
            raise ValueError("exception finding does not support its selected control mapping")
    evaluations = []
    for requirement in profile.requirements:
        mappings = tuple(
            value for value in catalogue.mappings if value.control_id == requirement.control_id
        )
        for component_id in scope:
            candidate = components.get(component_id) if component_id is not None else None
            component = candidate if isinstance(candidate, PolicyComponent) else None
            if not requirement.applicable:
                evaluations.append(
                    ControlEvaluation(
                        control_id=requirement.control_id,
                        component_id=component_id,
                        revision_id=component.revision.revision_id if component else None,
                        state="not_applicable",
                        limitations=(requirement.justification,),
                    )
                )
                continue
            evidence = tuple(
                _check_evidence(source, component, requirement, value, profile, assessed_at)
                for value in mappings
            )
            reasons = []
            if not evidence:
                reasons.append("NO_TECHNICAL_MAPPING")
            if component is None:
                reasons.append("NO_POLICY_RESULT_IN_SCOPE")
                if isinstance(candidate, AttemptComponent):
                    reasons.append(f"{candidate.state}:{candidate.diagnostic.code}")
            state: Literal[
                "technical_violation", "no_violation_in_examined_scope", "insufficient_evidence"
            ] = "insufficient_evidence"
            # A mismatch/unsupported version is retained evidence, never a profile violation proof.
            applicable_findings = any(
                item.finding_ids
                and "CHECK_VERSION_UNMAPPED" not in item.limitations
                and not any(value.startswith("PARAMETER_MISMATCH:") for value in item.limitations)
                for item in evidence
            )
            if applicable_findings:
                state = "technical_violation"
            elif evidence and all(item.sufficient for item in evidence):
                state = "no_violation_in_examined_scope"
            evaluations.append(
                ControlEvaluation(
                    control_id=requirement.control_id,
                    component_id=component_id,
                    revision_id=component.revision.revision_id if component else None,
                    state=state,
                    evidence=evidence,
                    limitations=tuple(reasons),
                )
            )
    result = tuple(evaluations)
    evidence_rows = [item for row in result for item in row.evidence]
    return result, ControlCoverage(
        evaluations=len(result),
        applicable_evaluations=sum(row.state != "not_applicable" for row in result),
        fully_examined_evaluations=sum(
            bool(row.evidence) and all(item.sufficient for item in row.evidence) for row in result
        ),
        expected_check_evaluations=len(evidence_rows),
        executed_check_evaluations=sum(
            item.execution in {"complete", "partial"} for item in evidence_rows
        ),
        sufficient_check_evaluations=sum(item.sufficient for item in evidence_rows),
        violations=sum(row.state == "technical_violation" for row in result),
        no_violations_in_examined_scope=sum(
            row.state == "no_violation_in_examined_scope" for row in result
        ),
        insufficient_evidence=sum(row.state == "insufficient_evidence" for row in result),
        not_applicable=sum(row.state == "not_applicable" for row in result),
    )


class ControlAssessment(ControlModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    assessment_id: UUID = Field(default_factory=uuid4)
    assessed_at: datetime
    source: AnalysisResult
    profile: OrganizationControlProfile
    catalogue: ControlCatalogue
    disclaimer: str = DISCLAIMER
    evaluations: tuple[ControlEvaluation, ...] | None = None
    coverage: ControlCoverage | None = None

    @model_validator(mode="after")
    def validate_assessment(self) -> Self:
        if self.disclaimer != DISCLAIMER:
            raise ValueError("technical evidence disclaimer cannot be replaced")
        evaluations, coverage = _evaluate(
            self.source, self.profile, self.catalogue, self.assessed_at
        )
        if self.evaluations is not None and self.evaluations != evaluations:
            raise ValueError("control evaluations do not replay from retained evidence/profile")
        if self.coverage is not None and self.coverage != coverage:
            raise ValueError("control coverage does not match actual evaluations")
        object.__setattr__(self, "evaluations", evaluations)
        object.__setattr__(self, "coverage", coverage)
        return self


def assess_controls(
    source: AnalysisResult,
    profile: OrganizationControlProfile,
    catalogue: ControlCatalogue,
    *,
    assessed_at: datetime,
) -> ControlAssessment:
    """Capture exact historical evidence and approvals; no I/O or ambient policy."""
    return ControlAssessment(
        source=source, profile=profile, catalogue=catalogue, assessed_at=assessed_at
    )


def export_control_assessment_json(result: ControlAssessment) -> str:
    return result.model_dump_json(indent=2)


def _formula_safe(value: str) -> str:
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def export_control_assessment_csv(result: ControlAssessment) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(
        (
            "control",
            "component",
            "state",
            "evidence",
            "limitations",
            "disclaimer",
            "analysis_id",
            "assessment_id",
            "assessed_at",
            "profile_id",
            "profile_version",
            "catalogue_id",
            "catalogue_version",
        )
    )
    for row in result.evaluations or ():
        writer.writerow(
            _formula_safe(value)
            for value in (
                row.control_id,
                row.component_id or "",
                row.state,
                "\n".join(item.model_dump_json() for item in row.evidence),
                "\n".join(row.limitations),
                result.disclaimer,
                str(result.source.analysis_id),
                str(result.assessment_id),
                result.assessed_at.isoformat(),
                result.profile.profile_id,
                result.profile.version,
                result.catalogue.catalogue_id,
                result.catalogue.version,
            )
        )
    return buffer.getvalue()


def export_control_assessment_html(result: ControlAssessment) -> str:
    assert result.coverage is not None
    profiles = result.profile.model_dump_json(indent=2)
    mappings = result.catalogue.model_dump_json(indent=2)
    digest = sha256(result.source.model_dump_json().encode("utf-8")).hexdigest()
    rows = "".join(
        "<tr>"
        + "".join(
            "<td><pre>" + escape(value) + "</pre></td>"
            for value in (
                row.control_id,
                row.component_id or "Нет policy-результата",
                row.state,
                row.model_dump_json(indent=2),
            )
        )
        + "</tr>"
        for row in result.evaluations or ()
    )
    return (
        '<!doctype html><html lang="ru"><meta charset="utf-8">'
        "<title>Технические свидетельства для контролей</title>"
        "<style>body{font:15px sans-serif;margin:2em}td,th{border:1px solid #aaa;"
        "padding:.5em;vertical-align:top}pre{white-space:pre-wrap;overflow-wrap:anywhere}"
        "table{border-collapse:collapse;width:100%}</style>"
        f"<h1>Технические свидетельства</h1><p>{escape(result.disclaimer)}</p>"
        f"<p>Analysis: {result.source.analysis_id}; SHA256: {digest}; "
        f"assessment: {result.assessment_id}; {result.assessed_at.isoformat()}</p>"
        f"<h2>Охват</h2><pre>{escape(result.coverage.model_dump_json(indent=2))}</pre>"
        "<table><tr><th>Контроль</th><th>Компонент</th><th>Исход</th><th>Доказательства</th></tr>"
        f"{rows}</table><h2>Точный профиль и исключения</h2><pre>{escape(profiles)}</pre>"
        f"<h2>Каталог и сопоставления</h2><pre>{escape(mappings)}</pre>"
        "<h2>Решения по findings (не изменяют технический вывод)</h2><pre>"
        + escape("\n".join(value.model_dump_json() for value in result.source.decisions))
        + "</pre></html>"
    )
