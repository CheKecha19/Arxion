"""Неизменяемая оболочка полного результата сравнения сохранённых запусков."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import Field, JsonValue, model_validator

from firewall_compliance import __version__
from firewall_compliance.domain.controls import ControlModel


class RunComparisonArtifact(ControlModel):
    artifact_type: Literal["firewall-compliance.run-comparison-artifact"] = (
        "firewall-compliance.run-comparison-artifact"
    )
    schema_version: Literal["1.0.0"] = "1.0.0"
    comparison_id: UUID = Field(default_factory=uuid4)
    saved_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    application_version: str = Field(default=__version__, min_length=1)
    project_id: str = Field(min_length=1)
    before_run_id: str = Field(min_length=1)
    after_run_id: str = Field(min_length=1)
    package: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        value = self.package
        if self.saved_at.utcoffset() is None or self.before_run_id == self.after_run_id:
            raise ValueError("Comparison needs distinct runs and a timezone-aware timestamp")
        if (
            value.get("package_type") != "firewall-compliance.run-comparison"
            or value.get("schema_version") != "1.0.0"
            or value.get("project_id") != self.project_id
            or value.get("before_run_id") != self.before_run_id
            or value.get("after_run_id") != self.after_run_id
        ):
            raise ValueError("Comparison package references differ from the envelope")
        selection = value.get("selection")
        if selection is not None and (
            not isinstance(selection, dict) or selection.get("mode") != "full_comparison"
        ):
            raise ValueError("Only a complete comparison can enter history")
        for name in ("devices", "rows", "limitations", "unresolved_before", "unresolved_after"):
            if not isinstance(value.get(name), list):
                raise ValueError("Incomplete comparison package")
        for name in ("profiles", "input_scopes"):
            if not isinstance(value.get(name), dict):
                raise ValueError("Comparison input metadata is missing")
        rows = value.get("rows")
        if not isinstance(rows, list):
            raise ValueError("Comparison rows are missing")
        for name in ("generated_at", "before_created_at", "after_created_at"):
            timestamp = value.get(name)
            if not isinstance(timestamp, str) or datetime.fromisoformat(timestamp).utcoffset() is None:
                raise ValueError("Comparison input timestamps must include a timezone")
        if any(
            not isinstance(row, dict)
            or any(not isinstance(row.get(key), str) for key in ("device", "channel", "change", "entity"))
            or "details" not in row
            for row in rows
        ):
            raise ValueError("Invalid comparison row")
        return self
