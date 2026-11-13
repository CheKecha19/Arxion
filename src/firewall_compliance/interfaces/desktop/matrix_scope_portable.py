"""Portable grouping for results whose approved matrix declares several checks."""

from __future__ import annotations

import json
from typing import Literal, Self

from pydantic import model_validator

from firewall_compliance.application.matrix_scope_assessment import (
    MatrixScopeAssessment, matrix_scope_checksum, verify_scope_rows,
)
from firewall_compliance.domain.access_matrix import AccessMatrix
from firewall_compliance.domain.controls import ControlModel


class MatrixScopePackage(ControlModel):
    format: Literal["arxion-matrix-scope-v1"] = "arxion-matrix-scope-v1"
    matrix: AccessMatrix
    result: MatrixScopeAssessment

    @model_validator(mode="after")
    def validate_matrix(self) -> Self:
        matrix, result = self.matrix, self.result
        if (
            matrix.matrix_id != result.matrix_id or matrix.version != result.matrix_version
            or matrix_scope_checksum(matrix) != result.matrix_checksum
        ):
            raise ValueError("Матрица в файле не совпадает с версией сохранённой сверки.")
        verify_scope_rows(matrix, result)
        return self


def encode_scope_result(result: MatrixScopeAssessment, matrix: AccessMatrix | None) -> str:
    if matrix is not None and any(group.scope_id == result.scope_id for group in matrix.boundary_groups):
        return MatrixScopePackage(matrix=matrix, result=result).model_dump_json(indent=2)
    return result.model_dump_json(indent=2)


def decode_scope_result(data: bytes) -> tuple[MatrixScopeAssessment, AccessMatrix | None]:
    raw = json.loads(data)
    if isinstance(raw, dict) and raw.get("format") == "arxion-matrix-scope-v1":
        package = MatrixScopePackage.model_validate(raw)
        return package.result, package.matrix
    return MatrixScopeAssessment.model_validate(raw), None
