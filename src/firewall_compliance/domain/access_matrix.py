"""Versioned access requirements, separate from technical controls and reachability."""

import json
from collections import Counter
from datetime import date
from hashlib import sha256
from ipaddress import ip_network
from typing import Any, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from firewall_compliance.domain.access_context import AccessContextCondition, AccessContextResolution
from firewall_compliance.domain.access_journey import AccessJourney, validate_journeys
from firewall_compliance.domain.controls import ControlModel
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.network import PortRange

MatrixState = Literal[
    "declared_match", "declared_conflict", "insufficient_evidence",
    "unregulated", "requirement_conflict", "not_applicable", "partial_match", "excess_allow",
]


class MatrixMember(ControlModel):
    kind: Literal["network", "object", "group", "logical_network", "resource"]
    value: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_network(self) -> "MatrixMember":
        if self.kind == "network":
            ip_network(self.value, strict=False)
        return self


class MatrixGroup(ControlModel):
    group_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    members: tuple[MatrixMember, ...] = ()


class MatrixCatalogBinding(ControlModel):
    """Состав ссылки каталога, использованный при конкретной сверке."""

    kind: Literal["logical_network", "resource"]
    value: str = Field(min_length=1, max_length=512)
    cidrs: tuple[str, ...] = Field(min_length=1)
    vrf: str | None = Field(default=None, min_length=1)

    @model_serializer(mode="wrap")
    def serialize_vrf(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        payload = handler(self)
        if self.vrf is None:
            payload.pop("vrf", None)
        return payload

    @model_validator(mode="after")
    def validate_prefixes(self) -> "MatrixCatalogBinding":
        for prefix in self.cidrs:
            ip_network(prefix, strict=True)
        return self


class MatrixService(ControlModel):
    protocol: Literal["ip", "tcp", "udp", "icmp"]
    ports: tuple[PortRange, ...] = Field(default=(), max_length=128)
    any_ports: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def validate_ports(self) -> "MatrixService":
        if self.protocol in {"tcp", "udp"}:
            if bool(self.ports) == self.any_ports:
                raise ValueError("specify explicit port ranges or any_ports, exclusively")
        elif self.ports or self.any_ports:
            raise ValueError("ports apply only to TCP/UDP")
        return self


class MatrixZonePair(ControlModel):
    """Явные зоны запроса к выбранной политике межсетевого экрана."""

    source_zone: str = Field(min_length=1, max_length=256)
    destination_zone: str = Field(min_length=1, max_length=256)


class MatrixRequirement(ControlModel):
    requirement_id: str = Field(min_length=1, max_length=128)
    source_group: str = Field(min_length=1, max_length=128)
    destination_group: str = Field(min_length=1, max_length=128)
    service: MatrixService
    requirement: Literal["permit", "allow_optional", "deny", "unregulated"] = "unregulated"
    scope_id: str = Field(min_length=1, max_length=256)
    policy_id: str | None = Field(default=None, min_length=1, max_length=256)
    owner: str | None = Field(default=None, min_length=1, max_length=256)
    review_date: date | None = None
    reason: str | None = Field(default=None, min_length=1, max_length=4096)
    identity: str | None = Field(default=None, min_length=1, max_length=512)
    schedule: str | None = Field(default=None, min_length=1, max_length=512)
    access_context: AccessContextCondition | None = None
    zone_pair: MatrixZonePair | None = None

    @model_serializer(mode="wrap")
    def serialize_context(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload = handler(self)
        if self.access_context is None:
            payload.pop("access_context", None)
        if self.zone_pair is None:
            payload.pop("zone_pair", None)
        return payload


class MatrixRequirementSet(ControlModel):
    """Неизменяемая версия повторно используемого набора строк."""

    set_id: str = Field(min_length=1, max_length=128)
    revision_id: UUID
    version: int = Field(ge=1, strict=True)
    name: str = Field(min_length=1, max_length=256)
    templates: tuple[MatrixRequirement, ...] = Field(min_length=1)

    @staticmethod
    def _identity(set_id: str, version: int, name: str, templates: tuple[MatrixRequirement, ...]) -> UUID:
        payload = json.dumps(
            [set_id, version, name, [row.model_dump(mode="json") for row in templates]],
            sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        )
        return uuid5(NAMESPACE_URL, "arxion:matrix-requirement-set:" + sha256(payload.encode("utf-8")).hexdigest())

    @classmethod
    def create(
        cls, set_id: str, version: int, name: str, templates: tuple[MatrixRequirement, ...],
    ) -> "MatrixRequirementSet":
        return cls(set_id=set_id, revision_id=cls._identity(set_id, version, name, templates),
                   version=version, name=name, templates=templates)

    @model_validator(mode="after")
    def validate_templates(self) -> "MatrixRequirementSet":
        if len({row.requirement_id for row in self.templates}) != len(self.templates):
            raise ValueError("Повторяющиеся ID шаблонов в наборе требований")
        if self.revision_id != self._identity(self.set_id, self.version, self.name, self.templates):
            raise ValueError("Содержимое не соответствует идентификатору версии набора требований")
        return self


class MatrixSetAssignment(ControlModel):
    """Связь групп с точно указанной версией набора."""

    assignment_id: UUID
    set_id: str = Field(min_length=1, max_length=128)
    revision_id: UUID
    axis: Literal["source_group", "destination_group"]
    group_ids: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_group_ids(self) -> "MatrixSetAssignment":
        if any(not key or len(key) > 128 for key in self.group_ids):
            raise ValueError("Некорректный ID группы назначения набора")
        if len(set(self.group_ids)) != len(self.group_ids):
            raise ValueError("Группы назначения набора должны быть уникальны")
        return self

    def row_id(self, template_id: str, group_id: str) -> str:
        payload = json.dumps([str(self.assignment_id), self.axis, template_id, group_id])
        return "set-" + sha256(payload.encode("utf-8")).hexdigest()


class MatrixBoundary(ControlModel):
    """Запрет остатка явно выбранной области после вычета разрешений."""

    boundary_id: str = Field(min_length=1, max_length=128)
    source_group: str = Field(min_length=1, max_length=128)
    destination_group: str = Field(min_length=1, max_length=128)
    service: MatrixService
    scope_id: str = Field(min_length=1, max_length=256)
    policy_id: str | None = Field(default=None, min_length=1, max_length=256)
    allowed_requirement_ids: tuple[str, ...] = ()
    zone_pair: MatrixZonePair | None = None

    @model_serializer(mode="wrap")
    def serialize_zones(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload = handler(self)
        if self.zone_pair is None:
            payload.pop("zone_pair", None)
        return payload


class MatrixBoundaryGroup(ControlModel):
    """Одна закрытая область, проверяемая в нескольких явно заданных точках."""

    group_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    scope_id: str = Field(min_length=1, max_length=256)
    boundary_ids: tuple[str, ...] = Field(min_length=2)
    point_names: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_points(self) -> "MatrixBoundaryGroup":
        identifiers = set(self.boundary_ids)
        if len(identifiers) != len(self.boundary_ids) or any(
            not identifier or len(identifier) > 128 for identifier in identifiers
        ):
            raise ValueError("Укажите разные ID закрытых областей для точек проверки")
        if not self.point_names.keys() <= identifiers or any(
            not name.strip() or len(name) > 256 for name in self.point_names.values()
        ):
            raise ValueError("Подписи должны относиться к перечисленным точкам проверки")
        return self

    @model_serializer(mode="wrap")
    def serialize_points(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload = handler(self)
        if not self.point_names:
            payload.pop("point_names", None)
        return payload


class AccessMatrix(ControlModel):
    schema_version: Literal["1.0.0", "2.0.0"] = "1.0.0"
    matrix_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    default_requirement: Literal["unregulated"] = "unregulated"
    groups: tuple[MatrixGroup, ...] = ()
    requirements: tuple[MatrixRequirement, ...] = ()
    boundaries: tuple[MatrixBoundary, ...] = ()
    boundary_groups: tuple[MatrixBoundaryGroup, ...] = ()
    requirement_sets: tuple[MatrixRequirementSet, ...] = ()
    set_assignments: tuple[MatrixSetAssignment, ...] = ()
    journeys: tuple[AccessJourney, ...] = ()

    @model_validator(mode="after")
    def validate_schema(self) -> "AccessMatrix":
        if self.schema_version == "1.0.0" and (
            self.boundaries
            or self.boundary_groups
            or self.requirement_sets
            or self.set_assignments
            or self.journeys
            or any(
                row.requirement == "allow_optional" or row.access_context is not None or row.zone_pair is not None
                for row in self.requirements
            )
            or any(
                member.kind in {"logical_network", "resource"}
                for group in self.groups
                for member in group.members
            )
        ):
            raise ValueError("Closed boundaries, optional access, sets, journeys, context and zones require matrix v2")
        if self.journeys:
            validate_journeys(self, self.journeys)
        return self

    @model_validator(mode="after")
    def validate_boundary_groups(self) -> "AccessMatrix":
        if not self.boundary_groups:
            return self
        boundaries = {row.boundary_id: row for row in self.boundaries}
        result_ids = Counter(row.requirement_id for row in self.requirements)
        result_ids.update(row.boundary_id for row in self.boundaries)
        identifiers: set[str] = set()
        for group in self.boundary_groups:
            if group.group_id in identifiers or result_ids[group.group_id]:
                raise ValueError(f"ID группы закрытых областей уже используется: {group.group_id}")
            identifiers.add(group.group_id)
            points = []
            for identifier in group.boundary_ids:
                point = boundaries.get(identifier)
                if point is None or result_ids[identifier] != 1:
                    raise ValueError(f"Закрытая область отсутствует или её ID неоднозначен: {identifier}")
                points.append(point)
            first = points[0]
            if any(
                (point.scope_id, point.source_group, point.destination_group, point.service)
                != (group.scope_id, first.source_group, first.destination_group, first.service)
                for point in points
            ):
                raise ValueError(
                    f"Точкам группы {group.group_id} нужны одинаковые область, источник, назначение и сервис"
                )
        return self

    @model_validator(mode="after")
    def validate_set_materialization(self) -> "AccessMatrix":
        revisions = {item.revision_id: item for item in self.requirement_sets}
        version_keys = {(item.set_id, item.version) for item in self.requirement_sets}
        if len(revisions) != len(self.requirement_sets) or len(version_keys) != len(self.requirement_sets):
            raise ValueError("Повторяющиеся версии наборов требований")
        if not self.set_assignments:
            return self
        if len({item.assignment_id for item in self.set_assignments}) != len(self.set_assignments):
            raise ValueError("Повторяющиеся назначения наборов требований")

        rows: dict[str, MatrixRequirement] = {}
        duplicates: set[str] = set()
        for row in self.requirements:
            if row.requirement_id in rows:
                duplicates.add(row.requirement_id)
            rows[row.requirement_id] = row
        for assignment in self.set_assignments:
            revision = revisions.get(assignment.revision_id)
            if revision is None or revision.set_id != assignment.set_id:
                raise ValueError("Версия назначенного набора отсутствует в матрице")
            for template in revision.templates:
                for group_id in assignment.group_ids:
                    identifier = assignment.row_id(template.requirement_id, group_id)
                    row = rows.get(identifier)
                    if row is None or identifier in duplicates:
                        raise ValueError("Матрица содержит неполное назначение набора требований")
                    if getattr(row, assignment.axis) != group_id or any(
                        getattr(row, field) != getattr(template, field)
                        for field in MatrixRequirement.model_fields
                        if field not in ("requirement_id", assignment.axis)
                    ):
                        raise ValueError("Требование не соответствует назначенной версии набора")
        return self

    @model_serializer(mode="wrap")
    def serialize_version(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload = handler(self)
        if self.schema_version == "1.0.0":
            payload.pop("boundaries", None)
        if not self.boundary_groups:
            payload.pop("boundary_groups", None)
        if not self.requirement_sets:
            payload.pop("requirement_sets", None)
        if not self.set_assignments:
            payload.pop("set_assignments", None)
        if not self.journeys:
            payload.pop("journeys", None)
        return payload


class MatrixDiagnostic(ControlModel):
    code: str
    message: str
    group_ids: tuple[str, ...] = ()
    requirement_ids: tuple[str, ...] = ()


class MatrixRequirementAssessment(ControlModel):
    requirement_id: str
    state: MatrixState
    evidence: tuple[Evidence, ...] = ()
    reasons: tuple[str, ...] = ()
    mode: Literal["declared_rules", "local_policy"] | None = None
    coverage_complete: bool | None = None
    attachment_limited: bool = Field(default=False, strict=True)
    context_resolution: AccessContextResolution | None = None

    @model_validator(mode="after")
    def validate_attachment(self) -> "MatrixRequirementAssessment":
        if self.attachment_limited and self.mode != "local_policy":
            raise ValueError("Attachment applicability requires a local policy result")
        return self

    @model_serializer(mode="wrap")
    def serialize_mode(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload = handler(self)
        if self.mode is None:
            payload.pop("mode", None)
        if self.coverage_complete is None:
            payload.pop("coverage_complete", None)
        if not self.attachment_limited:
            payload.pop("attachment_limited", None)
        if self.context_resolution is None:
            payload.pop("context_resolution", None)
        return payload


class MatrixAssessment(ControlModel):
    schema_version: Literal["1.0.0", "2.0.0"] = "1.0.0"
    mode: Literal["declared_rules", "local_policy", "mixed"] = "declared_rules"
    status: Literal["complete", "partial", "cancelled"] = "complete"
    matrix_id: str
    matrix_version: str
    revision_id: UUID
    profile_id: str = Field(min_length=1)
    profile_version: str = Field(min_length=1)
    scope_id: str = Field(min_length=1)
    diagnostics: tuple[MatrixDiagnostic, ...] = ()
    requirements: tuple[MatrixRequirementAssessment, ...] = ()
    limitations: tuple[str, ...] = (
        "Оцениваются заданные условия правил; порядок, NAT, маршрутизация и сквозная доступность не вычисляются.",
        "Отсутствие строки матрицы означает: не регламентировано.",
    )

    @model_validator(mode="after")
    def validate_schema(self) -> "MatrixAssessment":
        if self.schema_version == "1.0.0" and (
            self.mode != "declared_rules"
            or self.status != "complete"
            or any(
                row.mode is not None or row.coverage_complete is not None or row.context_resolution is not None
                or row.attachment_limited
                or row.state in {"partial_match", "excess_allow"}
                for row in self.requirements
            )
        ):
            raise ValueError("Local coverage and partial evaluation require assessment v2")
        return self

    @model_serializer(mode="wrap")
    def serialize_status(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload = handler(self)
        if self.schema_version == "1.0.0" and self.status == "complete":
            payload.pop("status", None)
        return payload
