"""Подготовка строк матрицы из таблицы с табуляцией между столбцами."""

import csv
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from io import StringIO
from typing import Literal

from firewall_compliance.application.access_matrix_v2 import valid_boundary_reference
from firewall_compliance.application.matrix_requirement_sets import MatrixRequirementCondition, matrix_requirement_condition
from firewall_compliance.domain.access_matrix import (
    AccessMatrix, MatrixBoundary, MatrixGroup, MatrixRequirement, MatrixService, MatrixZonePair,
)
from firewall_compliance.domain.network import PortRange

type _Intent = Literal["permit", "allow_optional", "deny", "unregulated", "boundary"]
type _Row = MatrixRequirement | MatrixBoundary

_HEADERS = (
    {"id"}, {"откуда", "источник", "source"}, {"куда", "назначение", "destination"},
    {"сервис", "service"}, {"требование", "intent", "requirement"}, {"политика", "policy"},
    {"исключения", "exceptions"}, {"зона источника", "source zone"},
    {"зона назначения", "destination zone"},
)
_INTENTS: dict[str, _Intent] = {
    "permit": "permit", "доступ необходим": "permit",
    "allow_optional": "allow_optional", "доступ допустим": "allow_optional",
    "deny": "deny", "запретить": "deny",
    "unregulated": "unregulated", "не регламентировано": "unregulated",
    "boundary": "boundary", "закрытая область": "boundary",
}


@dataclass(frozen=True, slots=True)
class MatrixTableImport:
    """Предпросмотр добавлений либо список ошибок всего пакета."""

    requirements: tuple[MatrixRequirement, ...] = ()
    boundaries: tuple[MatrixBoundary, ...] = ()
    existing: int = 0
    errors: tuple[str, ...] = ()


class _Groups:
    def __init__(self, groups: tuple[MatrixGroup, ...]) -> None:
        self.counts = Counter(group.group_id for group in groups)
        self.names: dict[str, set[str]] = defaultdict(set)
        for group in groups:
            self.names[group.name.strip().casefold()].add(group.group_id)

    def resolve(self, value: str, field: str) -> str:
        if self.counts[value] == 1:
            return value
        if self.counts[value] > 1:
            raise ValueError(f"ID группы в поле «{field}» встречается несколько раз.")
        names = self.names.get(value.casefold())
        if names and len(names) == 1:
            identifier = next(iter(names))
            if self.counts[identifier] == 1:
                return identifier
        if names:
            raise ValueError(f"Группа в поле «{field}» неоднозначна. Укажите её точный ID.")
        raise ValueError(f"В поле «{field}» укажите ID или имя существующей группы.")


def _service(text: str) -> MatrixService:
    protocol, separator, ports = text.casefold().partition("/")
    protocol, ports = protocol.strip(), ports.strip()
    if protocol in {"ip", "icmp"} and not separator:
        return MatrixService.model_validate({"protocol": protocol})
    if protocol not in {"tcp", "udp"} or not ports:
        raise ValueError("Укажите сервис, например tcp/443, udp/53, tcp/8000-8100, tcp/*, ip или icmp.")
    if ports == "*":
        return MatrixService.model_validate({"protocol": protocol, "any_ports": True})
    ranges = []
    try:
        for item in ports.split(","):
            start, hyphen, end = item.partition("-")
            ranges.append(PortRange(start=int(start), end=int(end if hyphen else start)))
        return MatrixService.model_validate({"protocol": protocol, "ports": ranges})
    except ValueError:
        raise ValueError("Проверьте порты сервиса. Укажите порт или диапазон от 0 до 65535.") from None


def _parse_row(cells: tuple[str, ...], groups: _Groups, scope_id: str) -> _Row:
    identifier, source, destination, service_text, intent_text, policy, excluded, source_zone, dest_zone = cells
    if not 1 <= len(identifier) <= 128:
        raise ValueError("Укажите ID длиной от 1 до 128 символов.")
    intent = _INTENTS.get(intent_text.casefold())
    if intent is None:
        raise ValueError("Выберите требование permit, allow_optional, deny, unregulated или boundary.")
    source = groups.resolve(source, "Откуда")
    destination = groups.resolve(destination, "Куда")
    service = _service(service_text)
    if bool(source_zone) != bool(dest_zone):
        raise ValueError("Укажите обе зоны политики или оставьте обе ячейки пустыми.")
    if excluded and intent != "boundary":
        raise ValueError("Исключения задаются только для закрытой области.")
    exceptions = tuple(key.strip() for key in excluded.split(",")) if excluded else ()
    if any(not key for key in exceptions) or len(set(exceptions)) != len(exceptions):
        raise ValueError("Перечислите разные ID исключений через запятую без пустых значений.")
    try:
        zones = MatrixZonePair(source_zone=source_zone, destination_zone=dest_zone) if source_zone else None
        if intent == "boundary":
            return MatrixBoundary(
                boundary_id=identifier, source_group=source, destination_group=destination,
                service=service, scope_id=scope_id, policy_id=policy or None, zone_pair=zones,
                allowed_requirement_ids=exceptions,
            )
        return MatrixRequirement(
            requirement_id=identifier, source_group=source, destination_group=destination,
            service=service, requirement=intent, scope_id=scope_id, policy_id=policy or None, zone_pair=zones,
        )
    except ValueError:
        raise ValueError("Проверьте область, ID политики и длину названий зон.") from None


def _matches_existing(row: _Row, existing: _Row) -> bool:
    if isinstance(row, MatrixRequirement) and isinstance(existing, MatrixRequirement):
        metadata = {"owner", "reason", "review_date"}
        return row.model_dump(exclude=metadata) == existing.model_dump(exclude=metadata)
    return row == existing


def _table_rows(text: str) -> Iterator[tuple[int, list[str]]]:
    stream = StringIO(text.removeprefix("\ufeff"), newline="")
    if '"' not in text:
        for number, raw in enumerate(stream, start=1):
            yield number, raw.rstrip("\r\n").split("\t")
        return
    reader = csv.reader(stream, delimiter="\t", strict=True)
    line = 1
    try:
        for fields in reader:
            yield line, fields
            line = reader.line_num + 1
    except csv.Error:
        raise ValueError(f"Строка {line}. Проверьте кавычки и длину ячеек таблицы.") from None


def prepare_matrix_table_import(matrix: AccessMatrix, text: str, scope_id: str) -> MatrixTableImport:
    """Проверить табличные строки и ссылки на исключения без изменения черновика."""
    groups = _Groups(matrix.groups)
    existing_rows: dict[str, list[_Row]] = defaultdict(list)
    for requirement in matrix.requirements:
        existing_rows[requirement.requirement_id].append(requirement)
    for boundary in matrix.boundaries:
        existing_rows[boundary.boundary_id].append(boundary)
    reserved = {group.group_id for group in matrix.boundary_groups}

    parsed: dict[str, tuple[int, _Row]] = {}
    duplicates: dict[str, int] = {}
    errors: list[tuple[int, str]] = []
    first = True
    line = 1
    try:
        for start, fields in _table_rows(text):
            line = start
            cells = tuple(value.strip() for value in fields)
            if not any(cells):
                continue
            is_header = first and cells[0].casefold() == "id"
            first = False
            if not 5 <= len(cells) <= len(_HEADERS):
                errors.append((start, "Нужно от 5 до 9 столбцов, разделённых табуляцией."))
                continue
            if is_header:
                if any(value.casefold() not in names for value, names in zip(cells, _HEADERS)):
                    errors.append((start, "Проверьте названия и порядок столбцов заголовка."))
                continue
            identifier = cells[0]
            if identifier in duplicates:
                errors.append((start, f"ID повторяет строку {duplicates[identifier]}."))
                continue
            duplicates[identifier] = start
            try:
                row = _parse_row(cells + ("",) * (len(_HEADERS) - len(cells)), groups, scope_id)
            except ValueError as error:
                errors.append((start, str(error)))
            else:
                parsed[identifier] = start, row
    except ValueError as error:
        return MatrixTableImport(errors=(str(error),))

    new_rows: dict[str, tuple[int, _Row]] = {}
    skipped = 0
    for identifier, (number, row) in parsed.items():
        current = existing_rows.get(identifier, [])
        if identifier in reserved:
            errors.append((number, "Этот ID уже занят группой закрытых областей."))
        elif not current:
            new_rows[identifier] = number, row
        elif len(current) == 1 and _matches_existing(row, current[0]):
            skipped += 1
        else:
            errors.append((number, "Этот ID уже занят другой строкой черновика."))

    decisions: dict[MatrixRequirementCondition, dict[bool, str]] = defaultdict(dict)
    decision_rows = [(number, row) for number, row in new_rows.values()
                     if isinstance(row, MatrixRequirement) and row.requirement != "unregulated"]
    if decision_rows:
        for row in matrix.requirements:
            if row.scope_id == scope_id and row.requirement != "unregulated":
                decisions[matrix_requirement_condition(row)].setdefault(row.requirement != "deny", row.requirement_id)
    for number, row in decision_rows:
        allows = row.requirement != "deny"
        alternatives = decisions[matrix_requirement_condition(row)]
        if opposite := alternatives.get(not allows):
            errors.append((number, f"Условия совпадают с противоположным требованием {opposite}."))
        alternatives.setdefault(allows, row.requirement_id)

    for number, row in parsed.values():
        if not isinstance(row, MatrixBoundary):
            continue
        for identifier in row.allowed_requirement_ids:
            current = existing_rows.get(identifier, [])
            added = new_rows.get(identifier)
            allowed = current[0] if len(current) == 1 else (added[1] if added else None)
            if not isinstance(allowed, MatrixRequirement) or not valid_boundary_reference(row, allowed):
                errors.append((
                    number, f"Исключение {identifier} должно ссылаться на разрешение этой области, политики и пары зон.",
                ))

    if not parsed and not errors:
        errors.append((line, "Вставьте хотя бы одну строку требований."))
    if errors:
        return MatrixTableImport(errors=tuple(f"Строка {number}. {error}" for number, error in sorted(errors)))
    return MatrixTableImport(
        requirements=tuple(row for _, row in new_rows.values() if isinstance(row, MatrixRequirement)),
        boundaries=tuple(row for _, row in new_rows.values() if isinstance(row, MatrixBoundary)),
        existing=skipped,
    )
