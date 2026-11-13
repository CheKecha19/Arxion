"""Разбор направления по известным настройкам коммутатора."""

from collections.abc import Mapping
from ipaddress import IPv4Address, IPv6Address, ip_network
from itertools import chain

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit,
    QPlainTextEdit, QVBoxLayout, QWidget,
)

from firewall_compliance.application.access_context import assigned_session_context
from firewall_compliance.application.access_matrix_v2 import (
    CatalogBindings, MatrixGroupResolver, catalog_bindings_for_policy,
)
from firewall_compliance.application.matrix_policy import matrix_catalog_switch_policy_contexts, matrix_policy_contexts
from firewall_compliance.application.switch_path_candidates import describe_switch_path, parse_switch_path_address
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixRequirement, MatrixRequirementAssessment
from firewall_compliance.domain.matrix_context_inputs import MatrixContextInputs
from firewall_compliance.domain.policy_matching import AddressSet
from firewall_compliance.domain.revision import DeviceRevision


def _path_ip(value: object) -> IPv4Address | IPv6Address | None:
    if isinstance(value, str):
        try:
            return parse_switch_path_address(value)
        except ValueError:
            pass
    return None


def _single_ip(addresses: AddressSet | None) -> IPv4Address | IPv6Address | None:
    if addresses is None or sum(map(len, addresses)) != 1:
        return None
    for address_type, ranges in zip((IPv4Address, IPv6Address), addresses, strict=True):
        if ranges:
            first, last = ranges[0]
            return _path_ip(str(address_type(first))) if first == last else None
    return None


def matrix_path_prefill(
    matrix: AccessMatrix, revision: DeviceRevision, result: MatrixRequirementAssessment, *,
    scope_id: str, bindings: CatalogBindings, context_inputs: MatrixContextInputs | None,
    bindings_by_vrf: Mapping[str, CatalogBindings] | None = None, policy_source_matches: bool = True,
) -> dict[str, str]:
    rows = [
        row for row in chain(matrix.requirements, matrix.boundaries)
        if (row.requirement_id if isinstance(row, MatrixRequirement) else row.boundary_id) == result.requirement_id
    ]
    row = rows[0] if len(rows) == 1 and rows[0].scope_id == scope_id else None
    policy_id = row.policy_id if row is not None and policy_source_matches else None
    catalog_contexts = matrix_catalog_switch_policy_contexts(revision) if policy_id is not None else {}
    contexts = matrix_policy_contexts(revision) if policy_id is not None else {}
    session_policy_vrf = contexts.get(policy_id or "", revision.device.context)
    policy_vrf = catalog_contexts.get(policy_id or "") or session_policy_vrf
    context = result.context_resolution if policy_source_matches else None
    session_ip = None
    prefill: dict[str, str] = {}
    if policy_id is not None and policy_vrf is not None:
        prefill["vrf"] = policy_vrf
    if context is not None and context.status == "resolved" and context.source_cidr is not None and context.session_id:
        vrf = assigned_session_context(context_inputs, result.requirement_id, context.session_id)
        if row is not None and vrf is not None and vrf == session_policy_vrf and vrf == policy_vrf:
            session_ip = _path_ip(str(ip_network(context.source_cidr).network_address))
            if session_ip is not None:
                prefill["vrf"] = vrf
    for evidence in result.evidence if policy_source_matches else ():
        witness = evidence.facts.get("witness")
        if isinstance(witness, Mapping):
            source = _path_ip(witness.get("source_ip"))
            destination = _path_ip(witness.get("destination_ip"))
            if context is not None and (session_ip is None or source != session_ip):
                continue
            if source is not None and destination is not None and source.version == destination.version:
                return {**prefill, "source_ip": str(source), "destination_ip": str(destination), "origin": "policy_sample"}

    if not isinstance(row, MatrixRequirement):
        return prefill
    row_bindings = catalog_bindings_for_policy(bindings, bindings_by_vrf or {}, catalog_contexts, policy_id)
    resolver = MatrixGroupResolver(matrix, revision, row_bindings, lambda: None)
    source = session_ip if row.access_context is not None else _single_ip(resolver.resolve(row.source_group))
    destination = _single_ip(resolver.resolve(row.destination_group))
    if source is not None and destination is not None and source.version != destination.version:
        return {}
    if source is not None:
        prefill["source_ip"] = str(source)
    if destination is not None:
        prefill["destination_ip"] = str(destination)
    if session_ip is not None:
        prefill["origin"] = "session"
    return prefill


class MatrixPathDialog(QDialog):
    def __init__(
        self, revision: DeviceRevision, witness: Mapping[str, object], parent: QWidget,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Настроенный путь между адресами")
        self.resize(650, 470)
        self._revision = revision
        layout = QVBoxLayout(self)
        captured = revision.parse_result.configuration.captured_at.isoformat(timespec="minutes")
        heading = f"{revision.device.hostname or revision.device.device_id} · снимок {captured}"
        origin = witness.get("origin")
        if origin == "policy_sample":
            heading += "\nНачальные адреса взяты из примера трафика в сверке. Можно указать конкретные узлы."
        elif origin == "session":
            heading += "\nНачальный адрес источника взят из подтверждённого сеанса."
        description = QLabel(heading)
        description.setTextFormat(Qt.TextFormat.PlainText)
        description.setWordWrap(True)
        description.setToolTip(str(revision.revision_id))
        layout.addWidget(description)
        form = QFormLayout()
        self._source = QLineEdit(str(_path_ip(witness.get("source_ip")) or ""))
        self._destination = QLineEdit(str(_path_ip(witness.get("destination_ip")) or ""))
        self._vrf = QComboBox()
        self._vrf.addItem("Подобрать по исходному адресу", None)
        facts = revision.parse_result.switch_facts
        if facts is not None:
            names = {item.vrf or "default" for item in (*facts.interfaces, *facts.routes)}
            for name in sorted(names):
                self._vrf.addItem(name, name)
        selected_vrf = witness.get("vrf")
        if isinstance(selected_vrf, str) and (index := self._vrf.findData(selected_vrf)) >= 0:
            self._vrf.setCurrentIndex(index)
        form.addRow("IP источника", self._source)
        form.addRow("IP назначения", self._destination)
        form.addRow("Контекст маршрутизации", self._vrf)
        layout.addLayout(form)
        self._details = QPlainTextEdit()
        self._details.setReadOnly(True)
        self._details.setAccessibleName("Маршрутные кандидаты и источники данных")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        run = buttons.addButton("Разобрать", QDialogButtonBox.ButtonRole.ActionRole)
        run.clicked.connect(self._describe)
        buttons.rejected.connect(self.reject)
        layout.addWidget(self._details, 1)
        layout.addWidget(buttons)
        if self._source.text() and self._destination.text():
            self._describe()

    def _describe(self) -> None:
        try:
            result = describe_switch_path(
                self._revision, self._source.text().strip(), self._destination.text().strip(),
                vrf=self._vrf.currentData(),
            )
        except ValueError:
            self._details.setPlainText("Укажите два конкретных адреса одного семейства IP.")
            return
        lines = [result.reason]
        if result.source_interface:
            lines.append(f"Исходный интерфейс · {result.source_interface}")
        if result.vrf:
            lines.append(f"Контекст · {result.vrf}")
        for candidate in result.routes:
            components = [candidate.prefix, candidate.interface, candidate.next_hop]
            lines.append("Кандидат · " + " → ".join(value for value in components if value))
            if candidate.qualification:
                lines.append(candidate.qualification)
        if result.management_gateways:
            lines.append("Шлюзы управления в снимке · " + ", ".join(
                gateway.next_hop or gateway.raw_next_hop for gateway in result.management_gateways
            ))
        for anchor in result.source_locations:
            reference = anchor.object_path or anchor.object_id
            if anchor.line_start is not None:
                reference = f"строки {anchor.line_start}–{anchor.line_end or anchor.line_start}"
            lines.append(f"{anchor.source_name} · {reference}" if reference else anchor.source_name)
        if result.next_evidence:
            lines.extend(("", result.next_evidence))
        self._details.setPlainText("\n".join(lines))
