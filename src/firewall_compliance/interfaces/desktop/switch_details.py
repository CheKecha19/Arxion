"""Представление конфигурационных фактов отдельно от разрешений firewall."""

from __future__ import annotations

import html
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QGraphicsScene,
    QGraphicsView,
    QHeaderView,
    QLabel,
    QSplitter,
    QTableView,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.application.switch_topology import build_switch_topology_from_items
from firewall_compliance.interfaces.desktop.qt_models import RowsModel


PURPOSE_LABELS = {
    "transit": "Транзит",
    "management": "Управление",
    "unbound": "Без привязки",
    "unknown": "Назначение неизвестно",
}
_CONFIGURED_PROFILE_LABELS = {
    "hpe-flexfabric-5944-5945-r6622": "HPE FlexFabric 5944/5945 · Release 6622",
}


def rule_category(rule: Mapping[str, Any]) -> str:
    """Не восстанавливать назначение старых данных по имени правила."""
    purpose = rule.get("policy_purpose")
    if purpose in PURPOSE_LABELS:
        return str(purpose)
    if str(rule.get("policy_id") or "").startswith("management:"):
        return "management"
    if rule.get("policy_semantics") == "first_match" and rule.get("policy_direction"):
        return "transit"
    return "unknown"


def _items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _text(value: Any) -> str:
    if value is None:
        return "Не определено"
    if isinstance(value, bool):
        return "Да" if value else "Нет"
    if isinstance(value, Mapping):
        return "; ".join(f"{key}: {_text(part)}" for key, part in value.items())
    if isinstance(value, (list, tuple)):
        return ", ".join(_text(part) for part in value) or "—"
    return str(value)


def _bindings_by_acl(bindings: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for binding in bindings:
        if isinstance(identifier := binding.get("acl_id"), str):
            result[identifier].append(binding)
    return result


def _acl_order(acl: Mapping[str, Any]) -> str | None:
    order = acl.get("match_order")
    if order == "config":
        return "По возрастанию номера ACE (config)"
    if order == "auto":
        return "Автоматический порядок (auto)"
    return None


def _binding_scope(binding: Mapping[str, Any]) -> str:
    if binding.get("configured_profile") in _CONFIGURED_PROFILE_LABELS:
        subject = _text(binding.get("subject"))
        vlan = subject.removeprefix("interface:vlan:")
        interface = f"VLAN {vlan}" if vlan.isdecimal() else subject
        parts = [interface, "входящий IPv4 при маршрутизации"]
        if vrf := binding.get("vrf"):
            parts.append(f"VRF {vrf}")
        return " · ".join(parts)
    return " · ".join(_text(binding.get(field)) for field in ("subject", "service", "vrf", "direction"))


def _binding_semantics(binding: Mapping[str, Any]) -> str:
    profile = _CONFIGURED_PROFILE_LABELS.get(binding.get("configured_profile"))
    implicit = "Неявное действие: " + _text(binding.get("implicit_action"))
    if profile is not None:
        if binding.get("implicit_action") == "unknown":
            implicit = "Действие без совпадения неизвестно"
        return f"{profile} · решение по конфигурации · {implicit}"
    return implicit


def source_anchor(value: Mapping[str, Any]) -> str:
    """Показать позицию без чтения исходного файла или секретной команды."""
    locations = _items(value.get("source_locations", []))
    single = value.get("source_location")
    if isinstance(single, Mapping):
        locations.append(dict(single))
    for provenance in _items(value.get("provenance", [])):
        locations.extend(_items(provenance.get("source_locations", [])))
    return "; ".join(
        f"{location.get('source_name', 'Источник')}:{location.get('line_start', '?')}"
        + (f"–{location['line_end']}" if location.get("line_end") else "")
        for location in locations
    ) or "Позиция не сохранена"


def safe_switch_source(text: str) -> str:
    """Скрыть credentials при переходе к management binding в исходнике."""
    lines = []
    for line in text.splitlines():
        line = re.sub(r"(?i)(\bcommunity\b).*", r"\1 [скрыто]", line)
        line = re.sub(
            r"(?i)(\b(?:securityname|password|key|ciphertext|cipher|hash|pre-share|pre-shared-key)\b).*",
            r"\1 [скрыто]", line,
        )
        lines.append(line)
    return "\n".join(lines)


def switch_summary(parsed: Mapping[str, Any]) -> str:
    """Раздельные счётчики исходных ACE и применений политик."""
    policies = parsed.get("switch_policies")
    if not isinstance(policies, Mapping):
        counts = Counter(rule_category(rule) for rule in _items(parsed.get("rules", [])))
        return "; ".join(f"{PURPOSE_LABELS[key]}: {counts[key]}" for key in PURPOSE_LABELS)
    declarations = _items(policies.get("declarations", []))
    bindings = _items(policies.get("bindings", []))
    bound = {binding.get("acl_id") for binding in bindings}
    entries = [entry for acl in declarations for entry in _items(acl.get("entries", []))]
    return (
        f"ACL: {len(declarations)}; явных ACE: {len(entries)}; "
        f"привязок: {len(bindings)}; "
        f"authorized managers: {len(_items(policies.get('managers', [])))}; "
        f"применений транзитных: {sum(binding.get('purpose') == 'transit' for binding in bindings)}; "
        f"управляющих: {sum(binding.get('purpose') == 'management' for binding in bindings)}; "
        f"без привязки: {sum(acl.get('acl_id') not in bound for acl in declarations)}; "
        f"неизвестных применений: {sum(binding.get('purpose') == 'unknown' for binding in bindings)}; "
        f"ошибочных ACE: {sum(not entry.get('valid', False) for entry in entries)}; "
        f"ошибочных authorized managers: {sum(not manager.get('valid', False) for manager in _items(policies.get('managers', [])))}"
    )


def acl_rule_html(parsed: Mapping[str, Any], rule: Mapping[str, Any]) -> str:
    """Состав исходной ACE и все её применения без SNMP community секретов."""
    policy = parsed.get("switch_policies")
    parts = [f"<p>Назначение: {html.escape(PURPOSE_LABELS[rule_category(rule)])}</p>"]
    if not isinstance(policy, Mapping):
        return "".join(parts)
    bindings_by_acl = _bindings_by_acl(_items(policy.get("bindings", [])))
    for acl in _items(policy.get("declarations", [])):
        entries = [
            entry for entry in _items(acl.get("entries", []))
            if rule.get("rule_id") in entry.get("rule_ids", [])
        ]
        if not entries:
            continue
        parts.append(f"<h4>ACL {html.escape(str(acl.get('name', acl.get('acl_id', ''))))}</h4>")
        if order := _acl_order(acl):
            parts.append(f"<p>Порядок ACE · {html.escape(order)}</p>")
        for entry in entries:
            parts.append(
                f"<p>Исходная ACE: {html.escape(source_anchor(entry))}; "
                f"корректность: {_text(entry.get('valid'))}</p>"
            )
        for binding in bindings_by_acl.get(acl.get("acl_id"), ()):
            description = f"{_text(binding.get('purpose'))} · {_binding_scope(binding)}"
            if binding.get("configured_profile") in _CONFIGURED_PROFILE_LABELS:
                description += f" · {_binding_semantics(binding)}"
            parts.append(f"<p>Применение: {html.escape(description)}<br>{html.escape(source_anchor(binding))}</p>")
    return "".join(parts)


def management_matrix(
    facts: Mapping[str, Any], policies: Mapping[str, Any]
) -> list[tuple[Any, ...]]:
    """Сопоставить только явно заданные сервисы и область их ограничений."""
    rows: list[tuple[Any, ...]] = []
    bindings = _items(policies.get("bindings", []))
    declarations = {
        acl.get("acl_id"): acl for acl in _items(policies.get("declarations", []))
    }
    for service in _items(facts.get("management", [])):
        if service.get("kind") != "service":
            continue
        name, vrf = service.get("service"), service.get("vrf")
        matched = [
            binding for binding in bindings
            if binding.get("purpose") == "management"
            and (binding.get("service") in {name, "control-plane", "all"}
                 or binding.get("subject") == "control-plane")
            and (binding.get("vrf") == vrf or (
                binding.get("vrf") is None and binding.get("service") == name
            ))
        ]
        if not matched:
            rows.append((name, _text(vrf), _text(service.get("enabled")),
                         "Не определены", "Привязка не обнаружена в файле",
                         "Доступность неизвестна", source_anchor(service)))
        for binding in matched:
            declaration = declarations.get(binding.get("acl_id"), {})
            entries = _items(declaration.get("entries", []))
            sources = "; ".join(
                _text(entry.get("raw_source"))
                for entry in entries if entry.get("action") in {"permit", "allow"}
            )
            rows.append((name, _text(vrf), _text(service.get("enabled")), sources,
                         _text(declaration.get("name")) + "; неявное действие: "
                         + _text(binding.get("implicit_action")),
                         "Конфигурация; не аутентификация" if entries and all(
                             entry.get("valid") for entry in entries
                         ) else "Условия частично неизвестны",
                         source_anchor(binding)))
    for manager in _items(policies.get("managers", [])):
        rows.append((manager.get("method"), "VRF не задан", "Не установлено этой записью",
                     _text(manager.get("source_cidr") or manager.get("source_raw")),
                     "authorized manager / " + _text(manager.get("privilege")),
                     "Конфигурация; не аутентификация" if manager.get("valid")
                     else "Некорректная или неподдержанная запись; разрешение не доказано",
                     source_anchor(manager)))
    return rows


class SwitchDetailsPanel(QTabWidget):
    """Карточка устройства с конфигурационными фактами и их происхождением."""

    source_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tables: dict[str, RowsModel] = {}
        self.overview = QTextBrowser()
        self.addTab(self.overview, "Сводка и полнота")
        for key, title, headers in (
            ("interfaces", "Интерфейсы", ("Интерфейс", "Режим / VRF", "Адреса", "VLAN", "Агрегат", "Адм. состояние", "Описание", "Источник")),
            ("vlans", "VLAN", ("VLAN", "Имя / описание", "Tagged", "Untagged", "Источник")),
            ("aggregates", "Агрегаты", ("Агрегат", "Участники", "LACP", "Описание", "Источник")),
            ("stack", "Стек", ("Участник", "Тип", "Приоритет", "Межсоединения", "Источник")),
            ("routes", "Маршруты", ("Префикс", "Next hop", "VRF", "Тип", "Источник")),
            ("management", "Управление", ("Сервис / факт", "VRF / область", "Значение", "Источник")),
            ("matrix", "Матрица управления", ("Сервис", "VRF", "Включён", "Источники", "Ограничение", "Достоверность", "Источник")),
            ("features", "Протоколы", ("Функция", "Область", "Включена", "Параметры", "Источник")),
            ("policies", "ACL и применения", ("Категория", "ACL / запись", "Состав / область", "Семантика", "Источник")),
            ("issues", "Диагностика", ("Код / область", "Сообщение", "Источник")),
        ):
            table = QTableView()
            model = RowsModel(headers)
            table.setModel(model)
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setWordWrap(True)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            table.horizontalHeader().setStretchLastSection(True)
            table.setSortingEnabled(False)
            table.setAccessibleName(title)
            self._tables[key] = model
            self.addTab(table, title)
        self.source_view = QTextBrowser()
        self.source_view.setOpenLinks(False)
        self.source_view.anchorClicked.connect(self._source_clicked)
        self.addTab(self.source_view, "Строки источника")
        self._locations: list[dict[str, Any]] = []

    def _source_clicked(self, url: Any) -> None:
        value = str(url.toString())
        if not value.startswith("source:"):
            return
        index = value.removeprefix("source:")
        if index.isdigit() and int(index) < len(self._locations):
            self.source_requested.emit(self._locations[int(index)])

    def show_source(self, text: str) -> None:
        """Показать только проверенный и обезличенный фрагмент."""
        self.source_view.append("<pre>" + html.escape(text) + "</pre>")
        self.setCurrentWidget(self.source_view)

    def set_item(self, item: Mapping[str, Any]) -> None:
        """Показать сохранённую ревизию без перечитывания конфигурации."""
        parsed = item.get("parse_result") or {}
        facts = parsed.get("switch_facts") or {}
        policies = parsed.get("switch_policies") or {}
        configuration = parsed.get("configuration") or {}
        declarations = _items(policies.get("declarations", []))
        bindings = _items(policies.get("bindings", []))
        managers = _items(policies.get("managers", []))
        bindings_by_acl = _bindings_by_acl(bindings)
        declarations_by_id: dict[str, dict[str, Any]] = {}
        for acl in declarations:
            if isinstance(identifier := acl.get("acl_id"), str):
                declarations_by_id.setdefault(identifier, acl)
        self._locations = []
        source_links = []
        seen_locations: set[frozenset[tuple[str, Any]]] = set()
        source_values = [
            value
            for group in ("interfaces", "vlans", "aggregates", "stack", "routes", "management", "features", "hardware")
            for value in _items(facts.get(group, []))
        ]
        source_values.extend(bindings)
        source_values.extend(managers)
        for acl in declarations:
            source_values.append(acl)
            source_values.extend(_items(acl.get("entries", [])))
        for value in source_values:
            for location in _items(value.get("source_locations", [])):
                key = frozenset(location.items())
                if key in seen_locations:
                    continue
                seen_locations.add(key)
                index = len(self._locations)
                self._locations.append(location)
                source_links.append(f"<p><a href='source:{index}'>{html.escape(source_anchor({'source_locations': [location]}))}</a></p>")
        self.source_view.setHtml("<p>Фрагменты доступны при подключённом исходнике с совпадающим SHA-256; секретные параметры скрываются.</p>" + "".join(source_links))
        overview = [
            ("Устройство", facts.get("hostname") or configuration.get("device_id")),
            ("Платформа", facts.get("platform") or configuration.get("platform")),
            ("Версия ОС", facts.get("os_version")),
            ("Аппаратные признаки", facts.get("hardware")),
            ("Предполагаемая роль", facts.get("role_hint")),
            ("Захват", facts.get("captured_at") or configuration.get("captured_at")),
            ("Импорт", configuration.get("imported_at")),
            ("SHA-256", facts.get("content_sha256") or configuration.get("content_sha256")),
            ("Заявленная полнота источника", facts.get("configuration_complete")),
            ("Основания определения", policies.get("detection_reasons")),
            ("Политики", switch_summary(parsed)),
        ]
        transit_note = ""
        if policies and not any(binding.get("purpose") == "transit" for binding in bindings):
            if configuration.get("platform") == "comware" and any(binding.get("purpose") == "unknown" for binding in bindings):
                transit_note = "<p>Обнаружены фильтры с неподтверждённой привязкой. Основания приведены в диагностике.</p>"
            else:
                transit_note = "<p>Транзитные ACL в представленном файле не обнаружены.</p>"
        self.overview.setHtml(
            "<h3>Конфигурационные сведения</h3>"
            + "".join(f"<p><b>{html.escape(label)}:</b> {html.escape(_text(value))}</p>" for label, value in overview)
            + "<p>Настройки не подтверждают состояние каналов, установленную таблицу маршрутизации или сквозную доступность. "
            "Отсутствующие в старых ревизиях сведения не восстановлены.</p>"
            + transit_note
            + "<h4>Охват областей</h4>"
            + "".join(f"<p>{html.escape(_text(area))}</p>" for area in _items(facts.get("coverage", [])))
            + (
                "<p>ACL и привязки: ограниченный разбор объявленных конструкций; "
                "корректность каждой ACE и неподдержанные применения показаны отдельно. "
                "Число извлечённых правил не означает полноту конфигурации.</p>"
                if policies else "<p>ACL и привязки: сведения этого формата не сохранены.</p>"
            )
        )
        self._tables["interfaces"].replace([
            (v.get("name"), f"{_text(v.get('mode'))} / {_text(v.get('vrf'))}", _text(v.get("addresses")) + " · " + _text(v.get("address_method")),
             "access " + _text(v.get("access_vlan")) + "; native " + _text(v.get("native_vlan")) + "; allowed " + _text(v.get("allowed_vlans")),
             _text(v.get("aggregate")), _text(v.get("admin_state")), _text(v.get("description")), source_anchor(v)) for v in _items(facts.get("interfaces", []))
        ])
        self._tables["vlans"].replace([(v.get("vlan_id"), _text(v.get("name") or v.get("description")), _text(v.get("tagged_interfaces")), _text(v.get("untagged_interfaces")), source_anchor(v)) for v in _items(facts.get("vlans", []))])
        self._tables["aggregates"].replace([(_text(v.get("name")), _text(v.get("members")), _text(v.get("lacp")), _text(v.get("description")), source_anchor(v)) for v in _items(facts.get("aggregates", []))])
        self._tables["stack"].replace([(_text(v.get("member")), _text(v.get("hardware_type")), _text(v.get("priority")), _text(v.get("links")), source_anchor(v)) for v in _items(facts.get("stack", []))])
        self._tables["routes"].replace([(_text(v.get("prefix") or v.get("raw_prefix")), _text(v.get("next_hop") or v.get("raw_next_hop")), _text(v.get("vrf")), _text(v.get("kind")) + " · " + _text(v.get("status")), source_anchor(v)) for v in _items(facts.get("routes", []))])
        management_rows = [(_text(v.get("service") or v.get("kind")), _text(v.get("vrf") or v.get("scope")), _text(v.get("value") or v.get("address") or v.get("raw_address")) + "; включён: " + _text(v.get("enabled")) + "; " + _text(v.get("status")), source_anchor(v)) for v in _items(facts.get("management", []))]
        for binding in bindings:
            if binding.get("purpose") == "management":
                declaration = declarations_by_id.get(binding.get("acl_id"), {})
                sources = [entry.get("raw_source") for entry in _items(declaration.get("entries", []))]
                management_rows.append((_text(binding.get("service") or binding.get("subject")), _text(binding.get("vrf")), "ACL " + _text(declaration.get("name")) + "; источники: " + _text(sources), source_anchor(binding)))
        management_rows.extend((_text(v.get("method")), "authorized manager", _text(v.get("source_cidr") or v.get("source_raw")) + "; " + _text(v.get("privilege")), source_anchor(v)) for v in managers)
        self._tables["management"].replace(management_rows)
        self._tables["matrix"].replace(management_matrix(facts, policies))
        self._tables["features"].replace([
            (value.get("name"), value.get("scope"), _text(value.get("enabled")),
             _text(value.get("value")), source_anchor(value))
            for value in _items(facts.get("features", []))
        ])
        policy_rows: list[tuple[Any, ...]] = []
        for acl in declarations:
            entries = _items(acl.get("entries", []))
            policy_rows.append((
                "Объявление", acl.get("name"), f"Явных ACE: {len(entries)}",
                _acl_order(acl) or "—", source_anchor(acl),
            ))
            for entry in entries:
                policy_rows.append(("ACE", entry.get("sequence"), " · ".join(_text(entry.get(key)) for key in ("action", "protocol", "raw_source", "raw_destination")), "Корректна" if entry.get("valid") else "Не подтверждена", source_anchor(entry)))
            for binding in bindings_by_acl.get(acl.get("acl_id"), ()):
                policy_rows.append((
                    PURPOSE_LABELS.get(str(binding.get("purpose")), "Неизвестно"), acl.get("name"),
                    _binding_scope(binding), _binding_semantics(binding), source_anchor(binding),
                ))
        if configuration.get("platform") == "comware":
            for binding in bindings:
                acl_identifier = binding.get("acl_id")
                if binding.get("purpose") == "unknown" and acl_identifier not in declarations_by_id:
                    policy_rows.append((
                        PURPOSE_LABELS["unknown"], _text(acl_identifier), _binding_scope(binding),
                        "Объявление ACL отсутствует среди разобранных", source_anchor(binding),
                    ))
        self._tables["policies"].replace(policy_rows)
        issues = [* _items(facts.get("issues", [])), * _items(policies.get("issues", []))]
        self._tables["issues"].replace([(_text(v.get("code") or v.get("area")), _text(v.get("message")), source_anchor(v)) for v in issues])


class SwitchTopologyPanel(QWidget):
    """Локальная структура и предположения по descriptions, отдельно от ACL-карты."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        label = QLabel(
            "Серые связи — настроенная структура. Пунктир — описание порта, сосед не подтверждён. "
            "Зелёные связи имеют отдельное наблюдение или подтверждение оператора, "
            "основание и время указаны в таблице. Одинаковый VLAN на разных устройствах "
            "не доказывает общий L2-домен. Состояние каналов и внешняя фильтрация неизвестны."
        )
        label.setWordWrap(True)
        layout.addWidget(label)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.scene = QGraphicsScene(self)
        self.graph = QGraphicsView(self.scene)
        self.graph.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        splitter.addWidget(self.graph)
        self.table = QTableView()
        self.model = RowsModel(("Устройство / захват", "Объект", "Настройка / кандидат в соседи", "Доказательность", "Источник"))
        self.table.setModel(self.model)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        splitter.addWidget(self.table)
        layout.addWidget(splitter)

    def set_items(self, items: Iterable[Mapping[str, Any]]) -> None:
        """Использовать тот же снимок структуры, который экспортируется в отчёты."""
        topology = build_switch_topology_from_items(tuple(items))
        self.set_topology(topology.model_dump(mode="json"))

    def set_topology(self, topology: Mapping[str, Any]) -> None:
        """Рисовать локальные узлы и связи с явной доказательностью."""
        self.scene.clear()
        rows: list[tuple[Any, ...]] = []
        positions: dict[str, tuple[float, float]] = {}
        nodes = _items(topology.get("nodes", []))
        columns: dict[str, int] = {}
        counters: Counter[str] = Counter()
        for node in nodes:
            kind = str(node.get("kind", "unknown"))
            column = columns.setdefault(kind, len(columns))
            x, y = float(column * 270), float(counters[kind] * 85)
            counters[kind] += 1
            positions[str(node.get("node_id"))] = (x, y)
        for link in _items(topology.get("links", [])):
            left = positions.get(str(link.get("left")))
            right = positions.get(str(link.get("right")))
            if left is not None and right is not None:
                pen = QPen(QColor("#687b88"))
                if link.get("status") in {"candidate", "inferred", "hypothesis", "unknown"}:
                    pen.setStyle(Qt.PenStyle.DashLine)
                    pen.setColor(QColor("#a98b54"))
                elif link.get("status") in {"observed", "operator_confirmed"}:
                    pen.setColor(QColor("#70a786"))
                edge = self.scene.addLine(
                    left[0] + 95, left[1] + 27, right[0] + 95, right[1] + 27, pen
                )
                edge.setToolTip(
                    _text(link.get("status")) + " / " + _text(link.get("evidence_kind"))
                    + "\n" + source_anchor(link)
                )
            rows.append((
                _text(link.get("provenance")), _text(link.get("kind")),
                _text(link.get("left")) + " → " + _text(link.get("right")),
                _text(link.get("status")) + " / " + _text(link.get("evidence_kind"))
                + "; альтернативы: " + _text(link.get("alternatives"))
                + "; конфликты: " + _text(link.get("conflicts")),
                source_anchor(link) + "; " + _text(link.get("provenance")),
            ))
        for node in nodes:
            position = positions[str(node.get("node_id"))]
            color = QColor("#35566f") if node.get("kind") == "device" else QColor("#334638")
            inferred = node.get("kind") == "neighbor"
            if inferred:
                color = QColor("#5c4b2e")
            kind_label = {
                "device": "Устройство", "stack_member": "Участник стека",
                "interface": "Интерфейс", "aggregate": "Агрегат", "vlan": "VLAN",
                "neighbor": "Предполагаемый сосед", "segment": "Сегмент",
            }.get(str(node.get("kind")), "Объект")
            self._node(*position, kind_label + "\n" + _text(node.get("label")), color)
            rows.append((
                _text(node.get("device_id")) + " / " + _text(node.get("revision_id")),
                _text(node.get("label")), _text(node.get("details")),
                "Предположение по описанию" if inferred
                else "Настроено; рабочее состояние неизвестно",
                source_anchor(node) + "; " + _text(node.get("provenance")),
            ))
        for gap in _items(topology.get("gaps", [])):
            rows.append((
                _text(gap.get("node_id")), _text(gap.get("code")),
                _text(gap.get("message")) + "; следующий источник: "
                + _text(gap.get("next_source")), "Пробел данных", _text(gap.get("provenance")),
            ))
        self.model.replace(rows)
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-20, -20, 20, 20))

    def _node(self, x: float, y: float, text: str, color: QColor) -> None:
        self.scene.addRect(x, y, 190, 55, QPen(QColor("#90a0aa")), QBrush(color))
        label = self.scene.addText(text if len(text) <= 58 else text[:55] + "…")
        label.setToolTip(text)
        label.setDefaultTextColor(QColor("#ffffff"))
        label.setTextWidth(180)
        label.setPos(x + 4, y + 2)

