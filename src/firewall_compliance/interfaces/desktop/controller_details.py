"""Связанные объекты ArubaOS Controller и объяснимый анализ заданной политики."""

from __future__ import annotations

import html
import json
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

from PySide6.QtCore import QSortFilterProxyModel, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.interfaces.desktop.qt_models import RowsModel


KIND_LABELS = {
    "role": "Роль", "vlan": "VLAN", "vlan_pool": "Именованный VLAN / пул", "ssid_profile": "SSID",
    "virtual_ap": "Виртуальная AP", "ap_group": "Группа AP", "aaa_profile": "AAA",
    "server_group": "Группа серверов", "radius_server": "RADIUS",
    "captive_portal": "Captive portal", "time_range": "Расписание",
    "bandwidth_contract": "Лимит полосы", "derivation_rules": "Назначение роли",
    "acl_session": "Session ACL", "acl_eth": "EtherType ACL", "acl_route": "Route ACL",
    "acl_geolocation": "Geolocation ACL", "address": "Адресный объект IPv4",
    "address6": "Адресный объект IPv6", "service": "Сервис", "nat_pool": "NAT-пул",
    "interface": "Интерфейс", "management": "Управление", "pki": "PKI",
    "vpn_profile": "VPN", "app_rf": "AppRF", "operational": "Операционные сведения",
}

ATTRIBUTE_LABELS = {
    "vlan_id": "Назначенный VLAN", "limits": "Ограничения полосы",
    "reauthentication": "Повторная аутентификация", "flags": "Дополнительные настройки",
    "acl_order_complete": "Порядок привязок ACL подтверждён разбором",
    "members": "Адресные элементы", "protocol": "Протокол", "ports": "Порты",
    "alg": "Обработка прикладного протокола (ALG)", "intervals": "Интервалы",
    "timezone": "Часовой пояс", "rate": "Значение лимита", "unit": "Единица",
}


def _items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (tuple, list)):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _escape(value: Any) -> str:
    return html.escape(str(value if value is not None else "Неизвестно"))


def _anchors(value: Mapping[str, Any]) -> str:
    return "; ".join(
        f"{location.get('source_name', '')}:{location.get('line_start', '?')}"
        for location in _items(value.get("source_locations", []))
    ) or "Позиция не сохранена"


class ControllerDetailsPanel(QTabWidget):
    """Каталог связей, диагностика и запрос к роли без заявления сетевой достижимости."""

    source_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._parsed: ParseResult | None = None
        self._objects: dict[str, dict[str, Any]] = {}
        self._references: list[dict[str, Any]] = []
        self._source_locations: list[dict[str, Any]] = []
        self.overview = QTextBrowser()
        self.addTab(self.overview, "Сводка и ограничения")
        catalog = QWidget()
        layout = QVBoxLayout(catalog)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск объектов: роли, VLAN, SSID, AAA, ACL, адреса и сервисы")
        self.search.setClearButtonEnabled(True)
        layout.addWidget(self.search)
        self.kind = QComboBox()
        self.kind.addItem("Все типы объектов", "")
        layout.addWidget(self.kind)
        self.model = RowsModel(("Тип", "Имя", "Описание", "Состояние", "Источник"))
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAccessibleName("Объекты ArubaOS Controller")
        self.detail = QTextBrowser()
        self.detail.setOpenLinks(False)
        self.detail.anchorClicked.connect(self._navigate_link)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail)
        splitter.setSizes([330, 300])
        layout.addWidget(splitter, 1)
        self.addTab(catalog, "Объекты и связи")
        self.search.textChanged.connect(self.proxy.setFilterFixedString)
        self.kind.currentIndexChanged.connect(self._populate_objects)
        self.table.selectionModel().selectionChanged.connect(self._selected)
        self.analysis_page = QWidget()
        analysis_layout = QVBoxLayout(self.analysis_page)
        self.analyze_button = QPushButton("Проанализировать заданные условия ACL")
        self.analyze_button.clicked.connect(self._analyze)
        analysis_layout.addWidget(self.analyze_button)
        self.analysis_view = QTextBrowser()
        self.analysis_view.setOpenLinks(False)
        self.analysis_view.anchorClicked.connect(self._navigate_link)
        analysis_layout.addWidget(self.analysis_view, 1)
        self.addTab(self.analysis_page, "Анализ политик")
        self._build_query()
        self.complex_view = QTextBrowser()
        self.complex_view.setOpenLinks(False)
        self.complex_view.anchorClicked.connect(self._navigate_link)
        self.addTab(self.complex_view, "NAT / PBR / AppRF")
        operational = QWidget()
        operational_layout = QVBoxLayout(operational)
        load_observation = QPushButton("Открыть вывод show ap active")
        load_observation.clicked.connect(self._open_ap_observation)
        operational_layout.addWidget(load_observation)
        self.operational_view = QTextBrowser()
        self.operational_view.setPlainText(
            "Выберите отдельный текстовый вывод show ap active. Отображается только счётчик AP. "
            "Устройство и время получения вывода следует сверить по исходному файлу."
        )
        operational_layout.addWidget(self.operational_view, 1)
        self.addTab(operational, "Операционные данные")
        self.source_view = QTextBrowser()
        self.addTab(self.source_view, "Строки источника")

    def _open_ap_observation(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Вывод show ap active", "", "Текст (*.txt *.log);;Все файлы (*)")
        if not filename:
            return
        path = Path(filename)
        try:
            with path.open("rb") as source:
                data = source.read(2_000_001)
            if len(data) > 2_000_000:
                raise ValueError("Размер вывода превышает 2 МБ.")
            output = data.decode("utf-8-sig")
            headings = re.findall(r"(?m)^[ \t]*Active AP Table[ \t]*\r?$", output)
            totals = re.findall(r"(?m)^[ \t]*Num APs:[ \t]*(\d{1,9})[ \t]*\r?$", output)
            if len(headings) != 1 or len(totals) != 1:
                raise ValueError("Нужен один вывод с заголовком Active AP Table и одним счётчиком Num APs.")
        except UnicodeError:
            self.operational_view.setPlainText("Ожидается текстовый файл в UTF-8.")
        except OSError:
            self.operational_view.setPlainText("Не удалось прочитать файл с выводом команды.")
        except ValueError as error:
            self.operational_view.setPlainText(str(error))
        else:
            self.operational_view.setPlainText(
                f"Файл: {path.name}\nAP в выводе: {int(totals[0])}\n\n"
                "Снимок из файла. Принадлежность выбранному контроллеру и время съёмки не подтверждены. "
                "Счётчик не влияет на оценку ACL и не сохраняется в ревизии."
            )

    def _build_query(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        note = QLabel(
            "Проверяется заданная политика роли, а не путь пакета или активный сеанс. "
            "Неизвестное предшествующее условие, неполный экспорт и динамические данные "
            "могут оставить решение неизвестным."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        form = QFormLayout()
        self.role = QComboBox()
        form.addRow("Роль", self.role)
        self.query_fields: dict[str, QLineEdit] = {}
        for key, label, placeholder in (
            ("source", "Источник", "IP-адрес источника"),
            ("destination", "Назначение", "IP-адрес назначения"),
            ("protocol", "Протокол", "tcp, udp, icmp, icmpv6, gre, esp или номер"),
            ("port", "Порт назначения", "Необязательно для протоколов без портов"),
            ("source_port", "Порт источника", "Необязательно"),
            ("at_time", "Время", "ISO 8601 с часовым поясом; пусто — неизвестно"),
            ("user_ip", "IP пользователя", "Для операнда user; пусто — неизвестно"),
            ("local_ip", "Локальный IP", "Для операнда localip; пусто — неизвестно"),
            ("user_roles", "Роли адресов", 'JSON: {"192.0.2.1": "role-name"}'),
            ("ap_group", "Группа AP", "Необязательно"),
        ):
            field = QLineEdit()
            field.setPlaceholderText(placeholder)
            field.setAccessibleName(label)
            self.query_fields[key] = field
            form.addRow(label, field)
        self.query_fields["protocol"].setText("tcp")
        layout.addLayout(form)
        button = QPushButton("Оценить политику роли")
        button.clicked.connect(self._evaluate)
        layout.addWidget(button)
        self.query_result = QTextBrowser()
        self.query_result.setOpenLinks(False)
        self.query_result.anchorClicked.connect(self._navigate_link)
        layout.addWidget(self.query_result, 1)
        self.addTab(page, "Запрос к роли")

    def set_item(self, item: Mapping[str, Any]) -> None:
        """Читать сохранённую ревизию, не переинтерпретируя её исходник."""
        parsed = item.get("parse_result") or (item.get("revision") or {}).get("parse_result")
        self._parsed = ParseResult.model_validate(parsed)
        inventory = self._parsed.controller_inventory
        if inventory is None:
            self.overview.setPlainText("В этой ревизии каталог Controller отсутствует.")
            return
        payload = inventory.model_dump(mode="json")
        self._objects = {obj["object_id"]: obj for obj in _items(payload.get("objects"))}
        self._references = _items(payload.get("references"))
        self.kind.blockSignals(True)
        self.kind.clear()
        self.kind.addItem("Все типы объектов", "")
        for kind in sorted({str(obj["kind"]) for obj in self._objects.values()}):
            self.kind.addItem(KIND_LABELS.get(kind, kind), kind)
        self.kind.blockSignals(False)
        self._populate_objects()
        self.role.clear()
        for obj in self._objects.values():
            if obj["kind"] == "role":
                self.role.addItem(str(obj["name"]))
        self.overview.setHtml(
            "<h3>ArubaOS Controller</h3>"
            f"<p>Устройство: {_escape(self._parsed.configuration.device_id)}<br>"
            f"Версия: {_escape(payload.get('declared_version'))}<br>"
            f"Вид экспорта: {_escape(payload.get('configuration_view'))}<br>"
            f"Узел: {_escape(payload.get('node_path'))}<br>"
            f"Заявленная полнота: {_escape(payload.get('configuration_complete'))}<br>"
            f"Получено: {_escape(payload.get('captured_at'))}<br>"
            f"Объектов: {len(self._objects)}; ссылок: {len(self._references)}</p>"
            + self._json_section("Полнота и ограничения", {
                "coverage": payload.get("coverage"), "limitations": payload.get("limitations"),
                "issues": payload.get("issues"),
            })
        )
        special = [obj for obj in self._objects.values() if obj["kind"] in {
            "nat_pool", "acl_route", "app_rf", "operational", "vpn_profile", "pki",
        } or (obj["kind"] == "ace" and (
            obj["attributes"].get("action") in {"src-nat", "dst-nat", "dual-nat", "redirect", "route"}
            or obj["attributes"].get("classification")
        ))]
        self.complex_view.setHtml(
            "<p>Объявления и ссылки не доказывают effective NAT/PBR, DPI-классификацию "
            "или операционное состояние. Неподдержанные условия сохраняют ограничения.</p>"
            + "".join(self._object_link(obj) + self._json_section("Параметры", obj) for obj in special)
        )
        self.analysis_view.setPlainText("Нажмите кнопку анализа для проверки заданных условий ACL.")

    @staticmethod
    def _json_section(title: str, value: Any) -> str:
        text = json.dumps(value, ensure_ascii=False, indent=2, default=str)
        return f"<h4>{_escape(title)}</h4><pre>{_escape(text)}</pre>"

    def _object_link(self, obj: Mapping[str, Any]) -> str:
        identifier = quote(str(obj["object_id"]), safe="")
        return f'<p><a href="object:{identifier}">{_escape(obj["name"])}</a></p>'

    def _populate_objects(self, *_: Any) -> None:
        kind = self.kind.currentData()
        objects = [obj for obj in self._objects.values() if not kind or obj["kind"] == kind]
        self.model.replace([
            (KIND_LABELS.get(str(obj["kind"]), obj["kind"]), obj["name"],
             obj.get("description") or "—", obj.get("state") or "declared", _anchors(obj))
            for obj in objects
        ], objects)

    def _selected(self, *_: Any) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        index = self.proxy.mapToSource(indexes[0])
        if index.isValid() and index.row() < len(self.model.payloads):
            self._show_object(self.model.payloads[index.row()])

    def _show_object(self, obj: Mapping[str, Any]) -> None:
        identifier = obj["object_id"]
        parts = [
            f"<h3>{_escape(obj['name'])}</h3>",
            f"<p>{_escape(KIND_LABELS.get(str(obj['kind']), obj['kind']))}; "
            f"состояние разбора: {_escape(obj.get('state'))}</p>",
            f"<p>{_escape(obj.get('description') or '')}</p>",
        ]
        for key, value in (obj.get("attributes") or {}).items():
            parts.append(self._json_section(ATTRIBUTE_LABELS.get(key, key), value))
        parts.append(self._source_links(obj.get("source_locations")))
        parts.append("<h4>Исходящие и входящие связи</h4>")
        for reference in self._references:
            if reference.get("source_id") != identifier and reference.get("target_id") != identifier:
                continue
            target = self._objects.get(str(reference.get("target_id")))
            origin = self._objects.get(str(reference.get("source_id")))
            parts.append(
                f"<p>{_escape((origin or {}).get('name'))} → "
                f"{_escape(reference.get('relation'))} → {_escape(reference.get('target_name'))}; "
                f"{_escape(reference.get('status'))}; позиция {_escape(reference.get('position'))}</p>"
            )
            neighbor = target if reference.get("source_id") == identifier else origin
            if neighbor:
                parts.append(self._object_link(neighbor))
        self.detail.setHtml("".join(parts))

    def _source_links(self, locations: Any) -> str:
        parts = []
        for location in _items(locations):
            if location not in self._source_locations:
                self._source_locations.append(location)
            index = self._source_locations.index(location)
            label = _anchors({"source_locations": [location]})
            parts.append(f'<p><a href="source:{index}">{_escape(label)}</a></p>')
        return "".join(parts)

    def _navigate_link(self, url: Any) -> None:
        value = str(url.toString())
        if value.startswith("object:"):
            obj = self._objects.get(unquote(value.removeprefix("object:")))
            if obj is not None:
                self.setCurrentIndex(1)
                self.search.clear()
                self.kind.setCurrentIndex(0)
                self._show_object(obj)
        elif value.startswith("source:"):
            index = value.removeprefix("source:")
            if index.isdecimal() and int(index) < len(self._source_locations):
                self.source_requested.emit(self._source_locations[int(index)])

    def show_source(self, text: str) -> None:
        """Получить только проверенный и обезличенный фрагмент от владельца источника."""
        self.source_view.setHtml("<pre>" + _escape(text) + "</pre>")
        self.setCurrentWidget(self.source_view)

    def _analyze(self) -> None:
        if self._parsed is None:
            return
        from firewall_compliance.analysis.controller_policy import analyze_controller

        result = analyze_controller(self._parsed).model_dump(mode="json")
        parts = [self._json_section("Ограничения и роли", {
            "limitations": result.get("limitations"), "roles": result.get("roles"),
        })]
        for finding in _items(result.get("findings")):
            parts.append(self._json_section(str(finding.get("title")), finding))
            parts.append(self._source_links(finding.get("source_locations")))
            policy = str(finding.get("policy_id") or "")
            for obj in self._objects.values():
                if obj["kind"] == "acl_session" and (
                    obj["object_id"] == policy or policy.endswith(":" + str(obj["name"]))
                ):
                    parts.append(self._object_link(obj))
        self.analysis_view.setHtml("".join(parts))

    def _evaluate(self) -> None:
        if self._parsed is None:
            return
        from firewall_compliance.analysis.controller_policy import evaluate_controller_role

        fields = {key: widget.text().strip() for key, widget in self.query_fields.items()}
        try:
            roles = json.loads(fields["user_roles"]) if fields["user_roles"] else None
            if roles is not None and (
                not isinstance(roles, dict)
                or not all(isinstance(key, str) and isinstance(value, str) for key, value in roles.items())
            ):
                raise ValueError("Роли адресов должны быть JSON-объектом IP → имя роли.")
            at_time = datetime.fromisoformat(fields["at_time"]) if fields["at_time"] else None
            if at_time is not None and at_time.tzinfo is None:
                raise ValueError("Время должно содержать часовой пояс.")
            port = int(fields["port"]) if fields["port"] else None
            source_port = int(fields["source_port"]) if fields["source_port"] else None
            if any(value is not None and not 0 <= value <= 65535 for value in (port, source_port)):
                raise ValueError("Порт должен быть от 0 до 65535.")
            result = evaluate_controller_role(
                self._parsed, self.role.currentText(), fields["source"], fields["destination"],
                fields["protocol"], port, source_port=source_port, at_time=at_time,
                user_ip=fields["user_ip"] or None, local_ip=fields["local_ip"] or None,
                user_roles=roles, ap_group=fields["ap_group"] or None,
            ).model_dump(mode="json")
        except (ValueError, TypeError) as error:
            self.query_result.setPlainText(str(error))
            return
        sections = [self._json_section("Решение и трассировка", result)]
        for entry in _items(result.get("trace")):
            sections.append(self._source_links(entry.get("source_locations")))
        self.query_result.setHtml("".join(sections))
