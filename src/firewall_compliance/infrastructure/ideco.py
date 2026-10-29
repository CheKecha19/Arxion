"""Bounded, verified HTTPS reader for the classic Ideco NGFW v23 API."""

import http.client
import json
import math
import re
import ssl
from contextlib import suppress
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from typing import Any


class IdecoError(Exception):
    """Collection error with no credentials or remote response text."""


_TABLES = ("forward", "input", "dnat", "snat")
_READ_PATHS = frozenset(
    {
        "/system_management/version",
        "/aliases/all",
        "/zones",
        "/firewall/state",
        "/firewall/settings",
        "/firewall/status",
        *(f"/firewall/rules/{table}" for table in _TABLES),
    }
)
_RULE_FIELDS = frozenset(
    {
        "id",
        "parent_id",
        "enabled",
        "logging",
        "protocol",
        "sources",
        "source_ports",
        "incoming_interface",
        "destinations",
        "destination_ports",
        "outgoing_interface",
        "hip_profiles",
        "dpi_profile",
        "dpi_enabled",
        "ips_profile",
        "ips_enabled",
        "timetable",
        "comment",
        "action",
        "change_destination_address",
        "change_destination_port",
        "change_source_address",
    }
)
_OBJECT_FIELDS = frozenset({"id", "type", "title", "comment", "value", "values", "start", "end"})
_VALUE_TYPES = frozenset(
    {
        "ip",
        "ip_range",
        "subnet",
        "domain",
        "port",
        "port_range",
        "address_list",
        "ip_address_list",
        "port_list",
        "time_list",
        "time_range",
        "list_of_iplists",
        "protocol",
        "interface",
        "terminal_server_network",
    }
)


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 100000:
        raise IdecoError("Некорректный или слишком большой список Ideco.")
    if any(not isinstance(row, dict) for row in value):
        raise IdecoError("Некорректный элемент списка Ideco.")
    return value


class IdecoReader:
    """Only session login/logout and an exact allowlist of configuration GETs.

    The reader uses the context exposed by the supplied management endpoint.
    It does not switch contexts or claim an effective/atomic policy snapshot.
    """

    def __init__(
        self,
        host: str,
        *,
        port: int = 8443,
        ca_file: str | None = None,
        timeout: float = 30,
    ) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", host):
            raise ValueError("Укажите имя узла или IPv4 без URL и порта.")
        if not 1 <= port <= 65535 or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ValueError("Недопустимый порт или таймаут Ideco.")
        self._host = host
        self._port = port
        self._timeout = timeout
        self._context = ssl.create_default_context(cafile=ca_file)
        self._cookies: dict[str, str] = {}
        self._total_bytes = 0

    def _request(self, method: str, path: str, body: dict[str, str] | None = None) -> Any:
        if not (
            (method == "GET" and path in _READ_PATHS)
            or (method in {"POST", "DELETE"} and path == "/web/auth/login")
        ):
            raise IdecoError("Метод Ideco запрещён: доступ только для чтения.")
        connection = http.client.HTTPSConnection(
            self._host, self._port, timeout=self._timeout, context=self._context
        )
        try:
            headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
            if self._cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
            encoded = json.dumps(body).encode("utf-8") if body is not None else None
            if encoded is not None:
                headers["Content-Type"] = "application/json"
            connection.request(method, path, encoded, headers)
            response = connection.getresponse()
            # Never follow redirects or forward authentication to another endpoint.
            if response.status != 200:
                raise IdecoError("Ideco отклонил запрос; проверьте адрес, права и контекст API.")
            if response.getheader("Content-Encoding", "identity") != "identity":
                raise IdecoError("Неожиданное кодирование ответа Ideco.")
            data = response.read(32 * 1024 * 1024 + 1)
            self._total_bytes += len(data)
            if len(data) > 32 * 1024 * 1024 or self._total_bytes > 128 * 1024 * 1024:
                raise IdecoError("Ответ Ideco превышает допустимый размер.")
            if method == "POST":
                for key, value in response.getheaders():
                    if key.lower() == "set-cookie":
                        cookie = SimpleCookie()
                        cookie.load(value)
                        for name, morsel in cookie.items():
                            self._cookies[name] = morsel.coded_value
                if not self._cookies:
                    raise IdecoError("Ideco не вернул сессионные cookie.")
            return json.loads(data) if method == "GET" else None
        except IdecoError:
            raise
        except Exception:
            raise IdecoError(
                "Не удалось прочитать Ideco; проверьте связь и сертификат HTTPS."
            ) from None
        finally:
            connection.close()

    def collect(self, login: str, password: str) -> dict[str, Any]:
        if not login or not password:
            raise ValueError("Укажите логин и пароль Ideco.")
        self._cookies.clear()
        self._total_bytes = 0
        try:
            self._request(
                "POST", "/web/auth/login", {"login": login, "password": password, "rest_path": "/"}
            )
            version = self._request("GET", "/system_management/version")
            if (
                not isinstance(version, dict)
                or type(version.get("major")) is not int
                or version["major"] != 23
                or version.get("product") != "UTM"
                or version.get("kind") not in {"STANDARD", "FSTEK", "NGFW-FSTEK"}
                or any(type(version.get(k)) is not int for k in ("minor", "build"))
            ):
                raise IdecoError("Поддерживается классический Ideco NGFW версии 23.")
            tables: dict[str, list[dict[str, Any]]] = {}
            for table in _TABLES:
                tables[table] = []
                for row in _rows(self._request("GET", f"/firewall/rules/{table}")):
                    clean = {key: value for key, value in row.items() if key in _RULE_FIELDS}
                    if set(row) - _RULE_FIELDS:
                        clean["unsupported_fields"] = True
                    tables[table].append(clean)
            objects = []
            for row in _rows(self._request("GET", "/aliases/all")):
                fields = (
                    _OBJECT_FIELDS if row.get("type") in _VALUE_TYPES else {"id", "type", "title"}
                )
                objects.append({key: value for key, value in row.items() if key in fields})
            zones = [
                {
                    key: value
                    for key, value in row.items()
                    if key in {"id", "title", "name", "comment"}
                }
                for row in _rows(self._request("GET", "/zones"))
            ]
            state = self._request("GET", "/firewall/state")
            settings = self._request("GET", "/firewall/settings")
            status = self._request("GET", "/firewall/status")
            if not isinstance(state, dict) or not isinstance(settings, dict):
                raise IdecoError("Некорректные настройки межсетевого экрана Ideco.")
            return {
                "format": "arxion-ideco-v1",
                "version": f"{version['major']}.{version['minor']}.{version['build']}",
                "node": self._host,
                "captured_at": datetime.now(UTC).isoformat(),
                "context_type": "classic",
                "collection_complete": False,
                "warnings": [
                    "Сбор API не является атомарным снимком конфигурации.",
                    "Полнота системных правил, правил Center и контекстов не подтверждена.",
                ],
                "tables": tables,
                "objects": objects,
                "zones": zones,
                "firewall_state": {"enabled": state.get("enabled")},
                "firewall_settings": {
                    key: value
                    for key, value in settings.items()
                    if key in {"automatic_snat_enabled", "log_mode", "log_actions"}
                },
                "firewall_status": [
                    {key: value for key, value in row.items() if key in {"name", "status"}}
                    for row in _rows(status)
                ],
            }
        finally:
            if self._cookies:
                with suppress(IdecoError):
                    self._request("DELETE", "/web/auth/login")
            self._cookies.clear()
