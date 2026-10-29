"""Bounded read-only UserGate XML-RPC collector (6.1.5+ and 7.x)."""

import http.client
import re
import ssl
import xmlrpc.client as rpc
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any, Literal

from defusedxml.xmlrpc import DefusedExpatParser


class UserGateError(Exception):
    """Sanitized collection failure; never includes remote error text or secrets."""


_READ_METHODS = frozenset(
    {
        "v2.core.login",
        "v2.core.logout",
        "v1.firewall.rules.list",
        "v1.traffic.rules.list",
        "v1.netmanager.zones.list",
        "v1.libraries.services.list",
        "v2.nlists.list",
        "v2.nlists.list.list",
    }
)


class _Transport(rpc.Transport):
    def __init__(self, timeout: float, context: ssl.SSLContext | None) -> None:
        super().__init__()
        self.timeout = timeout
        self.context = context

    def make_connection(self, host: Any) -> Any:
        if self.context is not None:
            return http.client.HTTPSConnection(host, timeout=self.timeout, context=self.context)
        return http.client.HTTPConnection(host, timeout=self.timeout)

    def getparser(self) -> Any:
        unmarshaller = rpc.Unmarshaller()
        return DefusedExpatParser(unmarshaller), unmarshaller

    def parse_response(self, response: Any) -> Any:
        # Bound the decoded XML body, including responses without Content-Length.
        parser, unmarshaller = self.getparser()
        size = 0
        while chunk := response.read(65536):
            size += len(chunk)
            if size > 32 * 1024 * 1024:
                raise UserGateError("Ответ UserGate превышает допустимый размер.")
            parser.feed(chunk)
        parser.close()
        return unmarshaller.close()


class UserGateReader:
    """No arbitrary RPC interface and no configuration mutation methods.

    Login/logout only manage an API session. All other allowed calls read data.
    HTTPS verifies certificates; no downgrade or certificate bypass is offered.
    """

    def __init__(
        self,
        host: str,
        *,
        family: Literal["6", "7"],
        transport: Literal["tcp", "https"] = "tcp",
        port: int | None = None,
        ca_file: str | None = None,
        timeout: float = 30,
    ) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", host):
            raise ValueError("Укажите имя узла или IPv4 без URL и порта.")
        if family not in {"6", "7"} or transport not in {"tcp", "https"}:
            raise ValueError("Неизвестный профиль UserGate.")
        if family == "6" and transport != "tcp":
            raise ValueError("Для UserGate 6 используется XML-RPC TCP/HTTP.")
        if timeout <= 0 or timeout > 300 or (port is not None and not 1 <= port <= 65535):
            raise ValueError("Недопустимый порт или таймаут.")
        context = ssl.create_default_context(cafile=ca_file) if transport == "https" else None
        scheme = "https" if context else "http"
        selected_port = port or (4443 if context else 4040)
        self._proxy = rpc.ServerProxy(
            f"{scheme}://{host}:{selected_port}/rpc",
            allow_none=True,
            transport=_Transport(timeout, context),
        )
        self._family = family
        self._https = context is not None

    def _call(self, method: str, *args: Any) -> Any:
        if method not in _READ_METHODS:
            raise UserGateError("RPC-метод запрещён: доступ только для чтения.")
        try:
            return getattr(self._proxy, method)(*args)
        except Exception:
            raise UserGateError(
                "Не удалось прочитать UserGate; проверьте связь и права API."
            ) from None

    def _pages(
        self, method: str, token: str, *prefix: Any, tail: tuple[Any, ...] = ({},)
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        seen: set[str] = set()
        start = 0
        for _ in range(1000):
            result = self._call(method, token, *prefix, start, 500, *tail)
            page = result.get("items") if isinstance(result, dict) else None
            if not isinstance(page, list) or any(not isinstance(row, dict) for row in page):
                raise UserGateError("Некорректный список в ответе UserGate.")
            for row in page:
                if "id" in row:
                    key = str(row["id"])
                    if key in seen:
                        raise UserGateError("Список изменился во время чтения; повторите сбор.")
                    seen.add(key)
            items.extend(page)
            if len(items) > 100000:
                raise UserGateError("Превышен лимит сбора UserGate.")
            if not page:
                return items
            start += len(page)
        raise UserGateError("Превышен лимит сбора UserGate; снимок не сохранён.")

    def collect(self, login: str, password: str) -> dict[str, Any]:
        session = self._call("v2.core.login", login, password, {"origin": "arxion-readonly"})
        if not isinstance(session, dict) or not isinstance(session.get("auth_token"), str):
            raise UserGateError("UserGate не вернул токен сессии.")
        token = session["auth_token"]
        try:
            version = str(session.get("version", ""))
            match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
            numbers = tuple(map(int, match.groups())) if match else ()
            if not numbers or str(numbers[0]) != self._family:
                raise UserGateError("Версия устройства не соответствует выбранному профилю.")
            if numbers[0] == 6 and numbers < (6, 1, 5):
                raise UserGateError("Требуется UserGate 6.1.5 или выше в ветке 6.x.")
            if self._https and numbers < (7, 3, 3):
                raise UserGateError("HTTPS API требует UserGate 7.3.3 или выше.")
            snapshot: dict[str, Any] = {
                "format": "arxion-usergate-v1",
                "version": version,
                "node": str(session.get("node", "UserGate")),
                "captured_at": datetime.now(UTC).isoformat(),
                "collection_complete": False,
                "warnings": ["Сбор API не является атомарным снимком конфигурации."],
            }
            snapshot["firewall_rules"] = self._pages("v1.firewall.rules.list", token)
            snapshot["traffic_rules"] = self._pages("v1.traffic.rules.list", token)
            zones = self._call("v1.netmanager.zones.list", token)
            if not isinstance(zones, list):
                raise UserGateError("Некорректный список зон UserGate.")
            snapshot["zones"] = zones
            snapshot["services"] = self._pages("v1.libraries.services.list", token, tail=({}, []))
            lists = self._pages("v2.nlists.list", token, "network")
            for item in lists:
                query: Any = "" if numbers[0] == 6 and numbers < (6, 1, 8) else {}
                item["content"] = self._pages(
                    "v2.nlists.list.list", token, item["id"], tail=(query, [])
                )
            snapshot["ip_lists"] = lists
            return snapshot
        finally:
            with suppress(UserGateError):
                self._call("v2.core.logout", token)
