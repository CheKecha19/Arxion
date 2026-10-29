"""Read-only Cloud.ru VMware Cloud Director collector; no infrastructure mutations."""

from __future__ import annotations

import json
import re
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Event
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

MAX_RESPONSE = 16 * 1024 * 1024
MAX_PAGES = 1000
API_VERSIONS = (
    "36.1",
    "36.2",
    "36.3",
    "37.0",
    "37.1",
    "37.2",
    "37.3",
    "38.0",
    "38.1",
    "39.0",
    "39.1",
)
RESOURCE_TYPES = {"vms": "Виртуальные машины", "edges": "Edge Gateway", "networks": "Сети Org VDC"}
DATA_TYPES = {
    "vm_networks": "Сетевые подключения и IP-адреса ВМ",
    "firewall": "Правила Firewall Edge Gateway (NSX-T)",
    "nat": "Правила NAT Edge Gateway (NSX-T)",
    "routes": "Статические маршруты Edge Gateway (NSX-T)",
}


class CloudError(Exception):
    """Safe user-facing API error, without response bodies or tokens."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


@dataclass(frozen=True)
class VMwareConfig:
    site: str
    tenant: str
    api_version: str = "auto"
    timeout: int = 30

    def __post_init__(self) -> None:
        parsed = urlsplit(self.site.strip())
        tenant = self.tenant.strip()
        tenant_path = re.fullmatch(r"/tenant/([^/]+)/?", parsed.path)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or not parsed.hostname.endswith(".cloud.ru")
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or (parsed.path not in ("", "/") and not tenant_path)
            or parsed.port not in (None, 443)
        ):
            raise ValueError(
                "Укажите HTTPS-адрес площадки Cloud.ru или ссылку входа https://<площадка>/tenant/<имя>/."
            )
        if tenant_path:
            linked_tenant = unquote(tenant_path[1])
            if tenant and tenant != linked_tenant:
                raise ValueError("Tenant в поле и в ссылке Cloud Director не совпадают.")
            tenant = linked_tenant
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", tenant):
            raise ValueError("Укажите имя tenant из ссылки /tenant/<имя>/.")
        if self.api_version != "auto" and self.api_version not in API_VERSIONS:
            raise ValueError(
                "Выберите автоматическую версию API или поддерживаемую версию 36.1–39.1."
            )
        if not 5 <= self.timeout <= 120:
            raise ValueError("Таймаут должен быть от 5 до 120 секунд.")
        object.__setattr__(self, "site", f"https://{parsed.hostname}")
        object.__setattr__(self, "tenant", tenant)


@dataclass(frozen=True)
class ScanSelection:
    resources: tuple[str, ...]
    data: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.resources or set(self.resources) - RESOURCE_TYPES.keys():
            raise ValueError("Выберите хотя бы один тип устройств или сетей.")
        if set(self.data) - DATA_TYPES.keys():
            raise ValueError("Неизвестный тип данных сканирования.")
        if "vm_networks" in self.data and "vms" not in self.resources:
            raise ValueError("Для сетевых подключений выберите виртуальные машины.")
        if set(self.data) & {"firewall", "nat", "routes"} and "edges" not in self.resources:
            raise ValueError("Для правил и маршрутов выберите Edge Gateway.")


@dataclass
class ScanResult:
    state: str
    records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    requests: list[dict[str, str]] = field(default_factory=list)


Transport = Callable[[Request, int], bytes]


def _transport(request: Request, timeout: int) -> bytes:
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=timeout) as response:
            data: bytes = response.read(MAX_RESPONSE + 1)
    except HTTPError as error:
        messages = {
            400: "Запрос отклонён. Проверьте параметры и тип ключа доступа.",
            401: "Токен недействителен или истёк.",
            403: "Недостаточно прав на чтение ресурса.",
            404: "Ресурс или API недоступен на площадке.",
            406: "Версия API не поддерживается площадкой.",
            407: "Прокси-сервер требует авторизацию. Проверьте настройки прокси Windows.",
            429: "Превышен лимит запросов. Повторите позже.",
        }
        raise CloudError(
            f"HTTP {error.code}: " + messages.get(error.code, "Запрос Cloud.ru завершился ошибкой.")
        ) from None
    except (URLError, OSError) as error:
        reason = error.reason if isinstance(error, URLError) else error
        host = urlsplit(request.full_url).hostname
        if isinstance(reason, socket.gaierror):
            message = (
                f"DNS: не удалось определить адрес {host}. Скопируйте адрес из ссылки входа "
                "в Cloud Director; проверьте опечатки, DNS и необходимость VPN."
            )
        elif isinstance(reason, ssl.SSLCertVerificationError):
            message = (
                f"TLS: сертификат {host} не прошёл проверку. Проверьте адрес площадки, "
                "дату компьютера и доверенные сертификаты Windows/корпоративного прокси."
            )
        elif isinstance(reason, ssl.SSLError):
            message = f"TLS: не удалось установить защищённое соединение с {host}."
        elif isinstance(reason, TimeoutError):
            message = f"Таймаут: {host} не ответил за {timeout} с. Проверьте сеть, VPN и прокси."
        elif isinstance(reason, ConnectionRefusedError):
            message = f"Соединение с {host} отклонено. Проверьте доступ к HTTPS, VPN и прокси."
        else:
            message = f"Сетевая ошибка при обращении к {host}. Проверьте сеть, VPN и прокси."
        raise CloudError(message) from None
    if len(data) > MAX_RESPONSE:
        raise CloudError("Ответ превышает допустимый размер; данные не получены полностью.")
    return data


def _xml(data: bytes) -> ET.Element:
    try:
        return SafeET.fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException:
        raise CloudError("Неподдерживаемый XML-ответ.") from None
    except (ET.ParseError, LookupError, ValueError):
        raise CloudError("Cloud Director вернул некорректный XML.") from None


def _json(data: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(data)
    except (ValueError, UnicodeError):
        raise CloudError("Cloud Director вернул некорректный JSON.") from None
    if not isinstance(parsed, dict):
        raise CloudError("Неожиданная структура ответа Cloud Director.")
    return parsed


class VMwareClient:
    def __init__(
        self,
        config: VMwareConfig,
        api_token: str,
        *,
        transport: Transport = _transport,
        cancel: Event | None = None,
    ) -> None:
        if not api_token.strip():
            raise ValueError("Введите API Token VMware Cloud Director.")
        self.config = config
        self.api_version = config.api_version
        self._api_token = api_token
        self._access_token = ""
        self.transport = transport
        self.cancel = cancel or Event()
        self.requests: list[dict[str, str]] = []
        self._reference_cache: dict[tuple[str, str], dict[str, Any] | None] = {}

    def _request(
        self, path: str, *, xml: bool = False, auth: bool = True, data: bytes | None = None
    ) -> bytes:
        if self.cancel.is_set():
            raise CloudError("Сканирование отменено.")
        if not path.startswith(("/api/", "/cloudapi/", "/oauth/")) or "\r" in path or "\n" in path:
            raise CloudError("Недопустимый путь API.")
        accept = "application/*+xml" if xml else "application/json"
        headers = {"Accept": accept + (f";version={self.api_version}" if auth else "")}
        if auth:
            headers["Authorization"] = f"Bearer {self._access_token}"
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        method = "POST" if data is not None else "GET"
        entry = {"method": method, "path": path}
        if auth:
            entry["api_version"] = self.api_version
        self.requests.append(entry)
        try:
            response = self.transport(
                Request(self.config.site + path, data=data, headers=headers, method=method),
                self.config.timeout,
            )
        except CloudError as error:
            entry["status"] = "error"
            raise CloudError(f"{method} {path}: {error}") from None
        entry["status"] = "ok"
        return response

    def _select_api_version(self) -> None:
        root = _xml(self._request("/api/versions", xml=True, auth=False))
        if root.tag.rsplit("}", 1)[-1] != "SupportedVersions":
            raise CloudError("Ожидался список версий API. Проверьте адрес площадки Cloud Director.")
        versions: dict[str, bool] = {}
        for entry in root:
            if entry.tag.rsplit("}", 1)[-1] != "VersionInfo":
                continue
            for child in entry:
                version = (child.text or "").strip()
                if child.tag.rsplit("}", 1)[-1] == "Version" and version in API_VERSIONS:
                    versions[version] = entry.attrib.get("deprecated", "false").lower() != "true"
        if not versions:
            raise CloudError("У площадки нет совместимых версий API 36.1–39.1.")
        if self.config.api_version == "auto":
            preferred = [version for version, current in versions.items() if current] or list(
                versions
            )
            self.api_version = max(
                preferred, key=lambda version: tuple(map(int, version.split(".")))
            )
        elif self.config.api_version not in versions:
            raise CloudError(
                f"Площадка не поддерживает API {self.config.api_version}. "
                "Выберите «Автоматически» в настройках. Доступны: " + ", ".join(versions) + "."
            )
        else:
            self.api_version = self.config.api_version

    def authenticate(self) -> None:
        self._select_api_version()
        body = urlencode({"grant_type": "refresh_token", "refresh_token": self._api_token}).encode()
        payload = _json(
            self._request(
                f"/oauth/tenant/{quote(self.config.tenant, safe='')}/token", auth=False, data=body
            )
        )
        token = payload.get("access_token")
        if not isinstance(token, str) or not token or "\n" in token or "\r" in token:
            raise CloudError("Cloud Director не вернул Access Token.")
        self._access_token = token

    def check_connection(self) -> ScanResult:
        try:
            self.authenticate()
            orgs = _xml(self._request("/api/org/", xml=True))
            names = [
                item.attrib.get("name", "") for item in orgs if item.tag.rsplit("}", 1)[-1] == "Org"
            ]
            if self.config.tenant not in names:
                raise CloudError("У токена нет доступа к указанному tenant.")
            return ScanResult("completed", requests=self.requests)
        except CloudError as error:
            return ScanResult(
                "failed",
                errors=[{"resource": "Подключение", "message": str(error)}],
                requests=self.requests,
            )

    def _collection(self, path: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for page in range(1, MAX_PAGES + 1):
            payload = _json(self._request(path + "?" + urlencode({"page": page, "pageSize": 128})))
            values = payload.get("values")
            if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
                raise CloudError("Ожидался список values; сбор данных не завершён.")
            records.extend(values)
            total = payload.get("resultTotal")
            pages = payload.get("pageCount")
            if isinstance(total, int) and len(records) >= total:
                return records
            if isinstance(pages, int) and page >= pages:
                if isinstance(total, int) and len(records) < total:
                    raise CloudError("Последняя страница не содержит всех заявленных ресурсов.")
                return records
            if total is None and pages is None and len(values) < 128:
                return records
            if not values:
                raise CloudError("Пагинация прервалась до получения всех данных.")
        raise CloudError("Превышен лимит страниц; сбор данных не завершён.")

    def _vms(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        received = 0
        for page in range(1, MAX_PAGES + 1):
            root = _xml(
                self._request(
                    "/api/query?"
                    + urlencode(
                        {
                            "type": "vm",
                            "format": "records",
                            "filter": "(isVAppTemplate==false;isDeleted==false)",
                            "page": page,
                            "pageSize": 128,
                        }
                    ),
                    xml=True,
                )
            )
            if root.tag.rsplit("}", 1)[-1] != "QueryResultRecords":
                raise CloudError("Неожиданный ответ списка виртуальных машин.")
            values = [
                dict(item.attrib) for item in root if item.tag.rsplit("}", 1)[-1] == "VMRecord"
            ]
            received += len(values)
            records.extend(
                item
                for item in values
                if item.get("isVAppTemplate", "false").lower() not in {"true", "1"}
                and item.get("isDeleted", "false").lower() not in {"true", "1"}
            )
            try:
                total = int(root.attrib["total"])
            except (KeyError, ValueError):
                raise CloudError("В ответе отсутствует размер списка ВМ.") from None
            if received >= total:
                return records
            if not values:
                raise CloudError("Список ВМ получен не полностью.")
        raise CloudError("Превышен лимит страниц списка ВМ.")

    def _firewall(self, path: str) -> dict[str, Any]:
        payload = _json(self._request(path))
        if "userDefinedRules" not in payload:
            raise CloudError("В ответе Firewall отсутствует поле userDefinedRules.")
        for key in ("userDefinedRules", "systemRules", "defaultRules"):
            if key not in payload:
                continue
            rules = payload[key]
            # Cloud Director represents an empty rule group as either [] or null.
            # Preserve the default/system rules even when user-defined rules are empty.
            if rules is None:
                payload[key] = []
            elif not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
                raise CloudError(f"Неожиданный формат поля {key} в ответе Firewall.")
        return payload

    def _firewall_objects(
        self, firewall: dict[str, Any]
    ) -> tuple[dict[str, dict[str, Any]], list[str]]:
        """Read referenced objects on the configured origin; failed references remain unknown."""
        objects: dict[str, dict[str, Any]] = {
            "firewall_groups": {},
            "application_port_profiles": {},
        }
        errors: list[str] = []
        for section in ("systemRules", "userDefinedRules", "defaultRules"):
            for rule in firewall.get(section) or []:
                for reference_field, collection, endpoint, kind in (
                    ("sourceFirewallGroups", "firewall_groups", "firewallGroups", "firewallGroup"),
                    (
                        "destinationFirewallGroups",
                        "firewall_groups",
                        "firewallGroups",
                        "firewallGroup",
                    ),
                    (
                        "applicationPortProfiles",
                        "application_port_profiles",
                        "applicationPortProfiles",
                        "applicationPortProfile",
                    ),
                ):
                    refs = rule.get(reference_field)
                    if not isinstance(refs, list):
                        continue
                    for ref in refs:
                        if self.cancel.is_set():
                            return objects, errors
                        identifier = ref.get("id") if isinstance(ref, dict) else None
                        if not isinstance(identifier, str) or not re.fullmatch(
                            rf"(?:urn:vcloud:{kind}:)?[a-fA-F0-9]{{8}}(?:-[a-fA-F0-9]{{4}}){{3}}-[a-fA-F0-9]{{12}}",
                            identifier,
                        ):
                            errors.append(
                                "Ссылка на группу или профиль сервиса "
                                "не содержит поддерживаемого UUID."
                            )
                            continue
                        key = collection, identifier
                        if key not in self._reference_cache:
                            try:
                                if len(self._reference_cache) >= 4096:
                                    raise CloudError("Превышен лимит разрешения ссылок Firewall.")
                                value = _json(
                                    self._request(
                                        f"/cloudapi/1.0.0/{endpoint}/{quote(identifier, safe=':')}"
                                    )
                                )
                                if value.get("id") != identifier:
                                    raise CloudError(
                                        "ID группы/профиля в ответе не соответствует запросу."
                                    )
                                self._reference_cache[key] = value
                            except CloudError as error:
                                self._reference_cache[key] = None
                                errors.append(str(error))
                        cached = self._reference_cache[key]
                        if cached is not None:
                            objects[collection][identifier] = cached
                        elif not errors:
                            errors.append("Не удалось прочитать одну из групп/профилей Firewall.")
        return objects, errors

    def _vm_connections(self, vm: dict[str, Any]) -> list[dict[str, Any]]:
        href = str(vm.get("href", ""))
        parsed = urlsplit(href)
        if (
            parsed.scheme != "https"
            or parsed.netloc != urlsplit(self.config.site).netloc
            or not re.fullmatch(r"/api/vApp/vm-[a-fA-F0-9-]+", parsed.path)
            or parsed.query
            or parsed.fragment
        ):
            raise CloudError("ВМ содержит недопустимую ссылку API.")
        root = _xml(self._request(parsed.path + "/networkConnectionSection", xml=True))
        if root.tag.rsplit("}", 1)[-1] != "NetworkConnectionSection":
            raise CloudError("Неожиданный ответ сетевых подключений ВМ.")
        return [
            {
                "network": item.attrib.get("network", ""),
                **{child.tag.rsplit("}", 1)[-1]: child.text or "" for child in item},
            }
            for item in root
            if item.tag.rsplit("}", 1)[-1] == "NetworkConnection"
        ]

    def scan(self, selection: ScanSelection) -> ScanResult:
        result = ScanResult("completed", requests=self.requests)
        try:
            self.authenticate()
        except CloudError as error:
            result.errors.append({"resource": "Подключение", "message": str(error)})
            result.state = "cancelled" if self.cancel.is_set() else "failed"
            return result
        for kind in selection.resources:
            if self.cancel.is_set():
                break
            try:
                if kind == "vms":
                    resources = self._vms()
                else:
                    resources = self._collection(
                        "/cloudapi/1.0.0/"
                        + ("edgeGateways" if kind == "edges" else "orgVdcNetworks")
                    )
            except CloudError as error:
                result.errors.append({"resource": RESOURCE_TYPES[kind], "message": str(error)})
                continue
            for resource in resources:
                if self.cancel.is_set():
                    break
                record: dict[str, Any] = {
                    "type": kind,
                    "name": str(resource.get("name", "")),
                    "id": str(resource.get("id") or resource.get("href", "")),
                    "inventory": resource,
                    "data": {},
                    "collected_at": datetime.now(UTC).isoformat(),
                }
                result.records.append(record)
                for data_kind in selection.data:
                    if kind == "vms" and data_kind == "vm_networks":
                        try:
                            record["data"][data_kind] = self._vm_connections(resource)
                        except CloudError as error:
                            result.errors.append(
                                {
                                    "resource": record["name"] + " / " + DATA_TYPES[data_kind],
                                    "message": str(error),
                                }
                            )
                    elif kind == "edges" and data_kind in {"firewall", "nat", "routes"}:
                        try:
                            gateway_id = str(resource.get("id", ""))
                            if not re.fullmatch(r"urn:vcloud:gateway:[a-fA-F0-9-]+", gateway_id):
                                raise CloudError("Edge Gateway содержит недопустимый ID.")
                            version = (
                                "2.0.0"
                                if tuple(map(int, self.api_version.split("."))) >= (38, 1)
                                else "1.0.0"
                            )
                            suffix = {
                                "firewall": "/firewall/rules",
                                "nat": "/nat/rules",
                                "routes": "/routing/staticRoutes",
                            }[data_kind]
                            path = (
                                f"/cloudapi/{version}/edgeGateways/"
                                f"{quote(gateway_id, safe=':')}{suffix}"
                            )
                            if data_kind == "firewall":
                                record["data"][data_kind] = self._firewall(path)
                                objects, object_errors = self._firewall_objects(
                                    record["data"][data_kind]
                                )
                                record["data"].update(objects)
                                result.errors.extend(
                                    {
                                        "resource": record["name"] + " / Объекты Firewall",
                                        "message": message,
                                    }
                                    for message in object_errors
                                )
                            else:
                                record["data"][data_kind] = self._collection(path)
                        except CloudError as error:
                            result.errors.append(
                                {
                                    "resource": record["name"] + " / " + DATA_TYPES[data_kind],
                                    "message": str(error),
                                }
                            )
        if self.cancel.is_set():
            result.state = "cancelled"
        elif result.errors:
            result.state = "partial" if result.records else "failed"
        return result
