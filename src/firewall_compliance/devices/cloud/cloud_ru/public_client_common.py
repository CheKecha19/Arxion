"""Read-only Evolution Compute and Advanced ECS/VPC API collectors."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Event
from typing import Any
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request
from uuid import UUID

from firewall_compliance.devices.cloud.cloud_ru.vmware.client import (
    CloudError,
    ScanResult,
    Transport,
    _json,
    _transport,
)

PUBLIC_RESOURCES = {
    "vms": "Виртуальные машины",
    "vpcs": "Виртуальные сети VPC",
    "subnets": "Подсети",
    "security_groups": "Группы безопасности",
    "interfaces": "Сетевые интерфейсы",
}
PUBLIC_DATA = {
    "vm_networks": "Сетевые подключения и IP-адреса ВМ",
    "security_rules": "Правила групп безопасности",
}
PLATFORM_RESOURCES = {
    "evolution": ("vms", "subnets", "security_groups", "interfaces"),
    "advanced": ("vms", "vpcs", "subnets", "security_groups"),
}
_PRIVATE_FIELDS = {
    "metadata",
    "metadata_fields",
    "image_metadata",
    "cloud_init",
    "user_data",
    "adminPass",
    "OS-EXT-SRV-ATTR:user_data",
    "vnc_url",
    "vnc_ws",
    "remote_console_url",
    "remote_console_ws",
}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items() if k not in _PRIVATE_FIELDS}
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


@dataclass(frozen=True)
class CloudCredentials:
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)

    def __post_init__(self) -> None:
        if not self.access_key.strip() or not self.secret_key.strip():
            raise ValueError("Укажите обе части ключа доступа.")
        if (
            any(char in self.access_key for char in '\r\n," ')
            or "\r" in self.secret_key
            or "\n" in self.secret_key
        ):
            raise ValueError("Ключ доступа содержит недопустимые символы.")


@dataclass(frozen=True)
class EvolutionConfig:
    project_id: str
    timeout: int = 30

    def __post_init__(self) -> None:
        try:
            normalized = str(UUID(self.project_id))
        except ValueError:
            raise ValueError("Project ID Evolution должен быть UUID проекта.") from None
        object.__setattr__(self, "project_id", normalized)
        if not 5 <= self.timeout <= 120:
            raise ValueError("Таймаут должен быть от 5 до 120 секунд.")


@dataclass(frozen=True)
class AdvancedConfig:
    project_id: str
    region: str = "ru-moscow-1"
    ecs_endpoint: str = ""
    vpc_endpoint: str = ""
    timeout: int = 30

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-fA-F0-9]{32}", self.project_id):
            raise ValueError("Project ID Advanced должен содержать 32 шестнадцатеричных символа.")
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,40}", self.region):
            raise ValueError("Укажите регион Advanced, например ru-moscow-1.")
        for name, service in (("ecs_endpoint", "ecs"), ("vpc_endpoint", "vpc")):
            endpoint = getattr(self, name) or f"https://{service}.{self.region}.hc.sbercloud.ru"
            parsed = urlsplit(endpoint)
            allowed = {
                f"{service}.{self.region}.hc.sbercloud.ru",
                f"{service}.{self.region}.hc.cloud.ru",
            }
            if (
                parsed.scheme != "https"
                or parsed.hostname not in allowed
                or parsed.username
                or parsed.password
                or parsed.port not in (None, 443)
                or parsed.query
                or parsed.fragment
                or parsed.path not in ("", "/")
            ):
                raise ValueError(
                    f"Укажите HTTPS-адрес {service.upper()} API Cloud.ru для выбранного региона."
                )
            object.__setattr__(self, name, f"https://{parsed.hostname}")
        if not 5 <= self.timeout <= 120:
            raise ValueError("Таймаут должен быть от 5 до 120 секунд.")


@dataclass(frozen=True)
class PublicSelection:
    resources: tuple[str, ...]
    data: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.resources or set(self.resources) - PUBLIC_RESOURCES.keys():
            raise ValueError("Выберите типы ресурсов для сканирования.")
        if set(self.data) - PUBLIC_DATA.keys():
            raise ValueError("Неизвестный тип данных сканирования.")
        if "vm_networks" in self.data and "vms" not in self.resources:
            raise ValueError("Для сетевых подключений выберите виртуальные машины.")
        if "security_rules" in self.data and "security_groups" not in self.resources:
            raise ValueError("Для правил выберите группы безопасности.")


def sign_advanced(request: Request, credentials: CloudCredentials, timestamp: str) -> None:
    """Huawei SDK-HMAC-SHA256 canonical request signing for read-only GETs."""
    parsed = urlsplit(request.full_url)
    canonical_uri = quote(parsed.path, safe="/-_.~")
    if not canonical_uri.endswith("/"):
        canonical_uri += "/"
    values = {"host": parsed.netloc, "x-sdk-date": timestamp}
    project_id = request.get_header("X-project-id")
    if project_id:
        values["x-project-id"] = project_id
    headers = "".join(f"{key}:{values[key]}\n" for key in sorted(values))
    signed_headers = ";".join(sorted(values))
    canonical = "\n".join(
        (
            request.get_method(),
            canonical_uri,
            parsed.query,
            headers,
            signed_headers,
            hashlib.sha256(b"").hexdigest(),
        )
    )
    to_sign = (
        "SDK-HMAC-SHA256\n" + timestamp + "\n" + hashlib.sha256(canonical.encode()).hexdigest()
    )
    signature = hmac.new(
        credentials.secret_key.encode(), to_sign.encode(), hashlib.sha256
    ).hexdigest()
    request.add_header("Host", parsed.netloc)
    request.add_header("X-Sdk-Date", timestamp)
    request.add_header(
        "Authorization",
        f"SDK-HMAC-SHA256 Access={credentials.access_key}, "
        f"SignedHeaders={signed_headers}, Signature={signature}",
    )


class PublicCloudClient:
    platform: str

    def __init__(
        self,
        config: EvolutionConfig | AdvancedConfig,
        credentials: CloudCredentials,
        *,
        transport: Transport = _transport,
        cancel: Event | None = None,
    ) -> None:
        self.config = config
        self.credentials = credentials
        self.transport = transport
        self.cancel = cancel or Event()
        self.requests: list[dict[str, str]] = []

    def _get(self, endpoint: str, path: str, query: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.cancel.is_set():
            raise CloudError("Сканирование отменено.")
        encoded = urlencode(sorted((query or {}).items()), quote_via=quote)
        url = endpoint + path + ("?" + encoded if encoded else "")
        self.requests.append({"method": "GET", "path": url})
        request = Request(url, headers={"Accept": "application/json"}, method="GET")
        self._authorize(request)
        return _json(self.transport(request, self.config.timeout))

    def _authorize(self, request: Request) -> None:
        raise NotImplementedError

    def _authenticate(self) -> None:
        pass

    def _resources(self, kind: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def _data(self, kind: str, resource: dict[str, Any], data_kind: str) -> Any:
        raise NotImplementedError

    def check_connection(self) -> ScanResult:
        try:
            self._authenticate()
            self._probe()
            return ScanResult("completed", requests=self.requests)
        except CloudError as error:
            return ScanResult(
                "failed",
                errors=[{"resource": "Подключение", "message": str(error)}],
                requests=self.requests,
            )

    def _probe(self) -> None:
        raise NotImplementedError

    def scan(self, selection: PublicSelection) -> ScanResult:
        if set(selection.resources) - set(PLATFORM_RESOURCES[self.platform]):
            raise ValueError("Выбранный тип ресурсов не поддерживается платформой.")
        result = ScanResult("completed", requests=self.requests)
        try:
            self._authenticate()
            if self.cancel.is_set():
                raise CloudError("Сканирование отменено.")
        except CloudError as error:
            result.state = "cancelled" if self.cancel.is_set() else "failed"
            result.errors.append({"resource": "Подключение", "message": str(error)})
            return result
        for kind in selection.resources:
            if self.cancel.is_set():
                break
            try:
                resources = self._resources(kind)
            except CloudError as error:
                result.errors.append({"resource": PUBLIC_RESOURCES[kind], "message": str(error)})
                continue
            for resource in resources:
                if self.cancel.is_set():
                    break
                record: dict[str, Any] = {
                    "type": kind,
                    "name": str(resource.get("name", resource.get("id", ""))),
                    "id": str(resource.get("id", "")),
                    "inventory": _sanitize(resource),
                    "data": {},
                    "collected_at": datetime.now(UTC).isoformat(),
                }
                result.records.append(record)
                for data_kind in selection.data:
                    if (kind, data_kind) not in {
                        ("vms", "vm_networks"),
                        ("security_groups", "security_rules"),
                    }:
                        continue
                    try:
                        record["data"][data_kind] = _sanitize(self._data(kind, resource, data_kind))
                    except CloudError as error:
                        result.errors.append(
                            {
                                "resource": record["name"] + " / " + PUBLIC_DATA[data_kind],
                                "message": str(error),
                            }
                        )
        if self.cancel.is_set():
            result.state = "cancelled"
        elif result.errors:
            result.state = "partial" if result.records else "failed"
        return result

    def _id(self, resource: dict[str, Any]) -> str:
        try:
            return str(UUID(str(resource["id"])))
        except (KeyError, ValueError):
            raise CloudError("Ресурс содержит недопустимый UUID.") from None
