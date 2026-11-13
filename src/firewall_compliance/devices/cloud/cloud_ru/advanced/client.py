"""AdvancedClient implementation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.request import Request
from uuid import UUID

from firewall_compliance.devices.cloud.cloud_ru.public_client_common import (
    AdvancedConfig,
    CloudCredentials,
    PublicCloudClient,
    PublicSelection,
    sign_advanced,
)
from firewall_compliance.devices.cloud.cloud_ru.vmware.client import (
    MAX_PAGES,
    CloudError,
    ScanResult,
)


def _uuid(value: object) -> str | None:
    if isinstance(value, str):
        try:
            return str(UUID(value))
        except ValueError:
            pass
    return None


class AdvancedClient(PublicCloudClient):
    platform = "advanced"

    def __init__(
        self, config: AdvancedConfig, credentials: CloudCredentials, **kwargs: Any
    ) -> None:
        super().__init__(config, credentials, **kwargs)
        self.advanced = config

    def _authorize(self, request: Request) -> None:
        request.add_header("X-Project-Id", self.config.project_id)
        sign_advanced(request, self.credentials, datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))

    def _probe(self) -> None:
        payload = self._get(
            self.advanced.ecs_endpoint,
            f"/v2.1/{self.config.project_id}/servers/detail",
            {"limit": 1},
        )
        if not isinstance(payload.get("servers"), list):
            raise CloudError("Не удалось подтвердить доступ к ECS проекта Advanced.")

    def _list(self, endpoint: str, path: str, key: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        marker = ""
        for _ in range(MAX_PAGES):
            query: dict[str, Any] = {"limit": 100}
            if marker:
                query["marker"] = marker
            payload = self._get(endpoint, path, query)
            items = payload.get(key)
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise CloudError(f"Advanced не вернул список {key}.")
            for item in items:
                identifier = self._id(item)
                if identifier in seen:
                    raise CloudError("Advanced повторил ресурс при пагинации; сбор неполный.")
                seen.add(identifier)
            result.extend(items)
            if not items:
                return result
            marker = self._id(items[-1])
        raise CloudError("Превышен лимит страниц Advanced.")

    def _resources(self, kind: str) -> list[dict[str, Any]]:
        project = self.config.project_id
        if kind == "vms":
            return self._list(
                self.advanced.ecs_endpoint, f"/v2.1/{project}/servers/detail", "servers"
            )
        suffix, key = {
            "vpcs": ("vpcs", "vpcs"),
            "subnets": ("subnets", "subnets"),
            "security_groups": ("security-groups", "security_groups"),
        }[kind]
        return self._list(self.advanced.vpc_endpoint, f"/v1/{project}/{suffix}", key)

    def scan(self, selection: PublicSelection) -> ScanResult:
        result = super().scan(selection)
        if "vm_networks" not in selection.data or result.state in ("failed", "cancelled"):
            return result

        attachments: list[tuple[str, str, dict[str, Any]]] = []
        unresolved = 0
        for record in result.records:
            vm_id = _uuid(record["id"])
            for attachment in record["data"].get("vm_networks", []):
                if not isinstance(attachment, dict):
                    unresolved += 1
                    continue
                port_id = _uuid(attachment.get("port_id"))
                if port_id is None or vm_id is None:
                    unresolved += 1
                    continue
                attachments.append((vm_id, port_id, attachment))

        if attachments:
            try:
                unresolved += self._join_vpc_ports(attachments)
            except CloudError as error:
                result.errors.append({"resource": "Порты VPC Advanced", "message": str(error)})
        if unresolved:
            result.errors.append(
                {
                    "resource": "Порты VPC Advanced",
                    "message": f"Интерфейсы ВМ без подтверждённых привязок SG: {unresolved}.",
                }
            )
        if self.cancel.is_set():
            result.state = "cancelled"
        elif result.errors and result.records:
            result.state = "partial"
        return result

    def _join_vpc_ports(self, attachments: list[tuple[str, str, dict[str, Any]]]) -> int:
        # ListPorts from Cloud.ru Advanced's VPC SDK uses this project-scoped endpoint.
        project = self.advanced.project_id
        ports = self._list(self.advanced.vpc_endpoint, f"/v1/{project}/ports", "ports")
        by_id = {self._id(port): port for port in ports}
        project_id = str(UUID(project))
        unresolved = 0
        for vm_id, port_id, attachment in attachments:
            port = by_id.get(port_id)
            if port is None:
                attachment["vpc_port_status"] = "missing"
                unresolved += 1
                continue
            network_id = _uuid(attachment.get("net_id"))
            groups = port.get("security_groups")
            if (
                _uuid(port.get("device_id")) != vm_id
                or network_id is None
                or _uuid(port.get("network_id")) != network_id
                or _uuid(port.get("tenant_id")) != project_id
                or not isinstance(groups, list)
                or any(_uuid(group) is None for group in groups)
            ):
                unresolved += 1
                continue
            evidence = {
                field: port[field]
                for field in ("id", "network_id", "device_id", "tenant_id", "security_groups")
            }
            security_enabled = port.get("port_security_enabled")
            if isinstance(security_enabled, bool):
                evidence["port_security_enabled"] = security_enabled
            attachment["vpc_port"] = evidence
            attachment["vpc_port_status"] = "present"
        return unresolved

    def _data(self, kind: str, resource: dict[str, Any], data_kind: str) -> Any:
        identifier = self._id(resource)
        if data_kind == "security_rules":
            payload = self._get(
                self.advanced.vpc_endpoint,
                f"/v1/{self.config.project_id}/security-groups/{identifier}",
            )
            group = payload.get("security_group")
            if not isinstance(group, dict) or not isinstance(
                group.get("security_group_rules"), list
            ):
                raise CloudError("Advanced не вернул правила группы безопасности.")
            return group["security_group_rules"]
        payload = self._get(
            self.advanced.ecs_endpoint,
            f"/v2.1/{self.config.project_id}/servers/{identifier}/os-interface",
        )
        interfaces = payload.get("interfaceAttachments")
        if not isinstance(interfaces, list):
            raise CloudError("Advanced не вернул сетевые интерфейсы ВМ.")
        for attachment in interfaces:
            if isinstance(attachment, dict):
                attachment.pop("vpc_port", None)
                attachment["vpc_port_status"] = "partial"
        return interfaces
