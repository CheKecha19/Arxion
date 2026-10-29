"""AdvancedClient implementation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.request import Request

from firewall_compliance.devices.cloud.cloud_ru.public_client_common import (
    AdvancedConfig,
    CloudCredentials,
    PublicCloudClient,
    sign_advanced,
)
from firewall_compliance.devices.cloud.cloud_ru.vmware.client import MAX_PAGES, CloudError


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
        return interfaces
