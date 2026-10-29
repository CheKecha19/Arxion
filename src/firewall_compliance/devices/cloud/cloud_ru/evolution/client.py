"""EvolutionClient implementation."""

from __future__ import annotations

import json
from typing import Any
from urllib.request import Request

from firewall_compliance.devices.cloud.cloud_ru.public_client_common import (
    CloudCredentials,
    EvolutionConfig,
    PublicCloudClient,
)
from firewall_compliance.devices.cloud.cloud_ru.vmware.client import MAX_PAGES, CloudError, _json


class EvolutionClient(PublicCloudClient):
    platform = "evolution"
    ENDPOINT = "https://compute.api.cloud.ru"

    def __init__(
        self, config: EvolutionConfig, credentials: CloudCredentials, **kwargs: Any
    ) -> None:
        super().__init__(config, credentials, **kwargs)
        self._access_token = ""

    def _authenticate(self) -> None:
        if self.cancel.is_set():
            raise CloudError("Сканирование отменено.")
        url = "https://iam.api.cloud.ru/api/v2/auth/token"
        self.requests.append({"method": "POST", "path": url})
        body = json.dumps(
            {"keyId": self.credentials.access_key, "secret": self.credentials.secret_key}
        ).encode()
        payload = _json(
            self.transport(
                Request(
                    url, data=body, headers={"Content-Type": "application/json"}, method="POST"
                ),
                self.config.timeout,
            )
        )
        token = payload.get("access_token")
        if not isinstance(token, str) or not token or "\r" in token or "\n" in token:
            raise CloudError("Evolution не вернул Access Token.")
        self._access_token = token

    def _authorize(self, request: Request) -> None:
        request.add_header("Authorization", "Bearer " + self._access_token)

    def _probe(self) -> None:
        payload = self._get(self.ENDPOINT, f"/api/v1/projects/{self.config.project_id}")
        if payload.get("id") != self.config.project_id:
            raise CloudError("Не удалось подтвердить доступ к проекту Evolution.")

    def _list(self, path: str, query: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            payload = self._get(
                self.ENDPOINT, path, {**(query or {}), "offset": len(collected), "limit": 100}
            )
            items, total = payload.get("items"), payload.get("total")
            if (
                not isinstance(items, list)
                or any(not isinstance(item, dict) for item in items)
                or type(total) is not int
                or total < 0
            ):
                raise CloudError("Некорректный ответ пагинации Evolution.")
            for item in items:
                item_id = self._id(item)
                if item_id in seen:
                    raise CloudError("Evolution повторил ресурс при пагинации; сбор неполный.")
                seen.add(item_id)
            collected.extend(items)
            if len(collected) == total:
                return collected
            if not items or len(collected) > total:
                raise CloudError(
                    "Список Evolution получен не полностью или изменился во время сбора."
                )
        raise CloudError("Превышен лимит страниц Evolution.")

    def _resources(self, kind: str) -> list[dict[str, Any]]:
        path = {
            "vms": "/api/v1/vms",
            "subnets": "/api/v1/subnets",
            "interfaces": "/api/v1/interfaces",
            "security_groups": "/api/v1/security-groups",
        }[kind]
        return self._list(path, {"project_id": self.config.project_id})

    def _data(self, kind: str, resource: dict[str, Any], data_kind: str) -> Any:
        identifier = self._id(resource)
        if data_kind == "security_rules":
            return self._list(f"/api/v1/security-groups/{identifier}/rules")
        return self._list(
            "/api/v1/interfaces", {"project_id": self.config.project_id, "vm_ids": identifier}
        )
