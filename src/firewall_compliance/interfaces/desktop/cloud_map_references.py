"""Типизированные ссылки сохранённых облачных ответов; без сети и догадок по именам."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID


KINDS = {
    "vm": "vms", "vms": "vms", "server": "vms", "servers": "vms",
    "network": "networks", "networks": "networks", "orgvdcnetwork": "networks",
    "orgvdcnetworks": "networks", "gateway": "edges", "edgegateway": "edges",
    "edgegateways": "edges", "vdc": "vdc", "orgvdc": "vdc",
    "subnet": "subnets", "subnets": "subnets", "vpc": "vpcs", "vpcs": "vpcs",
    "interface": "interfaces", "interfaces": "interfaces", "port": "interfaces",
    "securitygroup": "security_groups", "security-groups": "security_groups",
}
FIELDS = {
    "networkid": "networks", "netid": "networks", "networkref": "networks",
    "network": "networks", "orgvdcnetwork": "networks",
    "subnetid": "subnets", "subnetref": "subnets", "subnet": "subnets",
    "vpcid": "vpcs", "vpcref": "vpcs", "vpc": "vpcs",
    "serverid": "vms", "vmid": "vms", "virtualmachineid": "vms",
    "serverref": "vms", "vmref": "vms",
    "securitygroupid": "security_groups", "securitygroupids": "security_groups",
    "securitygroups": "security_groups", "securitygroup": "security_groups",
    "routerref": "edges", "edgegatewayref": "edges", "edgegatewayid": "edges",
    "edgegateway": "edges", "routerid": "edges",
    "interfaceid": "interfaces", "portid": "interfaces",
}


def reference_value(value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("id") or value.get("href")
    return value.strip() if isinstance(value, str) and value.strip() else None


def canonical_cloud_reference(value: str, kind: str) -> str:
    """URN/href/UUID сравниваются только в заданном типе и подключении."""
    candidate = value.strip()
    urn = re.fullmatch(r"urn:vcloud:([a-zA-Z]+):([a-fA-F0-9-]+)", candidate)
    if urn is not None:
        if KINDS.get(urn[1].lower()) != kind:
            return "ref:" + candidate
        candidate = urn[2]
    elif "://" in candidate or candidate.startswith("/"):
        parts = urlsplit(candidate).path.rstrip("/").split("/")
        if len(parts) < 2 or KINDS.get(parts[-2].lower()) != kind:
            return "ref:" + candidate
        candidate = parts[-1]
    try:
        return "uuid:" + str(UUID(candidate))
    except ValueError:
        return "ref:" + value.strip()


def vdc_reference(inventory: dict[str, object]) -> tuple[str, str] | None:
    for field in ("vdc", "orgVdc", "ownerRef", "vdcId", "orgVdcId", "vdc_id"):
        raw = inventory.get(field)
        value = reference_value(raw)
        if value is not None:
            if field == "ownerRef" and not any(
                marker in value.lower() for marker in (":vdc:", "/vdc/", "/orgvdcs/")
            ):
                continue
            label = raw.get("name") if isinstance(raw, dict) else None
            return canonical_cloud_reference(value, "vdc"), str(label or inventory.get("vdcName") or value)
    return None


@dataclass(frozen=True, order=True, slots=True)
class CloudReference:
    kind: str
    identifier: str
    path: str


def cloud_references(value: object, path: str = "inventory") -> tuple[CloudReference, ...]:
    result: set[CloudReference] = set()

    def visit(child: object, location: str) -> None:
        if isinstance(child, dict):
            for field, raw in child.items():
                normalized = str(field).replace("_", "").lower()
                kind = FIELDS.get(normalized)
                next_path = f"{location}.{field}"
                if kind is not None:
                    values = raw if isinstance(raw, list) else [raw]
                    for item in values:
                        # network="name" у VMware — локальное имя сети vApp,
                        # а security_groups=["name"] не содержит стабильных ID.
                        if not isinstance(item, dict) and not normalized.endswith(("id", "ids")):
                            continue
                        identifier = reference_value(item)
                        if identifier is not None:
                            result.add(CloudReference(kind, canonical_cloud_reference(identifier, kind), next_path))
                if isinstance(raw, (dict, list)):
                    visit(raw, next_path)
        elif isinstance(child, list):
            for index, item in enumerate(child):
                visit(item, f"{location}[{index}]")

    visit(value, path)
    return tuple(sorted(result))
