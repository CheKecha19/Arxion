"""Полные синтетические доказательства для первого среза forwarding policy."""

from typing import Any

from firewall_compliance.domain.forwarding import ForwardingContext
from tests.forwarding_fixtures import make_forwarding_context

INGRESS_ID = "GigabitEthernet0/1"
EGRESS_ID = "GigabitEthernet0/2"


def policy_payload() -> dict[str, Any]:
    """Отделить physical ID от label и задать явно подтверждённый профиль."""
    values = make_forwarding_context().model_dump(mode="python")
    values.update(
        device_context=None,
        context_mode="single",
        firewall_mode="routed",
        address_family="ipv4",
        table_role="data",
        table_id="default",
        profile_reference="Синтетическое подтверждение профиля",
    )
    for source in values["sources"]:
        source["device_context"] = None
    for interface, identifier in zip(values["interfaces"], (INGRESS_ID, EGRESS_ID), strict=True):
        interface["interface_id"] = identifier
    values["bindings"][0]["interface_id"] = INGRESS_ID
    values["flow"]["query"].update(device_context=None, ingress_interface_id=INGRESS_ID)
    return values


def feature(values: dict[str, Any], name: str) -> dict[str, Any]:
    return next(item for item in values["inventories"] if item["feature"] == name)


def incomplete_feature(values: dict[str, Any], name: str, status: str = "unknown") -> None:
    feature(values, name).update(status=status, complete=False, enumeration_complete=False)


def policy_context(values: dict[str, Any] | None = None) -> ForwardingContext:
    """Пересчитать только перечни фактов, сохранив неизвестность inventories."""
    values = policy_payload() if values is None else values
    facts = {
        "interfaces": values["interfaces"],
        "acl_definitions": values["acls"],
        "acl_bindings": values["bindings"],
        "same_security": [item for item in values["toggles"] if item["name"] != "permit_vpn"],
        "vpn_bypass": [item for item in values["toggles"] if item["name"] == "permit_vpn"],
    }
    for name, items in facts.items():
        inventory = feature(values, name)
        inventory["item_count"] = len(items)
        inventory["locations"] = [item["location"] for item in items if item["location"]]
        if inventory["complete"]:
            inventory["status"] = "known" if items else "absent"
    return ForwardingContext.model_validate(values)
