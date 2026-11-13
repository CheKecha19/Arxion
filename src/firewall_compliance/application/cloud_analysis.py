"""Normalize saved VMware Edge policies for the existing checks and maps; no I/O."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from ipaddress import ip_address, ip_network
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid4, uuid5

from firewall_compliance import __version__
from firewall_compliance.domain.configuration import Configuration, Device, Rule
from firewall_compliance.domain.enums import (
    DataStatus,
    EndpointKind,
    ParseIssueLevel,
    Protocol,
    RuleAction,
    SourceDocumentKind,
)
from firewall_compliance.domain.matrix_vmware_origin import VMwareMatrixOrigin
from firewall_compliance.domain.network import Endpoint, IpRange, PortRange, Service
from firewall_compliance.domain.parse_result import ParseCoverage, ParseIssue, ParseResult
from firewall_compliance.domain.revision import DeviceRevision, RevisionSource
from firewall_compliance.domain.source import SourceLocation

ADAPTER_VERSION = "1.1.0"


def vmware_device_id(config: dict[str, Any], resource_id: str) -> str:
    scope = json.dumps([config.get("site"), config.get("tenant"), resource_id])
    return "cloud-ru-vmware:" + sha256(scope.encode()).hexdigest()[:24]


def vmware_revision(
    scan: dict[str, Any], record_index: int, *, imported_at: datetime | None = None,
    application_version: str = __version__,
) -> DeviceRevision:
    """Interpret only Edge Firewall policy, keeping unsupported conditions explicit."""
    return vmware_record_revision(
        scan, record_index, scan["result"]["records"][record_index],
        imported_at=imported_at, application_version=application_version,
    )


def _vmware_captured_at(scan: dict[str, Any], record: dict[str, Any]) -> datetime:
    timestamp = record.get("collected_at") or scan.get("created_at")
    if not isinstance(timestamp, str):
        raise ValueError("В снимке VMware отсутствует дата сбора.")
    captured = datetime.fromisoformat(timestamp)
    if captured.utcoffset() is None:
        raise ValueError("Дата снимка VMware не содержит часовой пояс.")
    return captured


def vmware_scope_revision(
    scan: dict[str, Any], origin: VMwareMatrixOrigin, *, project_id: str, site_id: str | None,
    imported_at: datetime | None = None, application_version: str = __version__,
    record: dict[str, Any] | None = None,
) -> DeviceRevision:
    """Восстановить политику Edge из полного сбора или уже извлечённой записи."""
    if scan.get("id") != origin.scan_id or scan.get("project_id") != project_id:
        raise ValueError("Сбор VMware не найден в этом проекте")
    config = scan.get("config")
    if not isinstance(config, dict) or config.get("platform", "vmware") != "vmware":
        raise ValueError("Облачный сбор не относится к платформе VMware")
    if scan.get("state") not in {"completed", "partial"}:
        raise ValueError("Для сверки нужен успешный или частичный сбор VMware")
    selection = scan.get("selection")
    sites = selection.get("workspace_site_ids") if isinstance(selection, dict) else None
    if site_id == "" or (site_id is not None and (not isinstance(sites, (list, tuple)) or site_id not in sites)):
        raise ValueError("Сбор VMware не привязан к выбранной площадке")
    if record is None:
        result = scan.get("result")
        records = result.get("records") if isinstance(result, dict) else None
        if not isinstance(records, (list, tuple)) or origin.record_index >= len(records):
            raise ValueError("Запись Edge Gateway не найдена в сохранённом сборе")
        record = records[origin.record_index]
    if (not isinstance(record, dict) or record.get("id") != origin.resource_id
            or origin.resource_id != origin.resource_id.strip()):
        raise ValueError("Запись Edge Gateway отличается от сохранённого источника сверки")
    data = record.get("data")
    firewall = data.get("firewall") if isinstance(data, dict) else None
    if not isinstance(firewall, dict) or firewall.get("userDefinedRules") is None:
        raise ValueError("В снимке отсутствуют пользовательские правила Edge Gateway")
    return vmware_record_revision(
        scan, origin.record_index, record,
        imported_at=imported_at if imported_at is not None else _vmware_captured_at(scan, record),
        application_version=application_version,
    )


def vmware_record_revision(
    scan: dict[str, Any], record_index: int, record: object, *, imported_at: datetime | None = None,
    application_version: str = __version__,
) -> DeviceRevision:
    """Normalize the selected record with its original path in the saved scan."""
    if scan["config"].get("platform", "vmware") != "vmware":
        raise ValueError("Этот анализ поддерживает только Cloud.ru VMware.")
    if not isinstance(record, dict) or not isinstance(record.get("data"), dict):
        raise ValueError("Некорректный объект снимка VMware.")
    if not isinstance(record.get("id"), str) or not record["id"].strip():
        raise ValueError("В снимке отсутствует идентификатор Edge Gateway.")
    firewall = record["data"].get("firewall")
    if record.get("type") != "edges" or not isinstance(firewall, dict):
        raise ValueError("В выбранном ресурсе не получены правила Firewall Edge Gateway.")
    if "userDefinedRules" not in firewall:
        raise ValueError("В ответе Firewall отсутствует userDefinedRules.")
    captured = _vmware_captured_at(scan, record)
    if imported_at is not None and (imported_at.utcoffset() is None or imported_at < captured):
        raise ValueError("Время импорта VMware должно содержать часовой пояс и следовать за сбором.")
    imported = imported_at if imported_at is not None else max(datetime.now(UTC), captured)
    source_name = f"Cloud.ru VMware / {record.get('name') or record['id']} / {scan['id']}"
    device_id = vmware_device_id(scan["config"], record["id"])
    digest = sha256(json.dumps(record, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    config_id = uuid5(NAMESPACE_URL, f"{scan['id']}/{record['id']}/{digest}")
    source_id = uuid4() if imported_at is None else uuid5(NAMESPACE_URL, f"{config_id}/records/{record_index}")
    configuration = Configuration(
        configuration_id=config_id,
        source_name=source_name,
        device_id=device_id,
        vendor="vmware",
        platform="cloud-ru-vmware-nsxt",
        parser_version=ADAPTER_VERSION,
        content_sha256=digest,
        captured_at=captured,
        imported_at=imported,
    )
    issues: list[ParseIssue] = []
    endpoints: dict[str, Endpoint] = {}
    services: dict[str, Service] = {}
    groups = record.get("data", {}).get("firewall_groups", {})
    profiles = record.get("data", {}).get("application_port_profiles", {})

    def issue(message: str, location: SourceLocation) -> None:
        issues.append(
            ParseIssue(
                code="VMWARE_UNSUPPORTED_CONDITION",
                level=ParseIssueLevel.WARNING,
                message=message,
                source_location=location,
            )
        )

    def addresses(
        raw: dict[str, Any], side: str, family: str
    ) -> tuple[tuple[Endpoint, ...], DataStatus]:
        refs = raw.get(side + "FirewallGroups")
        ips = raw.get(side + "FirewallIpAddresses")
        values: list[Endpoint] = []

        def address(value: Any, key: str) -> None:
            try:
                if not isinstance(value, str):
                    raise ValueError
                if "-" in value:
                    start, end = value.split("-", 1)
                    if (
                        family == "IPV4"
                        and ip_address(start).version != 4
                        or family == "IPV6"
                        and ip_address(start).version != 6
                    ):
                        raise ValueError
                    values.append(
                        Endpoint(
                            endpoint_id=key,
                            name=value,
                            kind=EndpointKind.RANGE,
                            ip_ranges=(IpRange(start=start, end=end),),
                        )
                    )
                else:
                    network = ip_network(value, strict=False)
                    if (
                        family == "IPV4"
                        and network.version != 4
                        or family == "IPV6"
                        and network.version != 6
                    ):
                        raise ValueError
                    values.append(
                        Endpoint(
                            endpoint_id=key,
                            name=value,
                            kind=EndpointKind.SUBNET,
                            cidrs=(str(network),),
                        )
                    )
            except ValueError:
                values.append(
                    Endpoint(
                        endpoint_id=key,
                        name=str(value) or "Неизвестный адрес",
                        kind=EndpointKind.OBJECT,
                        resolution_status=DataStatus.UNKNOWN,
                    )
                )

        if (
            ips is not None
            and not isinstance(ips, list)
            or refs is not None
            and not isinstance(refs, list)
        ):
            value = Endpoint(
                endpoint_id=f"{side}:unknown",
                name="Неизвестное адресное условие",
                kind=EndpointKind.OBJECT,
                resolution_status=DataStatus.UNKNOWN,
            )
            endpoints[value.endpoint_id] = value
            return (value,), DataStatus.UNKNOWN
        for index, ip in enumerate(ips or []):
            address(ip, f"{side}:ip:{index}:{ip}")
        for ref in refs or []:
            key = str(ref.get("id", "")) if isinstance(ref, dict) else ""
            group = groups.get(key) if isinstance(groups, dict) else None
            if (
                isinstance(group, dict)
                and key
                and group.get("id") == key
                and group.get("typeValue", group.get("type")) == "IP_SET"
                and isinstance(group.get("ipAddresses"), list)
                and group["ipAddresses"]
                and not group.get("members")
                and not group.get("vmCriteria")
                and not group.get("macAddresses")
                and not group.get("criteria")
            ):
                for index, ip in enumerate(group["ipAddresses"]):
                    address(ip, f"{key}:{index}")
            else:
                values.append(
                    Endpoint(
                        endpoint_id=key or f"{side}:unknown-group",
                        kind=EndpointKind.GROUP,
                        name=str(ref.get("name") or key or "Неизвестная группа")
                        if isinstance(ref, dict)
                        else "Неизвестная группа",
                        resolution_status=DataStatus.UNKNOWN,
                    )
                )
        if not values:
            cidrs = {
                "IPV4": ("0.0.0.0/0",),
                "IPV6": ("::/0",),
                "IPV4_IPV6": ("0.0.0.0/0", "::/0"),
            }.get(family)
            if not cidrs:
                value = Endpoint(
                    endpoint_id=f"{side}:unknown-family",
                    name="Неизвестное семейство IP",
                    kind=EndpointKind.OBJECT,
                    resolution_status=DataStatus.UNKNOWN,
                )
                endpoints[value.endpoint_id] = value
                return (value,), DataStatus.UNKNOWN
            values.append(
                Endpoint(
                    endpoint_id=f"{side}:any:{family}",
                    name="Любой адрес · " + family,
                    kind=EndpointKind.SUBNET,
                    cidrs=cidrs,
                )
            )
        for value in values:
            endpoints[value.endpoint_id] = value
        return tuple(values), (
            DataStatus.KNOWN
            if all(v.resolution_status == DataStatus.KNOWN for v in values)
            else DataStatus.UNKNOWN
        )

    def ports(raw: dict[str, Any]) -> tuple[tuple[Service, ...], DataStatus]:
        entries: list[Any] = []
        unknown = False
        refs, direct = raw.get("applicationPortProfiles"), raw.get("rawPortProtocols")
        if (
            refs is not None
            and not isinstance(refs, list)
            or direct is not None
            and not isinstance(direct, list)
        ):
            unknown = True
            refs, direct = [], []
        for ref in refs or []:
            ref_id = ref.get("id") if isinstance(ref, dict) else None
            profile = (
                profiles.get(ref_id)
                if isinstance(ref_id, str) and isinstance(profiles, dict)
                else None
            )
            if (
                not isinstance(profile, dict)
                or not isinstance(ref, dict)
                or not ref.get("id")
                or profile.get("id") != ref["id"]
                or not isinstance(profile.get("applicationPorts"), list)
                or not profile["applicationPorts"]
            ):
                unknown = True
            else:
                entries.extend(profile["applicationPorts"])
        for entry in direct or []:
            layer = entry.get("layer4Item") if isinstance(entry, dict) else None
            if not isinstance(layer, dict) or set(entry) - {"layer4Item"}:
                unknown = True
            else:
                entries.append(layer)
        values = []
        for entry in entries:
            try:
                if not isinstance(entry, dict) or entry.get("sourcePorts") not in (
                    None,
                    [],
                    ["ANY"],
                ):
                    raise ValueError
                if set(entry) - {"protocol", "sourcePorts", "destinationPorts"}:
                    raise ValueError
                name = str(entry.get("protocol", "")).upper()
                protocols = {
                    "TCP": (Protocol.TCP,),
                    "UDP": (Protocol.UDP,),
                    "TCP_UDP": (Protocol.TCP, Protocol.UDP),
                    "ICMP": (Protocol.ICMP,),
                    "IP": (Protocol.IP,),
                    "ANY": (Protocol.IP,),
                }.get(name)
                if not protocols:
                    raise ValueError
                ranges: list[PortRange] = []
                any_port = False
                destination_ports = entry.get("destinationPorts")
                if destination_ports is not None and not isinstance(destination_ports, list):
                    raise ValueError
                for port in destination_ports or []:
                    if port == "ANY":
                        any_port = True
                        continue
                    start, _, end = str(port).partition("-")
                    ranges.append(PortRange(start=int(start), end=int(end or start)))
                if any_port:
                    ranges = []
                if ranges and any(
                    protocol in (Protocol.IP, Protocol.ICMP) for protocol in protocols
                ):
                    raise ValueError
                for protocol in protocols:
                    values.append(
                        Service(
                            service_id="service:"
                            + sha256(
                                json.dumps(
                                    [protocol.value, destination_ports], sort_keys=True
                                ).encode()
                            ).hexdigest()[:24],
                            name=f"{protocol} "
                            + (str(destination_ports) if destination_ports else "любые порты"),
                            protocol=protocol,
                            port_ranges=tuple(ranges),
                        )
                    )
            except ValueError:
                unknown = True
        if not entries and not refs and not direct and not unknown:
            values.append(
                Service(service_id="service:any", name="Любой сервис", protocol=Protocol.IP)
            )
        if unknown:
            values.append(
                Service(
                    service_id="service:unknown",
                    name="Неразрешённый сервис",
                    protocol=Protocol.OTHER,
                    resolution_status=DataStatus.UNKNOWN,
                )
            )
        for value in values:
            services[value.service_id + ":" + value.name] = value
        return tuple(values), DataStatus.UNKNOWN if unknown else DataStatus.KNOWN

    rules: list[Rule] = []
    malformed = 0
    rule_ids: set[str] = set()
    directions = set()
    for section in ("systemRules", "userDefinedRules", "defaultRules"):
        raw_rules = firewall.get(section)
        if raw_rules is None:
            continue
        malformed_section = not isinstance(raw_rules, list)
        if malformed_section:
            raw_rules = [None]
        for index, raw in enumerate(raw_rules):
            malformed_rule = not isinstance(raw, dict)
            if not isinstance(raw, dict):
                raw = {}
                malformed += 1
            raw_id = str(raw.get("id") or index)
            rule_id = f"{device_id}:{section}:{raw_id}"
            duplicate_id = rule_id in rule_ids
            while rule_id in rule_ids:
                rule_id += f":occurrence:{index}"
            location = SourceLocation(
                source_name=source_name,
                object_id=raw_id,
                object_path=f"/result/records/{record_index}/data/firewall/{section}"
                + ("" if malformed_section else f"/{index}"),
            )
            if malformed_rule:
                issue("Некорректное правило сохранено как неизвестное условие.", location)
            if duplicate_id:
                issue("Повторяющийся идентификатор правила; сохранены все вхождения.", location)
            rule_ids.add(rule_id)
            family = str(raw.get("ipProtocol") or "").upper()
            source, source_status = addresses(raw, "source", family)
            destination, destination_status = addresses(raw, "destination", family)
            service, service_status = ports(raw)
            direction: Literal["in", "out", "global"] | None = {
                "IN": "in",
                "OUT": "out",
                "IN_OUT": "global",
            }.get(str(raw.get("direction")))  # type: ignore[assignment]
            enabled = raw.get("active", raw.get("enabled"))
            action = {
                "ALLOW": RuleAction.ALLOW,
                "DROP": RuleAction.DROP,
                "REJECT": RuleAction.REJECT,
                "DENY": RuleAction.DENY,
            }.get(str(raw.get("actionValue", raw.get("action", ""))).upper(), RuleAction.UNKNOWN)
            known = all(
                s == DataStatus.KNOWN for s in (source_status, destination_status, service_status)
            )
            if (
                direction is None
                or type(enabled) is not bool
                or action == RuleAction.UNKNOWN
                or family not in {"IPV4", "IPV6", "IPV4_IPV6"}
                or any(
                    raw.get(key)
                    for key in (
                        "networkContextProfiles",
                        "appliedTo",
                        "sourceGroupsExcluded",
                        "destinationGroupsExcluded",
                    )
                )
            ):
                known = False
            if type(enabled) is not bool:
                action = RuleAction.UNKNOWN
            if not known:
                reasons = [
                    label
                    for status, label in (
                        (source_status, "адреса / группы источника"),
                        (destination_status, "адреса / группы назначения"),
                        (service_status, "сервисы / порты"),
                    )
                    if status != DataStatus.KNOWN
                ]
                if direction is None:
                    reasons.append("направление")
                if type(enabled) is not bool:
                    reasons.append("состояние правила")
                if action == RuleAction.UNKNOWN:
                    reasons.append("действие")
                if family not in {"IPV4", "IPV6", "IPV4_IPV6"}:
                    reasons.append("семейство IP")
                if any(
                    raw.get(key)
                    for key in (
                        "networkContextProfiles",
                        "appliedTo",
                        "sourceGroupsExcluded",
                        "destinationGroupsExcluded",
                    )
                ):
                    reasons.append("L7, область применения или исключения групп")
                issue(
                    "Не разрешены: " + ", ".join(reasons) + ". Попарные выводы ограничены.",
                    location,
                )
            description_values = [raw[key] for key in ("comments", "description") if key in raw]
            invalid_description = any(
                value is not None and not isinstance(value, str) for value in description_values
            )
            description = next(
                (value for value in description_values if isinstance(value, str) and value.strip()),
                None,
            )
            if invalid_description:
                issue("Некорректный формат комментария; наличие комментария неизвестно.", location)
            logging = raw.get("logging")
            rules.append(
                Rule(
                    rule_id=rule_id,
                    configuration_id=config_id,
                    sequence=len(rules) + 1,
                    name=str(raw.get("name") or raw_id),
                    action=action,
                    enabled=enabled is not False,
                    sources=source,
                    destinations=destination,
                    services=service,
                    source_status=source_status,
                    destination_status=destination_status,
                    service_status=service_status,
                    match_status=DataStatus.KNOWN if known else DataStatus.UNKNOWN,
                    logging_enabled=logging if type(logging) is bool else None,
                    logging_status=DataStatus.KNOWN
                    if type(logging) is bool
                    else DataStatus.UNKNOWN,
                    description=description if isinstance(description, str) else None,
                    description_status=(
                        DataStatus.UNKNOWN
                        if invalid_description
                        else DataStatus.KNOWN
                        if isinstance(description, str) and description.strip()
                        else DataStatus.ABSENT
                        if any(k in raw for k in ("comments", "description"))
                        else DataStatus.UNKNOWN
                    ),
                    policy_id=record["id"],
                    policy_direction=direction,
                    policy_semantics="first_match",
                    zone_status=DataStatus.KNOWN if direction is not None else DataStatus.UNKNOWN,
                    source_location=location,
                )
            )
            directions.add(direction)
    if "global" in directions and len(directions) > 1:
        issue(
            "Смешанные IN/OUT/IN_OUT: взаимное перекрытие направлений не вычисляется.",
            SourceLocation(source_name=source_name, object_path="/data/firewall"),
        )
    parsed = ParseResult(
        configuration=configuration,
        rules=tuple(rules),
        endpoints=tuple(endpoints.values()),
        services=tuple(services.values()),
        warnings=tuple(issues),
        source_map={rule.rule_id: rule.source_location for rule in rules},
        coverage=ParseCoverage(
            discovered_constructs=len(rules),
            recognized_constructs=len(rules) - malformed,
            unsupported_constructs=malformed,
        ),
    )
    return DeviceRevision(
        revision_id=uuid5(NAMESPACE_URL, f"{config_id}/{ADAPTER_VERSION}"),
        device=Device(
            device_id=device_id,
            vendor="vmware",
            platform=configuration.platform,
            hostname=str(record.get("name") or record["id"]),
        ),
        parse_result=parsed,
        sources=(
            RevisionSource(
                source_document_id=source_id,
                source_name=source_name,
                content_sha256=digest,
                kind=SourceDocumentKind.CONFIGURATION,
                captured_at=captured,
            ),
        ),
        application_version=application_version,
        imported_at=imported,
    )
