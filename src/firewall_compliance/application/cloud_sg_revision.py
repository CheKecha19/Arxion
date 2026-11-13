"""Проекция выбранной группы безопасности и её интерфейса для матрицы."""

from collections import defaultdict
from datetime import UTC, datetime
from ipaddress import ip_interface, ip_network
from typing import Any, Literal, Self
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from firewall_compliance import __version__
from firewall_compliance.application.cloud_sg_policy import (
    ADVANCED_MULTI_ORDERED_PROJECTION, ADVANCED_ORDERED_PROJECTION, CloudSGOrderEvidence,
    advanced_multi_configuration_id, advanced_rule_order,
)
from firewall_compliance.domain.cloud_security_groups import (
    CloudSecurityGroupSnapshot, CloudSGDeclaration, CloudSGInterface, CloudSGRule, SGDirection,
)
from firewall_compliance.domain.configuration import Configuration, Device, Rule
from firewall_compliance.domain.controls import ControlModel
from firewall_compliance.domain.enums import DataStatus, EndpointKind, Protocol, RuleAction, SourceDocumentKind
from firewall_compliance.domain.network import Endpoint, Service
from firewall_compliance.domain.observation import ObservationEvidence
from firewall_compliance.domain.parse_result import ParseCoverage, ParseResult, UnsupportedConstruct
from firewall_compliance.domain.revision import DeviceRevision, RevisionSource
from firewall_compliance.domain.source import SourceLocation


class CloudSGSelection(ControlModel):
    scan_id: str = Field(min_length=1)
    group_id: str | None = Field(default=None, min_length=1)
    interface_id: str = Field(min_length=1)
    scope_id: str = Field(min_length=1)
    direction: SGDirection
    family: Literal[4, 6]
    order_evidence: CloudSGOrderEvidence | None = None

    @model_validator(mode="after")
    def validate_order_selection(self) -> Self:
        order = self.order_evidence
        if order is not None and (
            self.group_id is not None or self.direction != "ingress"
            or (order.scan_id, order.scope_id, order.interface_id) != (self.scan_id, self.scope_id, self.interface_id)
        ):
            raise ValueError("Наблюдённый порядок относится к входящей сверке всех групп выбранного интерфейса")
        return self

    @model_serializer(mode="wrap")
    def serialize_order(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        if self.order_evidence is None:
            payload.pop("order_evidence", None)
        return payload


def cloud_sg_policy_id(scope_id: str, group_key: str, direction: SGDirection, family: Literal[4, 6]) -> str:
    return f"sg:{uuid5(NAMESPACE_URL, scope_id + '/' + group_key).hex}:{direction}:ipv{family}"


class CloudSGRevisionProjector:
    """Подготовить поиск интерфейсов и групп для нескольких проекций одного сбора."""

    def __init__(self, snapshot: CloudSecurityGroupSnapshot) -> None:
        self._snapshot = snapshot
        self._interfaces: dict[str, list[CloudSGInterface]] = defaultdict(list)
        self._groups: dict[tuple[str, str], list[CloudSGDeclaration]] = defaultdict(list)
        for interface in snapshot.interfaces:
            self._interfaces[interface.interface_id].append(interface)
        for group in snapshot.groups:
            self._groups[(group.scope_id, group.group_id)].append(group)

    def project(self, selection: CloudSGSelection, *, imported_at: datetime) -> DeviceRevision:
        return _cloud_sg_revision(self._snapshot, selection, self._interfaces, self._groups, imported_at=imported_at)


def _service(rule: CloudSGRule, identifier: str) -> Service | None:
    value = rule.service
    if value is None:
        return None
    if value.protocol in {"tcp", "udp"}:
        if not value.ports and not value.any_ports:
            return None
        protocol = Protocol(value.protocol)
    elif value.protocol == "any":
        protocol = Protocol.IP
    elif value.protocol == "icmp" and value.icmp_type is None and value.icmp_code is None:
        protocol = Protocol.ICMP
    else:
        return None
    return Service(
        service_id=identifier, name=value.protocol, protocol=protocol, port_ranges=value.ports,
    )


def _ordered_rule(rule: CloudSGRule, selection: CloudSGSelection) -> bool:
    return (
        rule.direction == selection.direction and rule.family == selection.family
        and rule.priority is not None and rule.action in {"allow", "deny"}
        and rule.enabled is not None and rule.provider_status is None
        and rule.peer.kind == "network" and rule.peer.cidr is not None
        and ip_network(rule.peer.cidr).version == selection.family
        and _service(rule, "validation") is not None
    )


def _selected_group_ids(
    snapshot: CloudSecurityGroupSnapshot, selection: CloudSGSelection, interface: CloudSGInterface,
) -> set[str]:
    if selection.group_id is not None:
        if not any(item.group_id == selection.group_id and item.state == "present" for item in interface.assignments):
            raise ValueError("В сборе отсутствует однозначная привязка группы к интерфейсу")
        return {selection.group_id}
    if any(item.state != "present" for item in interface.assignments):
        raise ValueError("Для сверки всех групп нужен подтверждённый состав назначений")
    attached = {item.group_id for item in interface.assignments}
    order = selection.order_evidence
    if snapshot.platform == "evolution":
        if order is not None:
            raise ValueError("Наблюдённая очередность групп применяется только в Cloud.ru Advanced")
        return attached
    if order is None:
        raise ValueError("Для входящей сверки всех групп Advanced нужен наблюдённый порядок")
    if (
        order.snapshot_sha256 != snapshot.source_sha256 or order.scope_id != snapshot.scope_id
        or order.observed_at != snapshot.captured_at
    ):
        raise ValueError("Наблюдённый порядок должен совпадать с областью, SHA-256 и временем сохранённого сбора")
    if len(attached) != len(interface.assignments) or attached != set(order.group_ids):
        raise ValueError("Наблюдённый порядок должен перечислять все назначенные группы интерфейса")
    return attached


def cloud_sg_revision(
    snapshot: CloudSecurityGroupSnapshot, selection: CloudSGSelection, *, imported_at: datetime,
) -> DeviceRevision:
    """Построить условия выбранной SG или всех подтверждённых групп интерфейса."""
    return CloudSGRevisionProjector(snapshot).project(selection, imported_at=imported_at)


def _cloud_sg_revision(
    snapshot: CloudSecurityGroupSnapshot, selection: CloudSGSelection,
    interfaces_by_id: dict[str, list[CloudSGInterface]],
    declarations: dict[tuple[str, str], list[CloudSGDeclaration]],
    *, imported_at: datetime,
) -> DeviceRevision:
    if selection.scan_id != snapshot.scan_id:
        raise ValueError("Выбранный интерфейс относится к другому сбору")
    if snapshot.platform == "evolution" and selection.family != 4:
        raise ValueError("В этой проекции Evolution поддерживается IPv4")
    interfaces = interfaces_by_id.get(selection.interface_id, ())
    if len(interfaces) != 1:
        raise ValueError("Не удалось однозначно определить интерфейс")
    interface = interfaces[0]
    if interface.scope_id != selection.scope_id or interface.assignments_status != "present":
        raise ValueError("В сборе отсутствует подтверждённый состав назначений интерфейса")
    selected_ids = _selected_group_ids(snapshot, selection, interface)
    groups = [item for group_id in sorted(selected_ids)
              for item in declarations.get((selection.scope_id, group_id), ())]
    if not groups or len(groups) != len(selected_ids) or {item.group_id for item in groups} != selected_ids:
        raise ValueError("Не удалось однозначно определить объявления групп интерфейса")
    group_key = selection.group_id or "interface/" + interface.interface_id
    group_label = (groups[0].name or groups[0].group_id) if selection.group_id is not None else "Все группы интерфейса"
    if interface.security_enabled is False:
        raise ValueError("В сохранённом сборе фильтрация интерфейса отключена")
    addresses = tuple(sorted({
        f"{address.ip}/{address.max_prefixlen}"
        for raw in interface.addresses
        if (address := ip_interface(raw)).version == selection.family
    }))
    if not addresses:
        raise ValueError("У интерфейса нет подтверждённых адресов выбранного семейства")
    if imported_at.utcoffset() is None:
        raise ValueError("Время формирования ревизии должно содержать часовой пояс")
    captured = snapshot.captured_at
    if captured.utcoffset() is None:
        raise ValueError("Время сбора должно содержать часовой пояс")
    imported_at = max(imported_at, captured).astimezone(UTC)
    platform = "cloud-ru-" + snapshot.platform + "-sg"
    group_rules = (
        (group, declaration)
        for group in sorted(groups, key=lambda item: item.group_id) for declaration in group.rules
    )
    selected_rules = tuple(
        (index, group, rule) for index, (group, rule) in enumerate(group_rules)
        if rule.direction in (None, selection.direction) and rule.family in (None, selection.family)
    )
    order = selection.order_evidence
    ordered = (
        snapshot.platform == "advanced" and snapshot.rule_semantics == "advanced_priority"
        and snapshot.scan_status == "completed" and interface.security_enabled is True
        and len(interface.assignments) == len(groups)
        and all(item.locations for item in interface.assignments)
        and bool(interface.locations)
        and all(group.locations and group.rules_status == "present" for group in groups)
        and any(rule.enabled is True for _, _, rule in selected_rules)
        and all(_ordered_rule(rule, selection) for _, _, rule in selected_rules)
    )
    if order is not None and not ordered:
        raise ValueError(
            "Для входящей сверки всех групп Advanced нужны завершённый сбор, включённая защита порта "
            "и известные условия, состояния, действия и приоритеты всех применимых правил"
        )
    parser_version = (
        ADVANCED_MULTI_ORDERED_PROJECTION if order is not None
        else ADVANCED_ORDERED_PROJECTION if ordered else "sg-1.0.0"
    )
    stable_selection = selection.model_dump_json(exclude={"scan_id", "order_evidence"})
    identity = uuid5(NAMESPACE_URL, f"{platform}/{snapshot.scope_id}/{stable_selection}")
    config_key = f"{snapshot.scan_id}/{snapshot.source_sha256}"
    config_id = (
        advanced_multi_configuration_id(identity, order) if order is not None
        else uuid5(identity, f"{config_key}/{parser_version}" if ordered else config_key)
    )
    source_name = f"Cloud.ru {snapshot.platform} / {snapshot.scan_id} / SG {group_key}"
    configuration = Configuration(
        configuration_id=config_id, source_name=source_name, device_id=str(identity), vendor="cloud-ru",
        platform=platform, parser_version=parser_version, content_sha256=snapshot.source_sha256,
        captured_at=captured, imported_at=imported_at,
    )
    local = Endpoint(
        endpoint_id=f"interface:{interface.interface_id}", name=interface.name or interface.interface_id,
        kind=EndpointKind.OBJECT, cidrs=addresses,
    )
    endpoints = [local]
    services = []
    rules = []
    unsupported = []
    policy = cloud_sg_policy_id(snapshot.scope_id, group_key, selection.direction, selection.family)
    ingress = selection.direction == "ingress"
    group_positions = {identifier: index for index, identifier in enumerate(order.group_ids)} if order else {}
    for index, group, declaration in selected_rules:
        rule_key = declaration.rule_id or declaration.location.object_path
        if selection.group_id is None:
            rule_key = f"{group.group_id}/{rule_key}"
        identifier = str(uuid5(identity, f"rule/{rule_key}/{index}"))
        location = declaration.location.model_copy(update={"source_name": source_name})
        remote = None
        if declaration.peer.kind == "network" and declaration.peer.cidr is not None:
            remote = Endpoint(
                endpoint_id=f"peer:{identifier}", name=declaration.peer.cidr,
                kind=EndpointKind.SUBNET, cidrs=(declaration.peer.cidr,),
            )
            endpoints.append(remote)
        service = _service(declaration, identifier)
        if service is not None:
            services.append(service)
        known = (
            declaration.direction is not None and declaration.family is not None
            and declaration.action != "unknown"
            and remote is not None and service is not None
        )
        if not known:
            unsupported.append(UnsupportedConstruct(
                construct_type="cloud_security_group_rule", source_location=location,
                message="Условие группы безопасности требует дополнительных сведений или семантики платформы",
            ))
        peer = (remote,) if remote is not None else ()
        peer_status = DataStatus.KNOWN if remote is not None else DataStatus.UNKNOWN
        action = RuleAction(declaration.action)
        rules.append(Rule(
            rule_id=identifier, configuration_id=config_id, name=declaration.rule_id or f"SG {index + 1}",
            sequence=advanced_rule_order(declaration.priority, action, group_position=group_positions.get(group.group_id, 0))
            if ordered and declaration.priority is not None else index + 1,
            action=action, enabled=declaration.enabled is not False,
            sources=peer if ingress else (local,), destinations=(local,) if ingress else peer,
            source_status=peer_status if ingress else DataStatus.KNOWN,
            destination_status=DataStatus.KNOWN if ingress else peer_status,
            services=(service,) if service is not None else (),
            service_status=DataStatus.KNOWN if service is not None else DataStatus.UNKNOWN,
            policy_id=policy, policy_direction="in" if ingress else "out", zone_status=DataStatus.KNOWN,
            policy_semantics="first_match" if ordered else None,
            match_status=DataStatus.KNOWN if known else DataStatus.UNKNOWN, source_location=location,
        ))
    unknown_rules = len(unsupported)
    for group in groups:
        if group.rules_status != "present" or snapshot.scan_status != "completed":
            unsupported.append(UnsupportedConstruct(
                construct_type="cloud_security_group_coverage",
                source_location=group.locations[0].model_copy(update={"source_name": source_name}),
                message="Полнота списка правил группы или исходного сбора не подтверждена",
            ))
    if snapshot.platform == "advanced" and interface.security_enabled is None:
        unsupported.append(UnsupportedConstruct(
            construct_type="cloud_interface_security_state",
            source_location=interface.locations[0].model_copy(update={"source_name": source_name}),
            message="В сохранённых данных нет явного состояния фильтрации интерфейса",
        ))
    source_map = {rule.rule_id: rule.source_location for rule in rules}
    source_map.update({
        f"sg-interface:{index}": location.model_copy(update={"source_name": source_name})
        for index, location in enumerate(interface.locations)
    })
    if ordered:
        for key, locations in (
            ("sg-assignment", tuple(loc for item in interface.assignments for loc in item.locations)),
            ("sg-group", tuple(loc for group in groups for loc in group.locations)),
        ):
            source_map.update({
                f"{key}:{index}": location.model_copy(update={"source_name": source_name})
                for index, location in enumerate(locations)
            })
    revision_sources = [RevisionSource(
        source_document_id=uuid5(config_id, "source"), source_name=source_name,
        content_sha256=snapshot.source_sha256, kind=SourceDocumentKind.CONFIGURATION, captured_at=captured,
    )]
    if order is not None:
        source_map["sg-order-observation"] = SourceLocation(
            source_name=order.source_name, object_path=order.source_reference, object_id=order.scan_id,
        )
        source_map.update({
            f"sg-order:{index}": SourceLocation(
                source_name=order.source_name, object_path=f"/group_ids/{index}", object_id=identifier,
            )
            for index, identifier in enumerate(order.group_ids)
        })
        revision_sources.append(RevisionSource(
            source_document_id=uuid5(config_id, "group-order"), source_name=order.source_name,
            content_sha256=order.evidence_sha256, kind=SourceDocumentKind.CONFIGURATION,
            captured_at=order.observed_at,
            observation=ObservationEvidence(
                observed_at=order.observed_at, method="operator_declared", reference=order.source_reference,
            ),
        ))
    parsed = ParseResult(
        configuration=configuration, rules=tuple(rules), endpoints=tuple(endpoints), services=tuple(services),
        unsupported_constructs=tuple(unsupported), source_map=source_map,
        coverage=ParseCoverage(
            discovered_constructs=len(rules) + len(unsupported) - unknown_rules,
            recognized_constructs=len(rules) - unknown_rules, unsupported_constructs=len(unsupported),
        ),
    )
    return DeviceRevision(
        revision_id=uuid5(config_id, "revision"),
        device=Device(
            device_id=str(identity), vendor=configuration.vendor, platform=platform,
            hostname=f"{group_label} / {interface.name or interface.interface_id}",
            context=snapshot.scope_id,
        ),
        parse_result=parsed, sources=tuple(revision_sources),
        application_version=__version__, imported_at=imported_at,
    )
