"""Ограниченный разбор сетевых настроек HP/Aruba и Comware без runtime-догадок."""

import re
import shlex
from ipaddress import ip_address, ip_interface, ip_network
from typing import Literal

from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.domain.switch_facts import (
    SwitchAddress,
    SwitchAggregate,
    SwitchAreaCoverage,
    SwitchFactIssue,
    SwitchFacts,
    SwitchFeature,
    SwitchHardware,
    SwitchInterface,
    SwitchManagementFact,
    SwitchRoute,
    SwitchStackMember,
    SwitchVlan,
)
from firewall_compliance.parsers.contracts import SourceDocument
from firewall_compliance.parsers.platform_detection import detect_switch_platform


def _ports(expression: str) -> tuple[str, ...]:
    """Раскрыть ограниченные диапазоны HP; неизвестную форму сохранить целиком."""
    result: list[str] = []
    for part in expression.split(","):
        match = re.fullmatch(r"(\d+/)(\d+)-(?:\1)?(\d+)", part)
        if match and 0 <= int(match[3]) - int(match[2]) <= 4094:
            result.extend(f"{match[1]}{number}" for number in range(int(match[2]), int(match[3]) + 1))
        else:
            result.append(part)
    return tuple(result)


def _member(name: str) -> str | None:
    match = re.search(r"(?:Ethernet|FortyGigE)?(\d+)/\d+(?:/\d+)?$", name, re.I)
    return match[1] if match else None


class _Collector:
    """Собирать только перечисленные безопасные параметры, без хранения raw-команд."""

    def __init__(self, source: SourceDocument, platform: str) -> None:
        self.source = source
        self.platform = platform
        self.interfaces: dict[str, SwitchInterface] = {}
        self.vlans: dict[int, SwitchVlan] = {}
        self.aggregates: dict[str, SwitchAggregate] = {}
        self.stack: dict[str, SwitchStackMember] = {}
        self.hardware: list[SwitchHardware] = []
        self.routes: list[SwitchRoute] = []
        self.management: list[SwitchManagementFact] = []
        self.features: list[SwitchFeature] = []
        self.issues: list[SwitchFactIssue] = []
        self.locations: list[SourceLocation] = []
        self.hostname: str | None = None
        self.version: str | None = None
        self.family: str | None = None
        self.reasons: tuple[str, ...] = ()
        self.context: tuple[str, str] | None = None
        self.oobm_member: str | None = None

    def location(self, line: int) -> SourceLocation:
        return SourceLocation(source_name=self.source.source_name, line_start=line)

    def issue(self, area: str, line: int, message: str, code: str = "SWITCH_FACT_UNSUPPORTED") -> None:
        self.issues.append(SwitchFactIssue(code=code, area=area, message=message,
                                           source_location=self.location(line)))

    def interface(self, name: str, line: int) -> SwitchInterface:
        if name not in self.interfaces:
            lowered = name.lower()
            kind = ("management" if lowered.startswith(("mgmt", "oobm", "m-gigabit")) else
                    "vlan" if lowered.startswith(("vlan", "vlan-interface")) else
                    "aggregate" if lowered.startswith(("lag ", "trk", "bridge-aggregation")) else
                    "null" if lowered.startswith("null") else "physical")
            self.interfaces[name] = SwitchInterface(
                name=name, kind=kind, stack_member=_member(name),
                vrf="mgmt" if lowered.startswith(("mgmt", "oobm")) else "default",
                source_locations=(self.location(line),),
            )
        item = self.interfaces[name]
        loc = self.location(line)
        if loc not in item.source_locations:
            item.source_locations += (loc,)
        return item

    def aggregate(self, name: str, line: int) -> SwitchAggregate:
        if name not in self.aggregates:
            self.aggregates[name] = SwitchAggregate(name=name, source_locations=(self.location(line),))
        item = self.aggregates[name]
        if self.location(line) not in item.source_locations:
            item.source_locations += (self.location(line),)
        return item

    def vlan(self, number: int, line: int) -> SwitchVlan:
        if number not in self.vlans:
            self.vlans[number] = SwitchVlan(vlan_id=number, source_locations=(self.location(line),))
        item = self.vlans[number]
        if self.location(line) not in item.source_locations:
            item.source_locations += (self.location(line),)
        return item

    def stack_member(self, member: str, system: Literal["stacking", "irf", "vsf"],
                     line: int) -> SwitchStackMember:
        if member not in self.stack:
            self.stack[member] = SwitchStackMember(
                member=member, system=system, source_locations=(self.location(line),),
            )
        item = self.stack[member]
        if self.location(line) not in item.source_locations:
            item.source_locations += (self.location(line),)
        return item

    def address(self, raw: str, line: int) -> SwitchAddress:
        try:
            if "/" not in raw:
                raise ValueError("маска не задана")
            value = str(ip_interface(raw))
            return SwitchAddress(raw=raw, cidr=value, source_locations=(self.location(line),))
        except ValueError:
            self.issue("interfaces", line, "Некорректный IP-адрес интерфейса; запись не исправлена.",
                       "SWITCH_ADDRESS_INVALID")
            return SwitchAddress(raw=raw, status="unknown", source_locations=(self.location(line),))

    def host(self, raw: str, line: int, area: str) -> str | None:
        try:
            return str(ip_address(raw))
        except ValueError:
            self.issue(area, line, "Некорректный адрес; значение не исправлено.", "SWITCH_ADDRESS_INVALID")
            return None

    def management_host(self, service: str, raw: str, line: int, vrf: str | None = None) -> None:
        address = self.host(raw, line, "management")
        self.management.append(SwitchManagementFact(
            kind="server", service=service, vrf=vrf, address=address, raw_address=raw,
            subject=":".join(self.context) if self.context and self.context[0] == "radius" else None,
            status="known" if address else "unknown", source_locations=(self.location(line),),
        ))

    def feature(self, name: str, line: int, value: str | None = None,
                enabled: bool | None = None) -> None:
        scope = ":".join(self.context) if self.context else "global"
        self.features.append(SwitchFeature(name=name, scope=scope, value=value, enabled=enabled,
                                           source_locations=(self.location(line),)))

    def management_value(self, kind: str, service: str, line: int, value: str | None = None,
                         vrf: str | None = None, enabled: bool | None = None) -> None:
        subject = ":".join(self.context) if self.context else None
        self.management.append(SwitchManagementFact(
            kind=kind, service=service, subject=subject,
            value=value, vrf=vrf, enabled=enabled,
            source_locations=(self.location(line),),
        ))

    def route(self, prefix: str | None, next_hop: str, line: int, vrf: str | None = None,
              kind: Literal["static", "management_gateway"] = "static",
              parameters: tuple[str, ...] = ()) -> None:
        normalized = None
        if prefix is not None:
            try:
                normalized = str(ip_network(prefix, strict=False))
            except ValueError:
                self.issue("routes", line, "Некорректный префикс маршрута.", "SWITCH_ROUTE_INVALID")
        hop = self.host(next_hop, line, "routes")
        self.routes.append(SwitchRoute(
            kind=kind, prefix=normalized, next_hop=hop, raw_prefix=prefix, raw_next_hop=next_hop,
            vrf=vrf, status="known" if hop and (prefix is None or normalized) else "unknown",
            parameters=parameters, source_locations=(self.location(line),),
        ))

    def consume(self, raw: str, line: int) -> None:
        stripped = raw.strip()
        if not stripped:
            return
        header = re.search(r"(?i)(?:version\s+ArubaOS-CX\s+|created on release\s+#?)([^\s;]+)", stripped)
        if header:
            self.version = header[1]
            self.locations.append(self.location(line))
        if stripped.startswith(("!", ";")):
            return
        if stripped == "#":
            self.context = None
            return
        try:
            words = shlex.split(stripped, posix=True)
        except ValueError:
            self.issue("identification", line, "Незакрытая кавычка; строка не разобрана.")
            return
        if not words:
            return
        self._consume(words, raw, line)

    def _consume(self, words: list[str], raw: str, line: int) -> None:
        if words[0] in {"hostname", "sysname"} and len(words) == 2:
            self.hostname = words[1]
            self.locations.append(self.location(line))
            self.context = None
            return
        if words[0] == "version" and len(words) > 1:
            self.version = " ".join(words[1:])
            self.locations.append(self.location(line))
            return
        if words[0] in {"exit", "quit", "return"}:
            if self.context and self.context[0] == "oobm" and self.oobm_member:
                self.oobm_member = None
            else:
                self.context = None
            return
        if words[0] == "interface" and len(words) >= 2:
            name = " ".join(words[1:])
            self.context = ("interface", name)
            item = self.interface(name, line)
            if item.kind == "aggregate":
                self.aggregate(name, line)
            return
        if words[0] == "vlan" and len(words) == 2 and words[1].isdigit():
            number = int(words[1])
            if 1 <= number <= 4094:
                self.vlan(number, line)
                self.context = ("vlan", words[1])
            else:
                self.issue("vlans", line, "VLAN ID вне поддержанного диапазона.")
            return
        if words[0] == "stacking":
            self.context = ("stacking", "global")
            return
        if words[0] == "oobm":
            self.context = ("oobm", "global")
            self.interface("oobm", line)
            return
        if words[:2] == ["vsf", "member"] and len(words) == 3:
            self.context = ("vsf", words[2])
            self.stack_member(words[2], "vsf", line)
            return
        if words[0] == "irf-port" and len(words) == 2:
            self.context = ("irf", words[1])
            self.stack_member(words[1].split("/")[0], "irf", line)
            return
        if words[:2] == ["irf", "member"] and len(words) >= 5 and words[3] == "priority":
            if words[4].isdigit():
                self.stack_member(words[2], "irf", line).priority = int(words[4])
            return
        if words[:2] == ["radius", "scheme"] and len(words) == 3:
            self.context = ("radius", words[2])
            return
        if words[0] == "domain" and len(words) == 2:
            self.context = ("domain", words[1])
            return
        if len(words) > 1 and (
            words[0] == "local-user"
            or words[0] == "user" and self.platform == "aos-cx"
            and not raw[:1].isspace()
        ):
            self.context = ("account", f"account-line:{line}")
            # AOS-CX roles appear inline; never retain account name/password tokens.
            if "group" in words:
                index = words.index("group")
                if index + 1 < len(words):
                    self.management_value("local_role", "local", line, words[index + 1])
            return
        if words[:2] == ["snmp-server", "community"]:
            self.context = ("community", f"community-line:{line}")
            if "unrestricted" in words:
                self.management_value("community_access", "snmp", line, "rw")
            return
        if words[0] in {"line", "user-interface"}:
            self.context = ("terminal", " ".join(words[1:]))
            return
        if words[0] == "cli-session":
            self.context = ("terminal", "cli-session")
            return
        if words[0] == "trunk" and len(words) >= 4 and self.platform == "aos-switch":
            name = words[2].capitalize() if words[2].lower().startswith("trk") else words[2]
            agg = self.aggregate(name, line)
            agg.members = _ports(words[1])
            agg.lacp = "lacp" if words[3] == "lacp" else "unknown"
            for port in agg.members:
                self.interface(port, line).aggregate = name
            return
        # A non-indented global command ends a nested AOS-CX block.
        if not raw[:1].isspace() and words[0] not in {"member", "type", "link"}:
            self.context = None
        if self._nested(words, line):
            return
        self._global(words, line)

    def _nested(self, words: list[str], line: int) -> bool:
        if self.context is None:
            return False
        kind, name = self.context
        command = " ".join(words)
        if kind == "stacking" and words[0] == "member" and len(words) >= 4:
            item = self.stack_member(words[1], "stacking", line)
            if words[2] == "priority" and words[3].isdigit():
                item.priority = int(words[3])
            elif words[2] == "type":
                item.hardware_type = words[3]
                self.hardware.append(SwitchHardware(model=words[3], member=words[1], origin="hardware_type",
                                                     source_locations=(self.location(line),)))
            return True
        if kind == "vsf":
            item = self.stack_member(name, "vsf", line)
            if words[0] == "type" and len(words) == 2:
                item.hardware_type = words[1]
                self.hardware.append(SwitchHardware(model=words[1], member=name, origin="hardware_type",
                                                     source_locations=(self.location(line),)))
                return True
            if words[0] == "link" and len(words) >= 3:
                item.links += (words[2],)
                return True
        if kind == "irf" and words[:3] == ["port", "group", "interface"] and len(words) >= 4:
            self.stack_member(name.split("/")[0], "irf", line).links += (words[3],)
            return True
        if kind == "oobm":
            if words[0] == "member" and len(words) == 2:
                self.oobm_member = words[1]
                return True
            target = f"oobm member {self.oobm_member}" if self.oobm_member else "oobm"
            if words[:2] == ["ip", "address"]:
                return self._interface(words, self.interface(target, line), line)
        if kind == "interface":
            return self._interface(words, self.interface(name, line), line)
        if kind == "vlan":
            item = self.vlan(int(name), line)
            if words[0] == "name" and len(words) > 1:
                item.name = " ".join(words[1:])
                return True
            if words[0] == "description":
                item.description = " ".join(words[1:])
                return True
            if words[0] in {"tagged", "untagged"} and len(words) == 2:
                ports = _ports(words[1])
                if words[0] == "tagged":
                    item.tagged_interfaces += ports
                else:
                    item.untagged_interfaces += ports
                for port in ports:
                    interface = self.interface(port, line)
                    interface.mode = "l2"
                    if words[0] == "tagged":
                        interface.tagged_vlans += (int(name),)
                    else:
                        interface.untagged_vlans += (int(name),)
                return True
            if words[:2] == ["ip", "address"]:
                return self._interface(words, self.interface(f"vlan {name}", line), line)
            if any(words[0].startswith(prefix) for prefix in ("igmp", "pim")):
                self.feature(words[0], line, " ".join(words[1:]) or None, "enable" in words)
                return True
        if kind == "community":
            if words[0] == "access-level" and len(words) == 2:
                self.management_value("community_access", "snmp", line, words[1])
                return True
            if words[:2] == ["access-list", "ipv4"] and len(words) == 3:
                self.management_value("community_acl", "snmp", line, words[2])
                return True
        if kind == "radius" and words[:2] in (["primary", "authentication"], ["primary", "accounting"]):
            if len(words) >= 3:
                self.management_host(f"radius-{words[1]}", words[2], line)
            return True
        if kind in {"domain", "terminal"} and words[0] in {"authentication", "authorization", "accounting"}:
            if "password" not in words and "key" not in words:
                self.management_value("aaa", kind, line, command)
            return True
        if kind == "account" and words[0] in {"authorization-attribute", "service-type"}:
            if words[0] == "authorization-attribute" and words[1:2] not in (["user-role"], ["level"]):
                return False
            if any(word in words for word in ("password", "cipher", "ciphertext", "hash", "key")):
                return False
            self.management_value("local_role" if words[0] == "authorization-attribute" else "local_service",
                                  "local", line, " ".join(words[1:]))
            return True
        if kind == "terminal" and words[0] in {"user-role", "user", "protocol", "timeout", "idle-timeout"}:
            if not any(word in words for word in ("password", "cipher", "ciphertext", "hash")):
                self.management_value("terminal", name, line, command)
            return True
        return False

    def _interface(self, words: list[str], item: SwitchInterface, line: int) -> bool:
        command = " ".join(words)
        if words[0] == "description":
            item.description = " ".join(words[1:])
        elif command in {"shutdown", "no shutdown", "undo shutdown"}:
            item.admin_state = "disabled" if command == "shutdown" else "enabled"
        elif command in {"no routing", "port link-mode bridge"}:
            item.mode = "l2"
        elif command in {"routing", "port link-mode route"}:
            item.mode = "l3"
        elif words[:2] == ["port", "link-type"] and words[-1] in {"access", "trunk", "hybrid"}:
            item.link_type = "access" if words[-1] == "access" else "trunk" if words[-1] == "trunk" else "hybrid"
            item.mode = "l2"
        elif words[:2] in (["vrf", "attach"], ["ip", "binding"]) and len(words) >= 3:
            item.vrf = words[-1]
        elif words[0] == "lag" and len(words) == 2:
            item.aggregate = f"lag {words[1]}"
        elif words[:3] == ["port", "link-aggregation", "group"] and len(words) == 4:
            item.aggregate = f"Bridge-Aggregation{words[3]}"
        elif words[:2] == ["lacp", "mode"] and words[-1] == "active":
            self.aggregate(item.name, line).lacp = "active"
        elif command == "link-aggregation mode dynamic":
            self.aggregate(item.name, line).lacp = "dynamic"
        elif words[:3] == ["port", "access", "vlan"] or words[:2] == ["vlan", "access"]:
            item.link_type = "access"
            item.mode = "l2"
            if words[-1].isdigit() and 1 <= int(words[-1]) <= 4094:
                item.access_vlan = int(words[-1])
                self.vlan(item.access_vlan, line).untagged_interfaces += (item.name,)
            else:
                self.issue("vlans", line, "Некорректное назначение access VLAN.")
        elif words[:3] == ["vlan", "trunk", "native"]:
            item.link_type = "trunk"
            item.mode = "l2"
            if words[-1].isdigit() and 1 <= int(words[-1]) <= 4094:
                item.native_vlan = int(words[-1])
        elif words[:3] == ["vlan", "trunk", "allowed"]:
            item.link_type = "trunk"
            item.mode = "l2"
            item.allowed_vlans = " ".join(words[3:])
        elif words[:4] == ["port", "trunk", "permit", "vlan"]:
            item.link_type = "trunk"
            item.mode = "l2"
            item.allowed_vlans = " ".join(words[4:])
        elif words[:2] == ["ip", "address"] or words[:2] == ["ip", "static"]:
            values = words[2:]
            if not values:
                self.issue("interfaces", line, "Неполная адресная настройка.")
            elif values[0] in {"dhcp-bootp", "dhcp"}:
                item.address_method = "dhcp" if values[0] == "dhcp" else "dhcp-bootp"
            else:
                address = values[0] if "/" in values[0] else "/".join(values[:2])
                item.addresses += (self.address(address, line),)
                item.address_method = "static"
                item.mode = "l3"
        elif command == "ip dhcp":
            item.address_method = "dhcp"
        elif words[0] == "default-gateway" and len(words) == 2:
            self.route(None, words[1], line, item.vrf, "management_gateway")
        elif words[:2] == ["ip", "forward-broadcast"]:
            self.feature("ip-forward-broadcast", line, enabled=True)
        else:
            return False
        return True

    def _global(self, words: list[str], line: int) -> None:
        command = " ".join(words)
        if words[:2] == ["ip", "authorized-managers"] and len(words) >= 3:
            mask = words[3] if len(words) > 3 and re.fullmatch(r"[\d.]+", words[3]) else "255.255.255.255"
            raw = f"{words[2]}/{mask}"
            network = None
            try:
                network = str(ip_network(raw, strict=False))
            except ValueError:
                self.issue("management", line, "Некорректный источник управляющего доступа.", "SWITCH_ADDRESS_INVALID")
            method = words[words.index("access-method") + 1] if "access-method" in words and words.index("access-method") + 1 < len(words) else "all"
            privilege = words[words.index("access") + 1] if "access" in words and words.index("access") + 1 < len(words) else "manager"
            self.management.append(SwitchManagementFact(
                kind="authorized_source", service=method, address=network, raw_address=raw,
                value=privilege, status="known" if network else "unknown",
                source_locations=(self.location(line),),
            ))
        elif words[:2] == ["ip", "route"] and len(words) >= 5:
            self.route(f"{words[2]}/{words[3]}", words[4], line, "default", parameters=tuple(words[5:]))
        elif words[:2] == ["ip", "route-static"] and len(words) >= 5:
            values = words[2:]
            vrf = "default"
            if values[:1] == ["vpn-instance"] and len(values) >= 5:
                vrf, values = values[1], values[2:]
            if len(values) >= 3:
                self.route(f"{values[0]}/{values[1]}", values[2], line, vrf,
                           parameters=tuple(values[3:]))
        elif words[:2] == ["ip", "default-gateway"] and len(words) == 3:
            self.route(None, words[2], line, "default", "management_gateway")
        elif words[:2] == ["radius-server", "host"] and len(words) >= 3:
            # dyn-authorization/time-window are options, not a second server definition.
            if len(words) == 3 or "key" in words:
                self.management_host("radius", words[2], line)
        elif words[:2] in (["ntp", "server"], ["ntp-service", "unicast-server"]):
            if len(words) > 2:
                self.management_host("ntp", words[2], line)
        elif words[:2] == ["sntp", "server"]:
            index = 4 if words[2:3] == ["priority"] else 2
            if len(words) > index:
                self.management_host("sntp", words[index], line)
        elif words[0] == "logging" and len(words) == 2:
            self.management_host("syslog", words[1], line)
        elif words[:2] == ["info-center", "loghost"] and len(words) >= 3:
            self.management_host("syslog", words[2], line)
        elif words[:2] == ["snmp-server", "host"] and len(words) >= 3:
            vrf = words[words.index("vrf") + 1] if "vrf" in words and words.index("vrf") + 1 < len(words) else None
            self.management_host("snmp-trap", words[2], line, vrf)
        elif words[:2] == ["snmp-agent", "target-host"] and "udp-domain" in words:
            index = words.index("udp-domain")
            if index + 1 < len(words):
                self.management_host("snmp-trap", words[index + 1], line)
        elif words[:2] in (["ssh", "server"], ["https-server", "vrf"], ["snmp-server", "vrf"]):
            service = "ssh" if words[0] == "ssh" else words[0].removesuffix("-server")
            if "vrf" in words and words.index("vrf") + 1 < len(words):
                self.management_value("service", service, line, vrf=words[words.index("vrf") + 1], enabled=True)
            elif words[-1] == "enable":
                self.management_value("service", service, line, vrf="default", enabled=True)
            elif len(words) == 4 and words[2] == "acl":
                self.management_value("service_acl", service, line, words[3])
        elif words[:2] == ["snmp-agent", "community"]:
            if len(words) >= 3 and words[2] in {"read", "write"}:
                self.management.append(SwitchManagementFact(
                    kind="community_access", service="snmp", subject=f"community-line:{line}",
                    value="rw" if words[2] == "write" else "ro",
                    source_locations=(self.location(line),),
                ))
        elif words == ["snmp-agent"]:
            self.management_value("service", "snmp", line, enabled=True)
        elif words[:3] == ["snmp-agent", "sys-info", "version"]:
            self.management_value("versions", "snmp", line, " ".join(words[3:]))
        elif words[0] == "aaa" and not any(token in words for token in ("password", "cipher", "ciphertext", "key")):
            self.management_value("aaa", "login" if "login" in words else "port-access", line, command)
        elif words[:2] in (["ntp", "vrf"], ["ntp", "enable"]):
            self.management_value("service", "ntp", line, vrf=words[-1] if words[1] == "vrf" else None, enabled=True)
        elif words[0] in {"no", "undo"} and len(words) >= 2:
            service = {"telnet-server": "telnet", "web-management": "web", "rest-interface": "rest"}.get(words[1])
            if words[1:] == ["tftp", "server"]:
                service = "tftp"
            if service:
                self.management_value("service", service, line, enabled=False)
        elif words[0].startswith(("dhcp-snooping", "spanning-tree", "stp", "igmp", "pim")):
            self.feature(words[0], line, " ".join(words[1:]) or None,
                         False if "disable" in words else True if "enable" in words or len(words) == 1 else None)
        elif command in {"multicast routing-enable", "ip forward-broadcast"}:
            self.feature(command.replace(" ", "-"), line, enabled=True)
        elif words[:1] == ["static-rp"] and len(words) >= 2:
            address = self.host(words[1], line, "management")
            self.management.append(SwitchManagementFact(
                kind="server", service="pim-rp", address=address, raw_address=words[1],
                status="known" if address else "unknown", source_locations=(self.location(line),),
            ))

    def finish(self) -> SwitchFacts:
        ntp_vrfs = tuple(
            fact.vrf for fact in self.management
            if fact.kind == "service" and fact.service == "ntp" and fact.vrf is not None
        )
        if len(set(ntp_vrfs)) == 1:
            for fact in self.management:
                if fact.kind == "server" and fact.service == "ntp" and fact.vrf is None:
                    fact.vrf = ntp_vrfs[0]
        for item in self.interfaces.values():
            if item.aggregate:
                agg = self.aggregate(item.aggregate, item.source_locations[0].line_start or 1)
                if item.name not in agg.members:
                    agg.members += (item.name,)
            if item.kind == "aggregate":
                agg = self.aggregate(item.name, item.source_locations[0].line_start or 1)
                agg.description = item.description
                agg.allowed_vlans = item.allowed_vlans
                agg.native_vlan = item.native_vlan
                for location in item.source_locations:
                    if location not in agg.source_locations:
                        agg.source_locations += (location,)
        for agg in self.aggregates.values():
            agg.member_devices = tuple(sorted({member for port in agg.members if (member := _member(port))}))
        if self.hostname and not self.hardware:
            model = re.search(r"(?i)(?:HP|Aruba)[-_]?(\d{4}[A-Z]?)", self.hostname)
            if model and self.locations:
                self.hardware.append(SwitchHardware(model=model[0], origin="hostname_hint",
                                                     source_locations=(self.locations[0],)))
        quantities = {
            "identification": len(self.locations), "interfaces": len(self.interfaces),
            "vlans": len(self.vlans), "aggregation": len(self.aggregates),
            "stack": len(self.stack), "routes": len(self.routes),
            "management": len(self.management), "features": len(self.features),
        }
        return SwitchFacts(
            source_name=self.source.source_name, content_sha256=self.source.content_sha256,
            captured_at=self.source.captured_at, observation=self.source.observation,
            configuration_complete=self.source.configuration_complete,
            platform=self.platform, platform_family=self.family,
            identification_reasons=self.reasons, hostname=self.hostname, os_version=self.version,
            role_hint="Коммутатор L2/L3; назначение и активная маршрутизация требуют подтверждения."
            if self.interfaces else None,
            identification_locations=tuple(self.locations), hardware=tuple(self.hardware),
            interfaces=tuple(self.interfaces.values()), vlans=tuple(self.vlans.values()),
            aggregates=tuple(self.aggregates.values()), stack=tuple(self.stack.values()),
            routes=tuple(self.routes), management=tuple(self.management), features=tuple(self.features),
            issues=tuple(self.issues), coverage=tuple(
                SwitchAreaCoverage(area=area, status="partial" if count else
                                   "unknown" if any(issue.area == area for issue in self.issues) else "not_observed",
                                   recognized=count, issues=sum(issue.area == area for issue in self.issues))
                for area, count in quantities.items()
            ),
        )


def parse_switch_facts(source: SourceDocument, platform: str) -> SwitchFacts:
    """Извлечь ограниченный конфигурационный срез, сохраняя неполноту и ошибки адресов."""
    collector = _Collector(source, platform)
    try:
        text = source.content.decode("utf-8-sig")
    except UnicodeDecodeError:
        collector.issue("identification", 1, "Кодировка не поддержана; ожидается UTF-8.", "SWITCH_ENCODING")
        return collector.finish()
    for number, raw in enumerate(text.splitlines(), start=1):
        collector.consume(raw, number)
    detection = detect_switch_platform(text)
    collector.family = detection.family
    collector.reasons = detection.reasons
    if collector.version is None:
        collector.version = detection.version
    return collector.finish()
