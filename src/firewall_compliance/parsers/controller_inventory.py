"""Каталог объектов ArubaOS Controller и явные связи без догадок о runtime."""

from __future__ import annotations

import re
import shlex
from collections import Counter
from ipaddress import ip_address, ip_interface, ip_network
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from firewall_compliance.domain.controller import (
    ControllerCoverage,
    ControllerInventory,
    ControllerIssue,
    ControllerObject,
    ControllerReference,
)
from firewall_compliance.domain.source import SourceLocation

if TYPE_CHECKING:
    from firewall_compliance.domain.parse_result import ParseResult
    from firewall_compliance.parsers.contracts import SourceDocument


def controller_object_id(kind: str, name: str) -> str:
    """Имена разных типов живут в разных пространствах идентичности."""
    return f"{kind}:{quote(name, safe='')}"


def _operand(tokens: list[str], start: int) -> tuple[list[str], int]:
    if start >= len(tokens):
        raise ValueError("missing endpoint")
    count = 1
    if tokens[start] in {"host", "alias", "userrole"}:
        count = 2
    elif tokens[start] == "network":
        count = 2 if start + 1 < len(tokens) and "/" in tokens[start + 1] else 3
    if start + count > len(tokens):
        raise ValueError("incomplete endpoint")
    return tokens[start:start + count], start + count


def _vlan_ids(expression: str) -> tuple[int, ...]:
    identifiers: set[int] = set()
    for part in expression.split(","):
        match = re.fullmatch(r"([0-9]{1,4})(?:-([0-9]{1,4}))?", part.strip())
        if not match:
            raise ValueError("invalid VLAN range")
        start, end = int(match[1]), int(match[2] or match[1])
        if not 1 <= start <= end <= 4094:
            raise ValueError("invalid VLAN range")
        identifiers.update(range(start, end + 1))
    return tuple(sorted(identifiers))


class _InventoryBuilder:
    def __init__(self, source: SourceDocument, parsed: ParseResult) -> None:
        self.source = source
        self.parsed = parsed
        self.objects: dict[str, ControllerObject] = {}
        self.references: list[ControllerReference] = []
        self.issues: list[ControllerIssue] = []
        self.current: ControllerObject | None = None
        self.version: str | None = None
        self.timezone: str | None = None
        self.positions: Counter[str] = Counter()
        self.rules_by_line = {rule.source_location.line_start: rule for rule in parsed.rules}
        self.attachments_by_line = {
            attachment.source_location.line_start: attachment
            for attachment in parsed.policy_attachments
        }
        self.device = self.object("device", parsed.configuration.device_id, 1)
        self.skip_banner: str | None = None

    def location(self, line: int) -> SourceLocation:
        return SourceLocation(source_name=self.source.source_name, line_start=line, line_end=line)

    def object(self, kind: str, name: str, line: int, *, repeat: bool = False) -> ControllerObject:
        identifier = controller_object_id(kind, name)
        existing = self.objects.get(identifier)
        if existing is not None:
            if not repeat:
                existing.state = "partial"
                existing.attributes["duplicate_declaration"] = True
                self.issue("CONTROLLER_DUPLICATE_OBJECT", "Повторное объявление; порядок и область требуют проверки.", line, existing)
            self.anchor(existing, line)
            return existing
        item = ControllerObject(object_id=identifier, kind=kind, name=name,
                                source_locations=(self.location(line),))
        self.objects[identifier] = item
        return item

    def anchor(self, item: ControllerObject, line: int) -> None:
        location = self.location(line)
        if location not in item.source_locations:
            item.source_locations += (location,)

    def issue(self, code: str, message: str, line: int,
              item: ControllerObject | None = None) -> None:
        self.issues.append(ControllerIssue(code=code, message=message,
                                           object_id=item.object_id if item else None,
                                           source_location=self.location(line)))
        if item is not None:
            item.state = "partial"

    def reference(self, item: ControllerObject, target_kind: str, target: str, relation: str,
                  line: int, position: int | None = None, dynamic: bool = False) -> None:
        self.references.append(ControllerReference(
            reference_id=f"reference:{line}:{len(self.references)}", source_id=item.object_id,
            target_kind=target_kind, target_name=target, relation=relation,
            status="dynamic" if dynamic else "missing", position=position,
            source_locations=(self.location(line),),
        ))

    def consume(self, raw: str, line: int) -> None:
        text = raw.strip()
        if self.skip_banner is not None:
            if self.skip_banner in text:
                self.skip_banner = None
            return
        if not text:
            return
        if text.startswith(("banner ", "header ")):
            self.current = None
            self.issue("CONTROLLER_BANNER_OMITTED", "Текст баннера не интерпретируется как команды.", line)
            parts = text.split(maxsplit=2)
            if len(parts) == 3 and parts[2]:
                delimiter = parts[2][0]
                if delimiter not in parts[2][1:]:
                    self.skip_banner = delimiter
            return
        if text.startswith(("!", "#")):
            if text in {"!", "#"}:
                self.current = None
            return
        try:
            tokens = shlex.split(text, comments=False)
        except ValueError:
            self.issue("CONTROLLER_TOKEN_INVALID", "Некорректные кавычки; строка не интерпретирована.", line, self.current)
            return
        if not tokens:
            return
        if tokens[0] in {"exit", "end"}:
            self.current = None
            return
        if tokens[0] == "version" and len(tokens) >= 2:
            self.version = tokens[1]
            self.device.attributes["version"] = tokens[1]
            self.anchor(self.device, line)
            return
        if tokens[0] in {"hostname", "location"} and len(tokens) == 2:
            self.device.attributes[tokens[0]] = tokens[1]
            self.anchor(self.device, line)
            return
        if tokens[:2] == ["clock", "timezone"]:
            self.timezone = " ".join(tokens[2:])
            self.device.attributes["timezone"] = self.timezone
            self.anchor(self.device, line)
            return
        header = self.header(tokens, line)
        if header is not None:
            self.current = header
            return
        if self.current is not None and raw[:1].isspace():
            self.anchor(self.current, line)
            self.child(self.current, tokens, line)
            return
        self.current = None
        self.global_command(tokens, line)

    def header(self, tokens: list[str], line: int) -> ControllerObject | None:
        kind: str | None = None
        name = ""
        if tokens[:2] == ["ip", "access-list"] and len(tokens) == 4:
            kinds = {"session": "acl_session", "eth": "acl_eth", "route": "acl_route", "geolocation": "acl_geolocation"}
            kind, name = kinds.get(tokens[2]), tokens[3]
        elif tokens[0] in {"netdestination", "netdestination6", "user-role", "ap-group", "interface", "netexthdr"} and len(tokens) >= 2:
            kind = {"netdestination": "address", "netdestination6": "address6", "user-role": "role", "ap-group": "ap_group", "interface": "interface", "netexthdr": "extension_header"}[tokens[0]]
            name = " ".join(tokens[1:])
        elif tokens[:2] == ["time-range", "periodic"] and len(tokens) == 3:
            kind, name = "time_range", tokens[2]
        elif tokens[:2] == ["time-range", "absolute"] and len(tokens) >= 3:
            item = self.object("time_range", tokens[2], line)
            item.attributes.update(mode="absolute", specification=tokens[3:], timezone=self.timezone)
            return item
        elif tokens[:2] == ["wlan", "ssid-profile"] and len(tokens) == 3:
            kind, name = "ssid_profile", tokens[2]
        elif tokens[:2] == ["wlan", "virtual-ap"] and len(tokens) == 3:
            kind, name = "virtual_ap", tokens[2]
        elif tokens[:2] == ["aaa", "profile"] and len(tokens) == 3:
            kind, name = "aaa_profile", tokens[2]
        elif tokens[:3] == ["aaa", "authentication-server", "radius"] and len(tokens) == 4:
            kind, name = "radius_server", tokens[3]
        elif tokens[:2] == ["aaa", "server-group"] and len(tokens) == 3:
            kind, name = "server_group", tokens[2]
        elif tokens[:3] == ["aaa", "authentication", "captive-portal"] and len(tokens) == 4:
            kind, name = "captive_portal", tokens[3]
        elif tokens[:3] == ["aaa", "derivation-rules", "user"] and len(tokens) == 4:
            kind, name = "derivation_rules", tokens[3]
        elif tokens[:2] == ["aaa", "authentication"] and len(tokens) == 4:
            kind, name = "authentication_profile", f"{tokens[2]}:{tokens[3]}"
        elif tokens[0] == "vpn-dialer" and len(tokens) == 2 or tokens[:2] == ["dialer", "group"] and len(tokens) == 3:
            kind, name = "vpn_profile", tokens[-1]
        elif tokens[:3] == ["crypto-local", "pki", "rcp"] and len(tokens) == 4:
            kind, name = "pki", tokens[3]
        if kind is None:
            return None
        item = self.object(kind, name, line)
        if kind == "interface" and name.startswith("vlan ") and name[5:].isdigit():
            vlan_name = name[5:]
            self.object("vlan", vlan_name, line, repeat=True).attributes["interface_declared"] = True
            self.reference(item, "vlan", vlan_name, "vlan_interface", line)
        if kind in {"address", "address6"}:
            item.attributes.setdefault("members", [])
            item.attributes["address_family"] = "ipv6" if kind == "address6" else "ipv4"
        if kind == "time_range":
            item.attributes.update(mode="periodic", intervals=[], timezone=self.timezone)
        if kind == "role":
            item.attributes.setdefault("acl_order_complete", True)
            item.attributes.setdefault("limits", [])
        if kind.startswith("acl_"):
            item.attributes.setdefault("entry_ids", [])
            item.attributes["address_family"] = "mixed" if kind == "acl_session" else "unknown"
            item.attributes["application_classification_declared"] = False
        return item

    def child(self, item: ControllerObject, tokens: list[str], line: int) -> None:
        if tokens[0] == "description":
            item.description = " ".join(tokens[1:])
            return
        if item.kind in {"address", "address6"}:
            self.address_member(item, tokens, line)
            return
        if item.kind.startswith("acl_"):
            self.acl_entry(item, tokens, line)
            return
        if item.kind == "role":
            self.role(item, tokens, line)
            return
        if item.kind == "time_range":
            days = {"daily", "weekday", "weekend", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
            valid_times = len(tokens) == 4 and all(
                re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value)
                for value in (tokens[1], tokens[3])
            )
            if valid_times and tokens[2] == "to" and tokens[0].lower() in days:
                item.attributes.setdefault("intervals", []).append({"days": tokens[0].lower(), "start": tokens[1], "end": tokens[3]})
            else:
                self.issue("CONTROLLER_TIME_RANGE_UNSUPPORTED", "Временной интервал требует отдельной интерпретации.", line, item)
            return
        if item.kind == "derivation_rules":
            self.derivation(item, tokens, line)
            return
        # Secrets are recognised without retaining any values or full commands.
        if any(word.lower() in {"key", "password", "passwd", "secret", "pre-share", "pre-shared-key", "wpa-passphrase"} for word in tokens):
            item.attributes["credential_configured"] = True
            return
        if self.profile_link(item, tokens, line):
            return
        self.profile_attribute(item, tokens, line)

    def address_member(self, item: ControllerObject, tokens: list[str], line: int) -> None:
        member: dict[str, Any] = {"type": tokens[0], "status": "unknown", "line": line}
        family = 6 if item.kind == "address6" else 4
        try:
            if tokens[0] == "host" and len(tokens) == 2:
                address = ip_address(tokens[1])
                if address.version != family:
                    raise ValueError("family")
                member.update(address=str(address), cidr=f"{address}/{address.max_prefixlen}", status="known")
            elif tokens[0] == "network" and len(tokens) in {2, 3}:
                raw = tokens[1] if len(tokens) == 2 else f"{tokens[1]}/{tokens[2]}"
                network = ip_network(raw, strict=False)
                if network.version != family:
                    raise ValueError("family")
                member.update(address=tokens[1], mask=tokens[2] if len(tokens) == 3 else None,
                              cidr=str(network), status="known")
            elif tokens[0] == "range" and len(tokens) == 3:
                start, end = ip_address(tokens[1]), ip_address(tokens[2])
                if start.version != family or end.version != family or int(start) > int(end):
                    raise ValueError("range")
                member.update(start=str(start), end=str(end), status="known")
            elif tokens[0] == "name" and len(tokens) == 2:
                member.update(name=tokens[1], status="dynamic")
            elif tokens[0] == "invert" and len(tokens) == 1:
                item.attributes["invert"] = True
                item.attributes["effective_addresses"] = "unknown"
                return
            elif tokens[:2] == ["host", "vlan"]:
                member.update(vlan_id=int(tokens[2]), offset=int(tokens[4]) if len(tokens) == 5 and tokens[3] == "offset" else None, status="dynamic")
            else:
                raise ValueError("unsupported")
        except (ValueError, IndexError):
            member["raw"] = " ".join(tokens[1:]) if tokens[0] in {"host", "network", "range", "name"} else None
            self.issue("CONTROLLER_ADDRESS_UNRESOLVED", "Адресный элемент не разрешён; он не заменён ANY.", line, item)
        item.attributes.setdefault("members", []).append(member)
        if member["status"] != "known":
            item.state = "partial"

    def acl_entry(self, acl: ControllerObject, tokens: list[str], line: int) -> None:
        entry = self.object("ace", f"{acl.name}:{line}", line)
        self.positions[acl.object_id] += 1
        family = "ipv6" if tokens[:1] == ["ipv6"] else "ipv4"
        body = tokens[1:] if family == "ipv6" else tokens
        attributes: dict[str, Any] = {"acl_name": acl.name, "acl_kind": acl.kind,
                                      "address_family": family,
                                      "position": self.positions[acl.object_id],
                                      "semantics_supported": False}
        rule = self.rules_by_line.get(line)
        attributes["rule_id"] = rule.rule_id if rule else None
        acl.attributes["entry_ids"].append(entry.object_id)
        self.reference(acl, "ace", entry.name, "entry", line, self.positions[acl.object_id])
        if acl.kind != "acl_session":
            attributes["action"] = body[-1] if body else "unknown"
            attributes["syntax"] = body[:8]
            entry.state = "unsupported"
            self.issue("CONTROLLER_NON_SESSION_ACL", "ACL сохранена как отдельный тип; эффективная обработка не вычислена.", line, entry)
            entry.attributes = attributes
            return
        try:
            source, cursor = _operand(body, 0)
            destination, cursor = _operand(body, cursor)
            actions = {"permit", "deny", "src-nat", "dst-nat", "dual-nat", "redirect", "route"}
            action_index = next(index for index in range(cursor, len(body)) if body[index] in actions)
            service = body[cursor:action_index]
            attributes.update(source_tokens=source, destination_tokens=destination,
                              service_tokens=service, action=body[action_index],
                              extended_tokens=body[action_index + 1:])
            attributes["dynamic_operands"] = [operand[0] for operand in (source, destination)
                                               if operand[0] in {"user", "localip", "userrole"}]
            for relation, operand in (("source", source), ("destination", destination)):
                if operand[0] == "alias":
                    self.reference(entry, "address6" if family == "ipv6" else "address", operand[1], relation, line)
                elif operand[0] == "userrole":
                    self.reference(entry, "role", operand[1], relation, line, dynamic=True)
            if len(service) == 1 and service[0] not in {"any", "icmp", "icmpv6"} and not service[0].isdigit():
                self.reference(entry, "service", service[0], "service", line)
            for option in ("queue", "time-range", "position"):
                if option in body[action_index + 1:]:
                    index = body.index(option, action_index + 1)
                    if index + 1 < len(body):
                        attributes[option.replace("-", "_")] = body[index + 1]
                        if option == "time-range":
                            self.reference(entry, "time_range", body[index + 1], "time_range", line)
            attributes["semantics_supported"] = bool(rule and rule.match_status.value == "known")
            # Dynamic operands need query context, not a different ACE grammar.
            # Only understood options permit an eventual context-aware evaluation.
            if rule is not None and rule.match_status.value in {"known", "unknown"}:
                extended = body[action_index + 1:]
                cursor = 0
                supported = attributes["action"] in {"permit", "deny"}
                while cursor < len(extended):
                    token = extended[cursor]
                    if token in {"log", "mirror"}:
                        if token == "mirror":
                            supported = False
                        cursor += 1
                    elif token in {"queue", "time-range", "position"} and cursor + 1 < len(extended):
                        cursor += 2
                    else:
                        supported = False
                        break
                attributes["semantics_supported"] = supported
            if service[:1] in (["app"], ["appcategory"], ["web-cc-category"], ["web-cc-reputation"]):
                attributes["classification"] = service
                acl.attributes["application_classification_declared"] = True
                entry.state = "partial"
            if attributes["action"] not in {"permit", "deny"}:
                entry.state = "partial"
                self.issue("CONTROLLER_TRANSLATION_DECLARATION", "NAT/PBR/redirect сохранены; effective-трансляция и следующий переход не вычислены.", line, entry)
                self.nat_references(entry, body[action_index:], line)
        except (IndexError, StopIteration, ValueError):
            entry.state = "unsupported"
            self.issue("CONTROLLER_ACE_UNRESOLVED", "Условие ACL не полностью распознано.", line, entry)
        entry.attributes = attributes

    def nat_references(self, entry: ControllerObject, tokens: list[str], line: int) -> None:
        if "pool" in tokens:
            index = tokens.index("pool")
            if index + 1 < len(tokens):
                self.reference(entry, "nat_pool", tokens[index + 1], "nat_pool", line)

    def role(self, item: ControllerObject, tokens: list[str], line: int) -> None:
        if tokens[:1] == ["ipv6"]:
            tokens = tokens[1:]
        if tokens[:2] == ["access-list", "session"] or tokens[:1] == ["session-acl"]:
            index = 2 if tokens[0] == "access-list" else 1
            attachment = self.attachments_by_line.get(line)
            if index >= len(tokens) or attachment is None:
                item.attributes["acl_order_complete"] = False
                self.issue("CONTROLLER_ROLE_ACL_INVALID", "Неполная или неизвестная привязка ACL.", line, item)
                return
            self.positions[item.object_id] += 1
            explicit = attachment.declaration_position is not None
            previous = item.attributes.setdefault("explicit_acl_positions", explicit)
            if previous != explicit:
                item.attributes["acl_order_complete"] = False
            position = attachment.declaration_position or self.positions[item.object_id]
            self.reference(item, "acl_session", tokens[index], "acl", line, position)
            if (attachment.scope_reference or "").startswith("ap-group:"):
                self.reference(item, "ap_group", attachment.scope_reference.removeprefix("ap-group:"),
                               "acl_scope", line, dynamic=True)
            return
        if tokens[0] == "vlan" and len(tokens) == 2:
            if tokens[1].isdigit() and 1 <= int(tokens[1]) <= 4094:
                item.attributes["vlan_id"] = int(tokens[1])
                vlan = self.object("vlan", tokens[1], line, repeat=True)
                vlan.attributes["role_assignment_only"] = True
                self.reference(item, "vlan", tokens[1], "vlan", line)
            else:
                item.attributes["vlan_name"] = tokens[1]
                self.reference(item, "vlan_pool", tokens[1], "vlan", line)
            return
        if tokens[0] == "bw-contract":
            values = tokens[1:]
            selector = "role"
            selected: str | None = None
            if values and values[0] in {"app", "appcategory", "web-cc-category", "web-cc-reputation"}:
                selector = values[0]
                if len(values) < 3:
                    self.issue("CONTROLLER_BANDWIDTH_INVALID", "Неполная привязка bandwidth contract.", line, item)
                    return
                selected, values = values[1], values[2:]
            if not values:
                return
            scope = "per-user" if "per-user" in values else "per-apgroup" if "per-apgroup" in values else "per-role"
            item.attributes["limits"].append({"contract": values[0], "direction": values[-1] if values[-1] in {"upstream", "downstream"} else "unknown",
                                              "scope": scope, "selector_type": selector, "selector": selected})
            self.reference(item, "bandwidth_contract", values[0], "bandwidth", line)
            if selected is not None:
                app = self.object("app_rf", f"{item.name}:{line}", line)
                app.attributes.update(role=item.name, selector_type=selector, selector=selected,
                                      direction=item.attributes["limits"][-1]["direction"],
                                      classification="unknown")
                self.reference(app, "role", item.name, "role", line)
                self.reference(app, "bandwidth_contract", values[0], "bandwidth", line)
            return
        if tokens[0] == "captive-portal" and len(tokens) == 2:
            self.reference(item, "captive_portal", tokens[1], "captive_portal", line)
            return
        if tokens[0] == "reauthentication-interval" and len(tokens) in {2, 3}:
            if tokens[1].isdigit():
                item.attributes["reauthentication"] = {"value": int(tokens[1]), "unit": tokens[2] if len(tokens) == 3 else "minutes"}
                return
        flags = item.attributes.setdefault("flags", {})
        if tokens in (["dpi", "disable"], ["web-cc", "disable"], ["no", "openflow-enable"], ["no", "captive-portal", "check-for-accounting"]):
            flags[" ".join(tokens[1:] if tokens[0] == "no" else tokens[:-1])] = False
            return
        self.issue("CONTROLLER_ROLE_ATTRIBUTE_UNSUPPORTED", "Атрибут роли не полностью поддержан; effective-роль не заявляется.", line, item)

    def derivation(self, item: ControllerObject, tokens: list[str], line: int) -> None:
        if len(tokens) >= 8 and tokens[:3] == ["set", "role", "condition"] and "set-value" in tokens:
            index = tokens.index("set-value")
            if index + 1 < len(tokens):
                target = tokens[index + 1]
                condition = {"attribute": tokens[3], "operator": tokens[4], "value": tokens[5],
                             "role": target, "line": line}
                if "description" in tokens[index + 2:]:
                    desc = tokens.index("description", index + 2)
                    condition["description"] = " ".join(tokens[desc + 1:])
                item.attributes.setdefault("conditions", []).append(condition)
                self.reference(item, "role", target, "derived_role", line)
                return
        self.issue("CONTROLLER_DERIVATION_UNSUPPORTED", "Условие назначения роли требует отдельной интерпретации.", line, item)

    def profile_link(self, item: ControllerObject, tokens: list[str], line: int) -> bool:
        if len(tokens) < 2:
            return False
        mappings: dict[str, tuple[str, str]] = {}
        if item.kind == "aaa_profile":
            mappings = {"initial-role": ("role", "initial_role"), "dot1x-default-role": ("role", "dot1x_role"), "mac-default-role": ("role", "mac_role"), "user-derivation-rules": ("derivation_rules", "derivation"), "dot1x-server-group": ("server_group", "dot1x_servers"), "mac-server-group": ("server_group", "mac_servers"), "radius-accounting": ("server_group", "accounting"), "authentication-dot1x": ("authentication_profile", "dot1x_authentication"), "authentication-mac": ("authentication_profile", "mac_authentication")}
        elif item.kind == "virtual_ap":
            mappings = {"aaa-profile": ("aaa_profile", "aaa"), "ssid-profile": ("ssid_profile", "ssid"), "vlan": ("vlan", "vlan")}
        elif item.kind == "ap_group":
            mappings = {"virtual-ap": ("virtual_ap", "virtual_ap")}
        elif item.kind == "captive_portal":
            mappings = {"default-role": ("role", "authenticated_role"), "default-guest-role": ("role", "guest_role"), "server-group": ("server_group", "servers")}
        elif item.kind == "server_group":
            mappings = {"auth-server": ("radius_server", "server")}
        if tokens[0] not in mappings:
            return False
        kind, relation = mappings[tokens[0]]
        name = tokens[1]
        if kind == "authentication_profile":
            name = ("dot1x:" if "dot1x" in tokens[0] else "mac:") + name
        if kind == "vlan" and name.isdigit() and 1 <= int(name) <= 4094:
            self.object("vlan", name, line, repeat=True).attributes["profile_assignment_only"] = True
        elif kind == "vlan":
            kind = "vlan_pool"
        self.reference(item, kind, name, relation, line)
        return True

    def profile_attribute(self, item: ControllerObject, tokens: list[str], line: int) -> None:
        if item.kind == "ssid_profile" and tokens[0] == "essid" and len(tokens) == 2:
            item.attributes["essid"] = tokens[1]
            return
        if item.kind == "radius_server" and tokens[0] in {"host", "auth-port", "acct-port", "timeout", "retransmit"} and len(tokens) == 2:
            item.attributes[tokens[0].replace("-", "_")] = tokens[1]
            return
        if item.kind == "interface":
            if tokens[:2] == ["ip", "address"] and len(tokens) in {3, 4}:
                raw = tokens[2] if len(tokens) == 3 else f"{tokens[2]}/{tokens[3]}"
                if tokens[2] in {"dhcp", "dhcp-bootp"}:
                    item.attributes["address_method"] = tokens[2]
                    return
                try:
                    address = str(ip_interface(raw))
                    item.attributes.setdefault("addresses", []).append(address)
                except ValueError:
                    item.attributes.setdefault("unresolved_addresses", []).append(raw)
                    self.issue("CONTROLLER_INTERFACE_ADDRESS_INVALID", "Некорректный адрес интерфейса не исправлен автоматически.", line, item)
                return
            if tokens in (["shutdown"], ["no", "shutdown"]):
                item.attributes["admin_state"] = "disabled" if tokens[0] == "shutdown" else "enabled"
                return
        if item.kind == "pki" and tokens[:1] == ["revocation-check"]:
            item.attributes["revocation_check"] = tokens[1:]
            return
        # Only this explicit allowlist of safe noncredential profile settings is retained.
        safe = {"opmode", "forward-mode", "enable", "disable", "auth-survivability", "server-retry-count", "max-authentication-failures", "reauthentication", "reauthentication-interval", "user-idle-timeout", "controller-ip", "mtu", "native-vlan", "vlan", "ip"}
        if tokens[0] in safe and len(tokens) <= 5:
            item.attributes.setdefault("settings", []).append(tokens)
            return
        self.issue("CONTROLLER_PROFILE_ATTRIBUTE_UNSUPPORTED", "Параметр профиля не включён в поддержанный безопасный срез.", line, item)

    def global_command(self, tokens: list[str], line: int) -> None:
        if tokens[0] == "netservice" and len(tokens) >= 3:
            item = self.object("service", tokens[1], line)
            values = tokens[2:]
            item.attributes.update(protocol=values[0], ports=[], status="unknown")
            try:
                if values[0] in {"tcp", "udp"}:
                    operands = values[1:]
                    if "alg" in operands:
                        index = operands.index("alg")
                        item.attributes["alg"] = operands[index + 1]
                        operands = operands[:index]
                    if operands[:1] == ["list"] and len(operands) == 2:
                        numbers = re.split(r"[,\s]+", operands[1].strip())
                        item.attributes["ports"] = [[int(value), int(value)] for value in numbers]
                    elif len(operands) in {1, 2}:
                        item.attributes["ports"] = [[int(operands[0]), int(operands[-1])]]
                    else:
                        raise ValueError("ports")
                    item.attributes["ip_protocol"] = 6 if values[0] == "tcp" else 17
                elif values[0].isdigit() and 0 <= int(values[0]) <= 255:
                    item.attributes["ip_protocol"] = int(values[0])
                    if len(values) > 1:
                        if values[1] == "alg" and len(values) == 3:
                            item.attributes["alg"] = values[2]
                        else:
                            raise ValueError("protocol options")
                else:
                    raise ValueError("protocol")
                if any(not 0 <= start <= end <= 65535 for start, end in item.attributes["ports"]):
                    raise ValueError("port range")
                item.attributes["status"] = "known"
            except (ValueError, IndexError):
                self.issue("CONTROLLER_SERVICE_UNRESOLVED", "Сервис не полностью нормализован.", line, item)
            return
        if tokens[:2] == ["aaa", "bandwidth-contract"] and len(tokens) == 5:
            item = self.object("bandwidth_contract", tokens[2], line)
            if tokens[3] in {"mbits", "kbits"} and tokens[4].isdigit():
                item.attributes.update(unit=tokens[3], rate=int(tokens[4]))
            else:
                self.issue("CONTROLLER_BANDWIDTH_INVALID", "Неизвестная единица или скорость.", line, item)
            return
        if tokens[:3] == ["ip", "NAT", "pool"] or tokens[:3] == ["ip", "nat", "pool"]:
            if len(tokens) >= 6:
                item = self.object("nat_pool", tokens[3], line)
                item.attributes.update(start=tokens[4], end=tokens[5], effective_translation="unknown")
                self.issue("CONTROLLER_NAT_DECLARATION_ONLY", "NAT pool объявлен; применение и effective-трансляция неизвестны.", line, item)
            return
        if tokens[:2] == ["aaa", "timers"] and len(tokens) >= 4:
            item = self.object("management", "aaa-timers", line, repeat=True)
            unit = tokens[4] if len(tokens) == 5 else "minutes"
            if tokens[3].isdigit():
                item.attributes[tokens[2]] = {"value": int(tokens[3]), "unit": unit}
            return
        if tokens[:2] == ["controller-ip", "vlan"] or tokens[:3] == ["ip", "radius", "source-interface"]:
            item = self.object("management", "controller", line, repeat=True)
            name = tokens[-1]
            item.attributes["controller_vlan" if tokens[0] == "controller-ip" else "radius_source_vlan"] = name
            self.reference(item, "vlan", name, "controller_vlan" if tokens[0] == "controller-ip" else "radius_source_vlan", line)
            return
        if tokens[:3] == ["ip", "radius", "nas-ip"] and len(tokens) == 4:
            self.object("management", "controller", line, repeat=True).attributes["nas_ip"] = tokens[3]
            return
        if tokens[:3] == ["crypto-local", "pki", "TrustedCA"] or tokens[:3] == ["crypto-local", "pki", "ServerCert"] or tokens[:3] == ["crypto-local", "pki", "PublicCert"]:
            if len(tokens) >= 5:
                self.object("certificate", tokens[3], line).attributes.update(certificate_type=tokens[2], filename=tokens[4],validity="unknown")
            return
        if tokens[:2] == ["aaa", "tacacs-accounting"]:
            self.object("management", "tacacs-accounting", line).attributes["configured"] = True
            return
        if tokens[0] == "vlan-name" and len(tokens) >= 2:
            pool = self.object("vlan_pool", tokens[1], line, repeat=True)
            pool.attributes["explicit_declaration"] = True
            if len(tokens) >= 4 and tokens[2] == "assignment":
                pool.attributes["assignment"] = tokens[3]
            return
        if tokens[0] == "vlan" and len(tokens) >= 2:
            name = tokens[1]
            if name.isdigit() and 1 <= int(name) <= 4094 and len(tokens) <= 3:
                vlan = self.object("vlan", name, line, repeat=True)
                vlan.attributes["explicit_declaration"] = True
                if len(tokens) == 3 and tokens[2] != "option-82":
                    vlan.description = tokens[2]
            elif (name == "range" and len(tokens) >= 3 and tokens[2] != "remove") or (
                len(tokens) == 3 and name not in {"range", "wired"} and not name.isdigit()
            ):
                try:
                    identifiers = _vlan_ids(" ".join(tokens[2:]))
                except ValueError:
                    self.issue("CONTROLLER_VLAN_UNRESOLVED", "Диапазон или состав VLAN не распознан.", line)
                    return
                pool = self.object("vlan_pool", name, line, repeat=True) if name != "range" else None
                for identifier in identifiers:
                    vlan = self.object("vlan", str(identifier), line, repeat=True)
                    if pool is None:
                        vlan.attributes["explicit_declaration"] = True
                    else:
                        self.reference(pool, "vlan", vlan.name, "member", line)
            else:
                self.issue("CONTROLLER_VLAN_UNRESOLVED", "Вариант команды VLAN требует отдельной интерпретации.", line)
            return
        if tokens[0] == "show":
            self.issue("CONTROLLER_OPERATIONAL_INPUT_UNSUPPORTED", "Операционные выводы не смешиваются с конфигурацией; требуется отдельное свидетельство.", line)

    def finish(self) -> ControllerInventory:
        references = []
        for reference in self.references:
            identifier = controller_object_id(reference.target_kind, reference.target_name)
            target = self.objects.get(identifier)
            if target is not None:
                reference = reference.model_copy(update={"target_id": identifier, "status": "dynamic" if reference.status == "dynamic" else "known"})
            elif reference.status != "dynamic":
                self.issue("CONTROLLER_REFERENCE_MISSING", "Ссылка на отсутствующий в источнике объект.", reference.source_locations[0].line_start or 1, self.objects[reference.source_id])
            references.append(reference)
        counts = Counter(item.kind for item in self.objects.values())
        issue_counts = Counter(self.objects[issue.object_id].kind for issue in self.issues if issue.object_id in self.objects)
        for item in self.objects.values():
            if item.kind == "time_range" and self.timezone:
                item.attributes["timezone"] = self.timezone
        return ControllerInventory(
            source_name=self.source.source_name, content_sha256=self.source.content_sha256,
            captured_at=self.source.captured_at, declared_version=self.version,
            configuration_complete=self.source.configuration_complete,
            configuration_view=getattr(self.source, "configuration_view", "unknown"),
            node_path=getattr(self.source, "configuration_node_path", None),
            objects=tuple(self.objects.values()), references=tuple(references), issues=tuple(self.issues),
            coverage=tuple(ControllerCoverage(area=kind, recognized=count, unsupported=issue_counts[kind]) for kind, count in sorted(counts.items())),
        )


def parse_controller_inventory(source: SourceDocument, parsed: ParseResult) -> ControllerInventory:
    """Извлечь связанный каталог без выполнения команд, DNS-запросов или I/O."""
    builder = _InventoryBuilder(source, parsed)
    for number, raw in enumerate(source.content.decode("utf-8-sig").splitlines(), 1):
        builder.consume(raw, number)
    return builder.finish()
