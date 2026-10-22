"""Conservative explicit management syntax; no vendor defaults or runtime claims."""

import re
import shlex
from ipaddress import IPv4Address, IPv4Network

from firewall_compliance.domain.management import (
    ManagementFact,
    ManagementInventory,
    ManagementIssue,
    ManagementKind,
    normalize_server,
)
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.parsers.contracts import SourceDocument


def parse_management(source: SourceDocument, platform: str) -> ManagementInventory:
    lines = source.content.decode("utf-8-sig").splitlines()
    facts: dict[tuple[ManagementKind, str], ManagementFact] = {}
    issues: list[ManagementIssue] = []

    def loc(number: int) -> SourceLocation:
        return SourceLocation(source_name=source.source_name, line_start=number, line_end=number)

    def issue(kind: ManagementKind, number: int) -> None:
        issues.append(ManagementIssue(kind=kind, source_location=loc(number)))

    def issue_all(number: int) -> None:
        kinds: tuple[ManagementKind, ...] = (
            "telnet",
            "http",
            "admin_sources",
            "snmp_legacy",
            "snmp_write",
            "snmp_sources",
            "syslog",
            "ntp",
            "timeout",
            "banner",
        )
        for kind in kinds:
            issue(kind, number)

    def put(
        kind: ManagementKind,
        scope: str,
        value: str,
        number: int,
        extra: tuple[SourceLocation, ...] = (),
    ) -> None:
        key = (kind, scope)
        if key in facts and facts[key].value != value:
            issue(kind, number)
        facts[key] = ManagementFact(
            kind=kind, scope=scope, value=value, source_locations=(loc(number), *extra)
        )

    # Resolve only simple, ordered IPv4 basic ACLs. Extended, time-based and
    # unresolved ACLs are not approximated by their permit lines.
    acls: dict[str, list[tuple[int, str, IPv4Network, int]]] = {}
    bad_acls: set[str] = set()
    acl: str | None = None
    acl_skip_until = 0
    for number, raw in enumerate(lines, 1):
        if number <= acl_skip_until:
            continue
        line = raw.strip()
        if line.startswith(("banner ", "header ")):
            parts = line.split(maxsplit=2)
            if len(parts) == 3:
                delimiter, tail = parts[2][0], parts[2][1:]
                acl_skip_until = number
                while delimiter not in tail and acl_skip_until < len(lines):
                    tail += "\n" + lines[acl_skip_until]
                    acl_skip_until += 1
            else:
                acl_skip_until = len(lines)
            continue
        match = re.fullmatch(r"acl (?:number |basic )?(\d+)", line)
        if match:
            acl = match[1]
            acls.setdefault(acl, [])
            if not 2000 <= int(acl) <= 2999:
                bad_acls.add(acl)
            continue
        if line == "#" or (raw and not raw[0].isspace() and not line.startswith("rule ")):
            acl = None
        if acl and line.startswith("rule "):
            match = re.fullmatch(
                r"rule (\d+) (permit|deny)(?: source (any|[\d.]+)(?: ([\d.]+))?)?", line
            )
            if not match:
                bad_acls.add(acl)
                continue
            try:
                address, wildcard = match[3], match[4]
                netmask = IPv4Address(0xFFFFFFFF ^ int(IPv4Address(wildcard or "0.0.0.0")))
                network = (
                    IPv4Network("0.0.0.0/0")
                    if address in (None, "any")
                    else IPv4Network(
                        f"{address}/{netmask}",
                        strict=False,
                    )
                )
                # ipaddress treats 0.0.0.0 as /0 netmask, but ACL wildcard zero is /32.
                if address not in (None, "any") and wildcard in (None, "0.0.0.0"):
                    network = IPv4Network(f"{address}/32")
                acls[acl].append((int(match[1]), match[2], network, number))
            except ValueError:
                bad_acls.add(acl)

    def acl_sources(kind: ManagementKind, reference: str, scope: str, number: int) -> None:
        entries = acls.get(reference)
        if not source.configuration_complete or not entries or reference in bad_acls:
            issue(kind, number)
            return
        if len({e[0] for e in entries}) != len(entries):
            issue(kind, number)
            return
        remaining = [IPv4Network("0.0.0.0/0")]
        allowed: list[IPv4Network] = []
        for _, action, network, _ in sorted(entries):
            following: list[IPv4Network] = []
            for part in remaining:
                if not part.overlaps(network):
                    following.append(part)
                elif part.subnet_of(network):
                    if action == "permit":
                        allowed.append(part)
                else:
                    if action == "permit":
                        allowed.append(network)
                    following.extend(part.address_exclude(network))
            remaining = following
            if len(remaining) + len(allowed) > 4096:
                issue(kind, number)
                return
        # Comware basic ACL default handling is deliberately not inferred.
        if remaining:
            issue(kind, number)
            return
        evidence = tuple(loc(e[3]) for e in entries)
        put(kind, scope, ",".join(map(str, allowed)), number, evidence)

    context = "global"
    skip_until = 0
    for number, raw in enumerate(lines, 1):
        if number <= skip_until:
            continue
        line = raw.strip()
        if not line or line.startswith(("!", ";")):
            continue
        if line in ("#", "exit", "quit", "return"):
            context = "global"
            continue
        banner = re.match(r"(?:banner (?:motd|exec)|header login)\s+(.+)", line)
        if banner:
            body = banner[1]
            delimiter = body[0]
            tail = body[1:]
            end = number
            while delimiter not in tail and end < len(lines):
                tail += "\n" + lines[end]
                end += 1
            skip_until = end
            if delimiter in tail:
                put(
                    "banner",
                    "login",
                    str(bool(tail.split(delimiter, 1)[0].strip())).lower(),
                    number,
                    (loc(end),),
                )
            else:
                issue_all(number)
            continue
        # Never interpret banner/help text as configuration commands.
        if line.startswith(("header ", "banner ")):
            issue_all(number)
            skip_until = len(lines)
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            for kind in (
                "telnet",
                "http",
                "admin_sources",
                "snmp_legacy",
                "snmp_write",
                "snmp_sources",
                "syslog",
                "ntp",
                "timeout",
                "banner",
            ):
                issue(kind, number)
            continue
        if not tokens:
            continue
        if platform == "comware" and re.fullmatch(
            r"(?:user-interface|line) (?:vty|aux|console).*", line
        ):
            context = line
            continue
        if raw and not raw[0].isspace():
            context = "global"
        if (
            re.match(
                r"(?:interface |vlan |ip access-list |access-list ip |"
                r"acl (?:number |basic |advanced )?\d)",
                line,
            )
            and context == "global"
        ):
            context = line
            continue
        is_global = context == "global"
        if not is_global and not context.startswith(("user-interface ", "line ")):
            continue
        switches: dict[str, tuple[ManagementKind, str]] = {}
        if platform == "aos-switch":
            switches = {
                "telnet-server": ("telnet", "true"),
                "no telnet-server": ("telnet", "false"),
                "web-management plaintext": ("http", "true"),
                "no web-management plaintext": ("http", "false"),
            }
        elif platform == "comware":
            switches = {
                "telnet server enable": ("telnet", "true"),
                "undo telnet server enable": ("telnet", "false"),
                "ip http enable": ("http", "true"),
                "undo ip http enable": ("http", "false"),
            }
        if line in switches and is_global:
            kind, value = switches[line]
            put(kind, "global", value, number)
            continue
        if (
            platform == "aos-cx"
            and is_global
            and line in {"snmp-server snmpv3-only", "no snmp-server snmpv3-only"}
        ):
            put("snmp_legacy", "global", str(line.startswith("no ")).lower(), number)
            continue
        if platform == "comware" and context.startswith(("user-interface vty", "line vty")):
            match = re.fullmatch(r"acl (\d+) inbound", line)
            if match:
                acl_sources("admin_sources", match[1], context, number)
                continue
        if platform == "aos-switch" and line.startswith("ip authorized-managers "):
            match = re.fullmatch(
                r"ip authorized-managers ([\d.]+)(?: ([\d.]+))?"
                r"(?: access (?:manager|operator))?(?: access-method (\w+))?",
                line,
            )
            try:
                if match is None:
                    raise ValueError
                manager_network = str(IPv4Network(f"{match[1]}/{match[2] or '32'}", strict=False))
                method = match[3] or "all"
                if method not in {"all", "ssh", "telnet", "web", "snmp", "tftp"}:
                    raise ValueError
                if method in {"all", "ssh", "telnet", "web"}:
                    put("admin_sources", f"{method}:{number}", manager_network, number)
                if method in {"all", "snmp"}:
                    put("snmp_sources", f"{method}:{number}", manager_network, number)
            except ValueError:
                issue("admin_sources", number)
                issue("snmp_sources", number)
            continue
        if platform == "comware" and line.startswith("snmp-agent sys-info version "):
            versions = tokens[3:]
            if versions and set(versions) <= {"v1", "v2c", "v3", "all"}:
                put(
                    "snmp_legacy",
                    "global",
                    str(bool(set(versions) & {"v1", "v2c", "all"})).lower(),
                    number,
                )
            else:
                issue("snmp_legacy", number)
            continue
        if platform == "comware" and line.startswith("snmp-agent community "):
            match = re.fullmatch(
                r"snmp-agent community (read|write) (?:simple |cipher )?\S+(?: acl (\d+))?", line
            )
            if match:
                scope = f"community-line:{number}"
                put("snmp_write", scope, str(match[1] == "write").lower(), number)
                if match[2]:
                    acl_sources("snmp_sources", match[2], scope, number)
                elif source.configuration_complete:
                    put("snmp_sources", scope, "0.0.0.0/0", number)
                else:
                    issue("snmp_sources", number)
            else:
                issue("snmp_write", number)
                issue("snmp_sources", number)
            continue
        if platform == "aos-switch" and line.startswith("snmp-server community "):
            if len(tokens) >= 3 and set(tokens[3:]) <= {
                "operator",
                "manager",
                "restricted",
                "unrestricted",
            }:
                put("snmp_legacy", "global", "true", number)
                if "restricted" in tokens[3:] or "unrestricted" in tokens[3:]:
                    put(
                        "snmp_write",
                        f"community-line:{number}",
                        str("unrestricted" in tokens[3:]).lower(),
                        number,
                    )
                else:
                    issue("snmp_write", number)
            else:
                issue("snmp_legacy", number)
                issue("snmp_write", number)
            continue
        if platform == "aos-switch" and line == "snmpv3 only":
            put("snmp_legacy", "v3-only", "false", number)
            continue
        if line in {"info-center enable", "timesync ntp", "ntp enable", "ntp unicast"}:
            continue
        server_patterns: tuple[tuple[ManagementKind, str], ...] = (
            ("syslog", r"info-center loghost (\S+)" if platform == "comware" else r"logging (\S+)"),
            (
                "ntp",
                r"ntp-service unicast-server (\S+)"
                if platform == "comware"
                else r"ntp server(?:-name)? (\S+)(?: iburst)?",
            ),
        )
        handled = False
        for kind, pattern in server_patterns:
            match = re.fullmatch(pattern, line)
            if match:
                try:
                    if match[1] in {
                        "severity",
                        "facility",
                        "on",
                        "off",
                        "origin-id",
                        "vrf",
                        "host",
                    }:
                        raise ValueError
                    value = normalize_server(match[1].strip('"'))
                    put(kind, value, value, number)
                except ValueError:
                    issue(kind, number)
                handled = True
                break
        if handled:
            continue
        timeout_pattern = (
            r"idle-timeout (\d+)(?: (\d+))?"
            if platform == "comware"
            else r"console idle-timeout (\d+)"
            if platform == "aos-switch"
            else r"session-timeout (\d+)"
        )
        match = re.fullmatch(timeout_pattern, line)
        if match:
            if platform == "comware" and not context.startswith(("user-interface ", "line ")):
                issue("timeout", number)
                continue
            seconds = int(match[1])
            if platform == "comware":
                seconds = seconds * 60 + int(match[2] or 0)
                if int(match[2] or 0) > 59:
                    issue("timeout", number)
                    continue
            elif platform == "aos-cx":
                seconds *= 60
            put("timeout", context, str(seconds), number)
            continue
        # Any unhandled relevant syntax prevents a clean result in that domain.
        stripped = re.sub(r"^(?:no|undo) ", "", line)
        prefixes: tuple[tuple[tuple[str, ...], tuple[ManagementKind, ...]], ...] = (
            (("telnet",), ("telnet",)),
            (("web-management", "http-server", "ip http "), ("http",)),
            (
                ("ip authorized-managers", "ssh server", "apply access-list", "acl "),
                ("admin_sources",),
            ),
            (("snmp",), ("snmp_legacy", "snmp_write", "snmp_sources")),
            (("logging", "info-center"), ("syslog",)),
            (("ntp", "timesync", "sntp"), ("ntp",)),
            (("idle-timeout", "console idle-timeout", "session-timeout"), ("timeout",)),
            (("banner", "header"), ("banner",)),
        )
        for starts, kinds in prefixes:
            if stripped.startswith(starts):
                for kind in kinds:
                    issue(kind, number)

    if ("snmp_legacy", "v3-only") in facts:
        facts.pop(("snmp_legacy", "global"), None)
        if any(f.kind == "snmp_write" and f.value == "true" for f in facts.values()):
            issue(
                "snmp_write", facts[("snmp_legacy", "v3-only")].source_locations[0].line_start or 1
            )
    return ManagementInventory(
        platform=platform,
        complete_export=source.configuration_complete,
        source_location=loc(1),
        facts=tuple(facts.values()),
        issues=tuple(issues),
    )
