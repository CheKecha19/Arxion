"""Ограниченный IPv4 ACL adapter AOS-Switch/AOS-CX; management отдельно от transit."""

from __future__ import annotations

import re
import shlex
from collections import Counter
from dataclasses import dataclass, field, replace
from ipaddress import IPv4Address, IPv4Network
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from firewall_compliance.domain import (
    Configuration,
    DataStatus,
    Endpoint,
    EndpointKind,
    ParseCoverage,
    ParseIssue,
    ParseIssueLevel,
    ParseResult,
    PortRange,
    Protocol,
    Rule,
    RuleAction,
    Service,
    SourceLocation,
    UnsupportedConstruct,
)
from firewall_compliance.parsers.contracts import (
    DetectionResult,
    ParseFailure,
    ParseOutcome,
    ParseRequest,
    ParserMetadata,
    SourceDocument,
)
from firewall_compliance.parsers.management import parse_management

_PORTS = {
    "ssh": 22,
    "telnet": 23,
    "www": 80,
    "http": 80,
    "https": 443,
    "domain": 53,
    "dns": 53,
    "snmp": 161,
    "snmptrap": 162,
    "tftp": 69,
    "ftp": 21,
    "ntp": 123,
}
_PLACEHOLDER = re.compile(r"ip#?\d+(?:/[^\s]+)?$", re.IGNORECASE)
_IPV4 = re.compile(r"\d+\.\d+\.\d+\.\d+$")
_DIRECTIONS = {"in", "out", "routed-in", "routed-out"}
_PORT_OPERATORS = {"eq", "gt", "lt", "range", "neq", "group"}


@dataclass(frozen=True)
class _Binding:
    scope: str
    mode: str
    location: SourceLocation


@dataclass(frozen=True)
class _Entry:
    acl: str
    kind: Literal["standard", "extended"]
    tokens: tuple[str, ...]
    line: int
    description: str | None = None
    comment_line: int | None = None
    description_unknown: bool = False


@dataclass
class _Diagnostics:
    source_name: str
    discovered: set[int] = field(default_factory=set)
    unsupported_lines: set[int] = field(default_factory=set)
    warnings: list[ParseIssue] = field(default_factory=list)
    unsupported: list[UnsupportedConstruct] = field(default_factory=list)
    source_map: dict[str, SourceLocation] = field(default_factory=dict)

    def location(self, line: int) -> SourceLocation:
        return SourceLocation(source_name=self.source_name, line_start=line, line_end=line)

    def reject(self, line: int, code: str, message: str, kind: str = "acl") -> None:
        if code == "HP_ARUBA_COMMENT_LIMITED":
            kind = "comment"
        self.discovered.add(line)
        already_unsupported = line in self.unsupported_lines
        self.unsupported_lines.add(line)
        if not any(
            issue.code == code and issue.source_location == self.location(line)
            for issue in self.warnings
        ):
            self.warnings.append(
                ParseIssue(
                    code=code,
                    level=ParseIssueLevel.WARNING,
                    message=message,
                    source_location=self.location(line),
                )
            )
        if not already_unsupported:
            self.unsupported.append(
                UnsupportedConstruct(
                    construct_type=kind,
                    message=message,
                    source_location=self.location(line),
                )
            )


class HpArubaParser:
    """Распознать характерный HP/Aruba export и сохранить ACL с ограничениями."""

    _metadata = ParserMetadata(parser_id="hp-aruba-acl", version="0.2.0", vendor="hp-aruba")

    @property
    def metadata(self) -> ParserMetadata:
        return self._metadata

    def detect(self, source: SourceDocument) -> DetectionResult:
        """Определить семейство по содержимому, не по имени или расширению файла."""
        try:
            text = source.content.decode("utf-8-sig")
        except UnicodeDecodeError:
            return DetectionResult(parser_id=self.metadata.parser_id, is_match=False, confidence=0)
        platform = _platform(text)
        return DetectionResult(
            parser_id=self.metadata.parser_id,
            is_match=platform is not None,
            confidence=0.96 if platform is not None else 0,
            reasons=("Обнаружены характерные директивы HP/Aruba; подлинность export не проверена.",)
            if platform is not None
            else (),
        )

    def parse(self, request: ParseRequest) -> ParseOutcome:
        """Разобрать ACL/authorized-managers без вычисления пути и implicit deny."""
        try:
            text = request.source.content.decode("utf-8-sig")
        except UnicodeDecodeError:
            return _failure(
                request,
                self.metadata.parser_id,
                "HP_ARUBA_ENCODING",
                "Поддержана только текстовая UTF-8 конфигурация.",
            )
        platform = _platform(text)
        if platform is None:
            return _failure(
                request,
                self.metadata.parser_id,
                "HP_ARUBA_FORMAT",
                "Нет однозначных признаков поддержанного HP/Aruba формата.",
            )
        if platform == "arubaos-controller":
            return _failure(
                request,
                self.metadata.parser_id,
                "ARUBAOS_CONTROLLER_UNSUPPORTED",
                "ArubaOS controller session ACL/user-role распознаны, но не поддержаны.",
            )
        diagnostics = _Diagnostics(request.source.source_name)
        entries, bindings, managers, hostname = _collect(text, diagnostics)
        entries = _with_comments(entries, platform, diagnostics)
        permit_log_supported = _permit_log_supported(text, platform)
        config = Configuration(
            device_id=hostname or f"hp-aruba:{request.source.content_sha256[:16]}",
            vendor=self.metadata.vendor,
            platform=platform,
            parser_version=self.metadata.version,
            source_name=request.source.source_name,
            content_sha256=request.source.content_sha256,
            captured_at=request.source.captured_at,
            imported_at=request.imported_at,
        )
        rules: list[Rule] = []
        source_map: dict[str, SourceLocation] = dict(diagnostics.source_map)
        sequences: dict[str, int] = {}
        sequence_counts: Counter[tuple[str, int]] = Counter()
        for entry in entries:
            sequence = (
                int(entry.tokens[0])
                if entry.tokens and entry.tokens[0].isdigit()
                else (sequences.get(entry.acl, 0) + 10)
            )
            sequences[entry.acl] = max(sequences.get(entry.acl, 0), sequence)
            sequence_counts[(entry.acl, sequence)] += 1
        sequences.clear()
        for entry in entries:
            explicit = bool(entry.tokens and entry.tokens[0].isdigit())
            sequence = int(entry.tokens[0]) if explicit else sequences.get(entry.acl, 0) + 10
            sequences[entry.acl] = max(sequences.get(entry.acl, 0), sequence)
            tokens = entry.tokens[1:] if explicit else entry.tokens
            duplicate = sequence_counts[(entry.acl, sequence)] > 1
            if duplicate:
                diagnostics.reject(
                    entry.line,
                    "HP_ARUBA_SEQUENCE_CONFLICT",
                    "Повторный sequence не доказывает порядок ACL.",
                )
            scopes: list[_Binding | None] = list(bindings.get(entry.acl, ())) or [None]
            for index, binding in enumerate(scopes):
                try:
                    rule = _acl_rule(
                        config,
                        entry,
                        tokens,
                        sequence,
                        binding,
                        platform,
                        diagnostics,
                        index,
                        duplicate,
                        permit_log_supported,
                    )
                except (IndexError, ValueError):
                    diagnostics.reject(
                        entry.line,
                        "HP_ARUBA_ACE_INVALID",
                        "Неполная или повреждённая ACE; правило не восстановлено.",
                    )
                    break
                rules.append(rule)
                source_map[rule.rule_id] = rule.source_location
                if entry.comment_line is not None:
                    source_map[f"description:{rule.rule_id}"] = diagnostics.location(
                        entry.comment_line
                    )
                if binding is not None:
                    source_map[f"binding:{rule.rule_id}"] = binding.location
        for line, tokens in managers:
            try:
                rule = _manager_rule(config, line, tokens, diagnostics)
            except (IndexError, ValueError):
                diagnostics.reject(
                    line,
                    "HP_ARUBA_MANAGER_INVALID",
                    "Неполный authorized-managers; область доступа неизвестна.",
                    "management-access",
                )
                continue
            rules.append(rule)
            source_map[rule.rule_id] = rule.source_location
        for acl, linked_scopes in bindings.items():
            if not any(entry.acl == acl for entry in entries):
                for binding in linked_scopes:
                    diagnostics.reject(
                        binding.location.line_start or 1,
                        "HP_ARUBA_BINDING_WITHOUT_ACL",
                        "Привязка ссылается на ACL без распознанных ACE.",
                        "binding",
                    )
        warnings = [
            ParseIssue(
                code="HP_ARUBA_SCOPE_LIMITED",
                level=ParseIssueLevel.WARNING,
                message="Разобран только ограниченный IPv4 ACL/management срез. NAT, topology, "
                "операционное состояние, неявные действия и общая полнота не доказаны.",
                source_location=diagnostics.location(1),
            ),
            *diagnostics.warnings,
        ]
        endpoints = {
            ep.endpoint_id: ep for rule in rules for ep in (*rule.sources, *rule.destinations)
        }
        services = {service.service_id: service for rule in rules for service in rule.services}
        return ParseResult(
            configuration=config,
            management=parse_management(request.source, platform),
            rules=tuple(rules),
            endpoints=tuple(endpoints.values()),
            services=tuple(services.values()),
            warnings=tuple(warnings),
            unsupported_constructs=tuple(diagnostics.unsupported),
            source_map=source_map,
            coverage=ParseCoverage(
                discovered_constructs=len(diagnostics.discovered),
                recognized_constructs=len(diagnostics.discovered - diagnostics.unsupported_lines),
                unsupported_constructs=len(diagnostics.unsupported_lines),
            ),
        )


def _platform(text: str) -> str | None:
    lowered = text.lower()
    if re.search(r"^\s*(?:asa version|set version|version \d.*comware)", lowered, re.MULTILINE):
        return None
    if re.search(r"^\s*ip access-list session\s", lowered, re.MULTILINE) and re.search(
        r"^\s*(?:user-role|wlan)\s", lowered, re.MULTILINE
    ):
        return "arubaos-controller"
    has_cx = bool(
        re.search(
            r"^\s*[!;#]?\s*(?:version\s+)?(?:arubaos-cx|aos-cx|aruba os-cx)\b",
            lowered,
            re.MULTILINE,
        )
    )
    has_switch = "configuration editor" in lowered or "arubaos-switch" in lowered
    has_manager = bool(re.search(r"^\s*ip authorized-managers\s", lowered, re.MULTILINE))
    has_cx_acl = bool(re.search(r"^\s*access-list ip\s+\S+", lowered, re.MULTILINE))
    has_cx_binding = bool(re.search(r"^\s*apply access-list ip\s", lowered, re.MULTILINE))
    if has_cx and has_switch:
        return None
    if has_cx or has_cx_acl and has_cx_binding:
        return "aos-cx"
    if has_switch or has_manager:
        return "aos-switch"
    return None


def _failure(request: ParseRequest, parser_id: str, code: str, message: str) -> ParseFailure:
    return ParseFailure(
        parser_id=parser_id,
        source_name=request.source.source_name,
        content_sha256=request.source.content_sha256,
        errors=(ParseIssue(code=code, level=ParseIssueLevel.ERROR, message=message),),
    )


def _collect(
    text: str,
    diagnostics: _Diagnostics,
) -> tuple[list[_Entry], dict[str, list[_Binding]], list[tuple[int, tuple[str, ...]]], str | None]:
    entries: list[_Entry] = []
    bindings: dict[str, list[_Binding]] = {}
    managers: list[tuple[int, tuple[str, ...]]] = []
    hostname: str | None = None
    current_acl: tuple[str, Literal["standard", "extended"]] | None = None
    scope: str | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("!") or line in {"exit", "end"}:
            current_acl = None
            scope = None
            continue
        if current_acl is not None and raw[:1].isspace():
            diagnostics.source_map[f"acl-range:{current_acl[0]}:{number}"] = diagnostics.location(
                number
            )
        try:
            tokens = tuple(shlex.split(line, comments=False))
        except ValueError:
            if current_acl is not None and raw[:1].isspace():
                code = (
                    "HP_ARUBA_COMMENT_LIMITED"
                    if re.match(r"(?:\d+\s+)?(?:remark|comment)\b", line)
                    else "HP_ARUBA_TOKENIZATION"
                )
                diagnostics.reject(number, code, "Повреждённая директива внутри ACL.")
            elif any(
                marker in line for marker in ("access-list", "authorized-managers", "access-group")
            ):
                diagnostics.reject(number, "HP_ARUBA_TOKENIZATION", "Повреждённая ACL-директива.")
            continue
        if not tokens:
            continue
        if current_acl is not None and raw[:1].isspace():
            diagnostics.source_map[f"acl-range:{current_acl[0]}:{number}"] = diagnostics.location(
                number
            )
        if tokens[0] == "hostname" and len(tokens) == 2:
            hostname = tokens[1]
            current_acl = None
        elif tokens[:2] == ("ip", "authorized-managers"):
            current_acl = None
            managers.append((number, tokens))
            diagnostics.discovered.add(number)
        elif tokens[:2] == ("ip", "access-list"):
            diagnostics.discovered.add(number)
            scope = None
            if len(tokens) >= 4 and tokens[2] in {"standard", "extended"}:
                current_acl = (tokens[3], "standard" if tokens[2] == "standard" else "extended")
                diagnostics.source_map[f"acl-range:{tokens[3]}:{number}"] = diagnostics.location(
                    number
                )
                assert current_acl is not None
                if len(tokens) > 4:
                    entries.append(_Entry(current_acl[0], current_acl[1], tokens[4:], number))
            else:
                current_acl = None
                diagnostics.reject(number, "HP_ARUBA_ACL_HEADER", "Неподдержанный ACL header.")
        elif tokens[:2] == ("access-list", "ip"):
            diagnostics.discovered.add(number)
            scope = None
            if len(tokens) >= 3:
                current_acl = (tokens[2], "extended")
                diagnostics.source_map[f"acl-range:{tokens[2]}:{number}"] = diagnostics.location(
                    number
                )
                assert current_acl is not None
                if len(tokens) > 3:
                    entries.append(_Entry(current_acl[0], current_acl[1], tokens[3:], number))
            else:
                current_acl = None
                diagnostics.reject(number, "HP_ARUBA_ACL_HEADER", "Неполный CX ACL header.")
        elif tokens[0] == "access-list":
            current_acl = None
            diagnostics.discovered.add(number)
            if len(tokens) >= 3 and tokens[1].isdigit() and 1 <= int(tokens[1]) <= 199:
                kind: Literal["standard", "extended"] = (
                    "standard" if int(tokens[1]) < 100 else "extended"
                )
                entries.append(_Entry(tokens[1], kind, tokens[2:], number))
                diagnostics.source_map[f"acl-range:{tokens[1]}:{number}"] = diagnostics.location(
                    number
                )
            else:
                diagnostics.reject(number, "HP_ARUBA_NUMBERED_ACL", "Неизвестный numbered ACL.")
        elif tokens[0] in {"interface", "vlan"}:
            current_acl = None
            scope = ":".join(tokens)
        elif tokens[:2] == ("ip", "access-group") or tokens[:3] == ("apply", "access-list", "ip"):
            current_acl = None
            diagnostics.discovered.add(number)
            index = 2 if tokens[0] == "ip" else 3
            if len(tokens) > index:
                diagnostics.source_map[f"acl-binding:{tokens[index]}:{number}"] = (
                    diagnostics.location(number)
                )
            if (
                tokens[0] == "apply"
                and len(tokens) == index + 4
                and tokens[index + 1 : index + 3] == ("control-plane", "vrf")
            ):
                binding = _Binding(
                    f"management-plane:vrf:{tokens[-1]}",
                    "control-plane",
                    diagnostics.location(number),
                )
                bindings.setdefault(tokens[index], []).append(binding)
            elif len(tokens) == index + 2 and tokens[-1] in _DIRECTIONS and scope is not None:
                binding = _Binding(scope, tokens[-1], diagnostics.location(number))
                if binding not in bindings.setdefault(tokens[index], []):
                    bindings[tokens[index]].append(binding)
            else:
                diagnostics.reject(
                    number,
                    "HP_ARUBA_BINDING_UNSUPPORTED",
                    "Привязка не имеет поддержанного interface/VLAN направления.",
                    "binding",
                )
        elif current_acl is not None:
            diagnostics.discovered.add(number)
            diagnostics.source_map[f"acl-range:{current_acl[0]}:{number}"] = diagnostics.location(
                number
            )
            body = tokens[1:] if tokens[0].isdigit() else tokens
            if body and body[0] in {"permit", "deny"} or body and body[0] in {"remark", "comment"}:
                entries.append(_Entry(current_acl[0], current_acl[1], tokens, number))
            elif raw[:1].isspace():
                diagnostics.reject(
                    number,
                    "HP_ARUBA_ACL_CHILD_UNSUPPORTED",
                    "Неподдержанный элемент ACL не влияет на разрешённые условия.",
                )
            else:
                diagnostics.discovered.discard(number)
                current_acl = None
        elif (
            tokens[:2] in {("ipv6", "access-list"), ("no", "access-list")}
            or (tokens[:3] == ("apply", "access-list", "ipv6"))
            or tokens[:3]
            in {
                ("no", "ip", "access-list"),
                ("no", "ip", "authorized-managers"),
                ("no", "ip", "access-group"),
                ("no", "apply", "access-list"),
            }
        ):
            diagnostics.reject(
                number,
                "HP_ARUBA_NON_IPV4_UNSUPPORTED",
                "IPv6 или изменение ACL не входит в поддержанный IPv4 snapshot.",
            )
        elif not raw[:1].isspace():
            scope = None
    return entries, bindings, managers, hostname


def _unknown_endpoint(name: str) -> Endpoint:
    return Endpoint(
        endpoint_id=f"object:{name}",
        name=name,
        kind=EndpointKind.OBJECT,
        resolution_status=DataStatus.UNKNOWN,
    )


def _with_comments(entries: list[_Entry], platform: str, diagnostics: _Diagnostics) -> list[_Entry]:
    """Связать комментарии с sequence ACE, не добавляя их в условия пакета.

    AOS-S remark предшествует ACE и может иметь её автоматически назначенный sequence.
    CX comment с явным sequence может следовать за ACE. У CX comment без sequence
    нет достоверной связи с правилом в снимке; такая запись остаётся ограничением.
    """
    result: list[_Entry] = []
    sequences: dict[str, int] = {}
    comments: dict[tuple[str, int], list[_Entry]] = {}
    pending: _Entry | None = None
    for entry in entries:
        explicit = bool(entry.tokens and entry.tokens[0].isdigit())
        body = entry.tokens[1:] if explicit else entry.tokens
        sequence = int(entry.tokens[0]) if explicit else None
        if body and body[0] in {"remark", "comment"}:
            expected = "remark" if platform == "aos-switch" else "comment"
            if body[0] != expected or len(body) < 2 or (sequence is None and platform == "aos-cx"):
                diagnostics.reject(
                    entry.line,
                    "HP_ARUBA_COMMENT_LIMITED",
                    "Комментарий не имеет однозначной поддержанной привязки к ACE.",
                )
                pending = None
                continue
            comment = replace(entry, description=" ".join(body[1:]))
            if sequence is not None:
                comments.setdefault((entry.acl, sequence), []).append(comment)
            else:
                if pending is not None and not pending.tokens[0].isdigit():
                    diagnostics.reject(
                        pending.line,
                        "HP_ARUBA_COMMENT_LIMITED",
                        "Несколько комментариев без sequence не связаны с ACE.",
                    )
                pending = comment
            if platform == "aos-switch":
                pending = comment
            continue
        if sequence is None:
            if pending is not None and pending.acl == entry.acl and pending.tokens[0].isdigit():
                sequence = int(pending.tokens[0])
            else:
                sequence = sequences.get(entry.acl, 0) + 10
        sequences[entry.acl] = max(sequences.get(entry.acl, 0), sequence)
        if pending is not None and not pending.tokens[0].isdigit():
            if pending.acl == entry.acl:
                comments.setdefault((entry.acl, sequence), []).append(pending)
            else:
                diagnostics.reject(
                    pending.line,
                    "HP_ARUBA_COMMENT_LIMITED",
                    "Комментарий без sequence не продолжен ACE той же ACL.",
                )
        pending = None
        result.append(replace(entry, tokens=(str(sequence), *body)))
    if pending is not None and not pending.tokens[0].isdigit():
        diagnostics.reject(
            pending.line, "HP_ARUBA_COMMENT_LIMITED", "Комментарий без sequence не продолжен ACE."
        )
    targets = {(entry.acl, int(entry.tokens[0])) for entry in result}
    for key, values in comments.items():
        if key not in targets or len(values) != 1:
            for value in values:
                diagnostics.reject(
                    value.line,
                    "HP_ARUBA_COMMENT_LIMITED",
                    "Комментарий не имеет единственной ACE-привязки.",
                )
    uncertain_lines = {
        issue.source_location.line_start
        for issue in diagnostics.warnings
        if issue.code == "HP_ARUBA_COMMENT_LIMITED" and issue.source_location is not None
    }
    uncertain_acls = {entry.acl for entry in entries if entry.line in uncertain_lines}
    uncertain_acls.update(
        key.removeprefix("acl-range:").rsplit(":", 1)[0]
        for key, location in diagnostics.source_map.items()
        if key.startswith("acl-range:") and location.line_start in uncertain_lines
    )
    for index, entry in enumerate(result):
        values = comments.get((entry.acl, int(entry.tokens[0])), [])
        if len(values) == 1:
            result[index] = replace(
                entry, description=values[0].description, comment_line=values[0].line
            )
        elif values or entry.acl in uncertain_acls:
            result[index] = replace(entry, description_unknown=True)
    return result


def _permit_log_supported(text: str, platform: str) -> bool:
    """Проверить документированную версию синтаксиса, не гарантируя runtime logging."""
    pattern = (
        r"\b(?:[A-Z]{1,3}\.)?(16)\.(\d+)\.\d+\b"
        if platform == "aos-switch"
        else r"\b(?:[A-Z]{1,3}\.)?(10)\.(\d+)\.\d+\b"
    )
    version_lines = "\n".join(
        line
        for line in text.splitlines()
        if re.search(r"\b(?:version|release)\b", line, re.IGNORECASE)
    )
    releases = [(int(match[0]), int(match[1])) for match in re.findall(pattern, version_lines)]
    minimum = (16, 10) if platform == "aos-switch" else (10, 13)
    return bool(releases) and all(release >= minimum for release in releases)


def _address(tokens: tuple[str, ...], index: int, *, wildcard: bool) -> tuple[Endpoint, int]:
    token = tokens[index]
    if token == "any":
        return Endpoint(endpoint_id="any:ipv4", name="any", kind=EndpointKind.ANY), index + 1
    host = token == "host"
    if host:
        index += 1
        token = tokens[index]
    next_index = index + 1
    mask: str | None = None
    if wildcard and not host and "/" not in token and next_index < len(tokens):
        candidate = tokens[next_index]
        if _IPV4.fullmatch(candidate) or _PLACEHOLDER.fullmatch(candidate):
            mask = candidate
            next_index += 1
    if _PLACEHOLDER.fullmatch(token):
        return _unknown_endpoint(token), next_index
    try:
        if mask is not None:
            inverse = int(IPv4Address(mask))
            if inverse & (inverse + 1):
                return _unknown_endpoint(token), next_index
            network = IPv4Network(f"{token}/{32 - inverse.bit_count()}", strict=False)
        else:
            network = IPv4Network(token if "/" in token else f"{token}/32", strict=False)
        return Endpoint(
            endpoint_id=f"network:{network}",
            name=str(network),
            kind=EndpointKind.HOST if network.prefixlen == 32 else EndpointKind.SUBNET,
            cidrs=(str(network),),
        ), next_index
    except ValueError:
        return _unknown_endpoint(token), next_index


def _port(value: str) -> int:
    port = int(value) if value.isdigit() else _PORTS[value.lower()]
    if not 1 <= port <= 65535:
        raise ValueError("порт вне поддержанного диапазона")
    return port


def _ports(tokens: tuple[str, ...], index: int) -> tuple[tuple[PortRange, ...], int, bool]:
    if index >= len(tokens) or tokens[index] not in _PORT_OPERATORS:
        return (), index, False
    operator = tokens[index]
    if operator == "group":
        return (), min(index + 2, len(tokens)), True
    consumed = 3 if operator == "range" else 2
    try:
        first = _port(tokens[index + 1])
        second = _port(tokens[index + 2]) if operator == "range" else first
        if operator == "eq" or operator == "range":
            result = (PortRange(start=first, end=second),)
        elif operator == "gt" and first < 65535:
            result = (PortRange(start=first + 1, end=65535),)
        else:
            return (), min(index + consumed, len(tokens)), True
        return result, index + consumed, False
    except (IndexError, KeyError, ValueError):
        return (), min(index + consumed, len(tokens)), True


def _acl_rule(
    config: Configuration,
    entry: _Entry,
    tokens: tuple[str, ...],
    sequence: int,
    binding: _Binding | None,
    platform: str,
    diagnostics: _Diagnostics,
    binding_index: int,
    duplicate: bool,
    permit_log_supported: bool,
) -> Rule:
    if tokens[0] not in {"permit", "deny"}:
        raise ValueError("неизвестное действие")
    action = RuleAction.ALLOW if tokens[0] == "permit" else RuleAction.DENY
    if entry.kind == "standard":
        protocol = Protocol.IP
        source, index = _address(tokens, 1, wildcard=platform == "aos-switch")
        destination = Endpoint(endpoint_id="any:ipv4", name="any", kind=EndpointKind.ANY)
        ports: tuple[PortRange, ...] = ()
        service_unknown = False
    else:
        protocol_token = tokens[1]
        protocol = {
            "ip": Protocol.IP,
            "any": Protocol.IP,
            "tcp": Protocol.TCP,
            "udp": Protocol.UDP,
            "icmp": Protocol.ICMP,
            "6": Protocol.TCP,
            "17": Protocol.UDP,
            "1": Protocol.ICMP,
        }.get(protocol_token, Protocol.OTHER)
        source, index = _address(tokens, 2, wildcard=platform == "aos-switch")
        _, index, source_ports_unknown = _ports(tokens, index)
        # Любая source-port операция не представима текущим Service, даже если число распознано.
        source_port_present = any(token in _PORT_OPERATORS for token in tokens[2:index])
        destination, index = _address(tokens, index, wildcard=platform == "aos-switch")
        ports, index, destination_ports_unknown = _ports(tokens, index)
        service_unknown = (
            protocol == Protocol.OTHER
            or source_port_present
            or source_ports_unknown
            or destination_ports_unknown
            or bool(ports)
            and protocol not in {Protocol.TCP, Protocol.UDP}
        )
    suffix = tokens[index:]
    allowed_suffix = {"log", "count"}
    suffix_unknown = any(token not in allowed_suffix for token in suffix) or len(
        set(suffix)
    ) != len(suffix)
    log_unknown = "log" in suffix and action == RuleAction.ALLOW and not permit_log_supported
    unresolved = (
        source.resolution_status != DataStatus.KNOWN
        or destination.resolution_status != DataStatus.KNOWN
    )
    if unresolved:
        diagnostics.reject(
            entry.line,
            "HP_ARUBA_ADDRESS_UNRESOLVED",
            "Замаскированный адрес/объект или неподдержанная маска остаются unknown.",
        )
    if service_unknown:
        diagnostics.reject(
            entry.line,
            "HP_ARUBA_SERVICE_UNSUPPORTED",
            "Протокол/порт или source-port условие не представимы без потери семантики.",
        )
    if suffix_unknown:
        diagnostics.reject(
            entry.line,
            "HP_ARUBA_ACE_SUFFIX_UNSUPPORTED",
            "Дополнительные match-условия ACE не вычисляются.",
        )
    if log_unknown:
        diagnostics.reject(
            entry.line,
            "HP_ARUBA_LOGGING_VERSION_UNKNOWN",
            "Permit log зависит от платформы/версии; поддержанная версия не установлена.",
            "logging",
        )
    management_binding = binding is not None and binding.mode == "control-plane"
    known = not (unresolved or service_unknown or suffix_unknown or duplicate or management_binding)
    service_status = DataStatus.UNKNOWN if service_unknown else DataStatus.KNOWN
    service = Service(
        service_id=f"service:{protocol.value}:{ports}:{'unknown' if service_unknown else 'known'}",
        name=protocol.value,
        protocol=protocol,
        port_ranges=ports if protocol in {Protocol.TCP, Protocol.UDP} else (),
        resolution_status=service_status,
    )
    direction: Literal["in", "out"] | None = None
    source_zone = destination_zone = None
    policy_id = f"acl:{entry.acl}:unbound"
    if binding is not None:
        direction = "in" if binding.mode in {"in", "routed-in", "control-plane"} else "out"
        zone = f"{binding.scope}:{binding.mode}"
        source_zone = zone if direction == "in" else None
        destination_zone = zone if direction == "out" else None
        policy_id = f"acl:{entry.acl}@{zone}"
        if management_binding:
            source_zone = "management-source"
            destination_zone = binding.scope
            policy_id = f"management:acl:{entry.acl}@{binding.scope}"
    identifier = str(
        uuid5(NAMESPACE_URL, f"hp-aruba:{config.content_sha256}:{entry.line}:{binding_index}")
    )
    return Rule(
        rule_id=identifier,
        configuration_id=config.configuration_id,
        name=f"{entry.acl} sequence {sequence}",
        sequence=sequence,
        action=action,
        enabled=True,
        sources=(source,),
        destinations=(destination,),
        services=(service,),
        source_zone=source_zone,
        destination_zone=destination_zone,
        policy_id=policy_id,
        policy_direction=direction,
        policy_semantics="first_match" if not duplicate else None,
        match_status=DataStatus.KNOWN if known else DataStatus.UNKNOWN,
        source_status=source.resolution_status,
        destination_status=destination.resolution_status,
        service_status=service_status,
        zone_status=DataStatus.KNOWN if binding else DataStatus.UNKNOWN,
        logging_enabled="log" in suffix if not (suffix_unknown or log_unknown) else None,
        logging_status=DataStatus.KNOWN
        if not (suffix_unknown or log_unknown)
        else DataStatus.UNKNOWN,
        description=entry.description,
        description_status=DataStatus.UNKNOWN
        if entry.description_unknown
        else DataStatus.KNOWN
        if entry.description
        else DataStatus.ABSENT,
        source_location=diagnostics.location(entry.line),
    )


def _manager_rule(
    config: Configuration,
    line: int,
    tokens: tuple[str, ...],
    diagnostics: _Diagnostics,
) -> Rule:
    address = tokens[2]
    has_mask = len(tokens) > 3 and bool(
        _IPV4.fullmatch(tokens[3]) or _PLACEHOLDER.fullmatch(tokens[3])
    )
    mask = tokens[3] if has_mask else "255.255.255.255"
    index = 4 if has_mask else 3
    if _PLACEHOLDER.fullmatch(address) or _PLACEHOLDER.fullmatch(mask):
        source = _unknown_endpoint(address)
    else:
        try:
            network = IPv4Network(f"{address}/{mask}", strict=False)
            source = Endpoint(
                endpoint_id=f"network:{network}",
                name=str(network),
                kind=EndpointKind.HOST if network.prefixlen == 32 else EndpointKind.SUBNET,
                cidrs=(str(network),),
            )
        except ValueError:
            source = _unknown_endpoint(address)
    privilege, method = "manager", "all"
    unknown = False
    while index < len(tokens):
        if tokens[index] == "access" and index + 1 < len(tokens):
            privilege = tokens[index + 1]
            unknown |= privilege not in {"manager", "operator"}
            index += 2
        elif tokens[index] == "access-method" and index + 1 < len(tokens):
            method = tokens[index + 1]
            unknown |= method not in {"all", "ssh", "telnet", "web", "snmp", "tftp"}
            index += 2
        else:
            unknown = True
            index += 1
    destination = Endpoint(
        endpoint_id="zone:management-plane",
        name="management-plane",
        kind=EndpointKind.ZONE,
        zone="management-plane",
        resolution_status=DataStatus.UNKNOWN,
    )
    service = Service(
        service_id=f"management:{method}",
        name=f"management:{method}",
        protocol=Protocol.OTHER,
        resolution_status=DataStatus.UNKNOWN,
    )
    if source.resolution_status != DataStatus.KNOWN:
        diagnostics.reject(
            line,
            "HP_ARUBA_MANAGER_ADDRESS_UNKNOWN",
            "Замаскированный manager source не разрешён в IP; доступ не расширяется.",
            "management-access",
        )
    if unknown:
        diagnostics.reject(
            line,
            "HP_ARUBA_MANAGER_SUFFIX_UNSUPPORTED",
            "Неподдержанные параметры authorized-managers ограничивают смысл записи.",
            "management-access",
        )
    return Rule(
        rule_id=f"hp-aruba:manager:{line}",
        configuration_id=config.configuration_id,
        name=f"Authorized manager {privilege}/{method}",
        sequence=line,
        action=RuleAction.ALLOW,
        enabled=True,
        sources=(source,),
        destinations=(destination,),
        services=(service,),
        source_zone="management-source",
        destination_zone="management-plane",
        policy_id=f"management:authorized-managers:{method}",
        policy_direction="in",
        policy_semantics=None,
        match_status=DataStatus.UNKNOWN,
        source_status=source.resolution_status,
        destination_status=DataStatus.UNKNOWN,
        service_status=DataStatus.UNKNOWN,
        zone_status=DataStatus.KNOWN,
        logging_enabled=None,
        logging_status=DataStatus.UNKNOWN,
        description=f"Управляющий доступ {privilege}/{method}; не transit firewall ACL.",
        description_status=DataStatus.KNOWN,
        source_location=diagnostics.location(line),
    )
