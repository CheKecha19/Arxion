"""Conservative import of classic Ideco NGFW v23 API snapshots."""

import json
import re
from typing import Any

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
from firewall_compliance.domain.network import IpRange
from firewall_compliance.parsers.contracts import (
    DetectionResult,
    ParseFailure,
    ParseOutcome,
    ParseRequest,
    ParserMetadata,
    SourceDocument,
)


class IdecoParser:
    """Preserve unsupported selectors instead of widening them to any."""

    metadata = ParserMetadata(parser_id="ideco-api", version="0.1.0", vendor="ideco")

    def detect(self, source: SourceDocument) -> DetectionResult:
        try:
            payload = json.loads(source.content)
            match = isinstance(payload, dict) and payload.get("format") == "arxion-ideco-v1"
        except (ValueError, UnicodeError):
            match = False
        return DetectionResult(
            parser_id=self.metadata.parser_id, is_match=match, confidence=1.0 if match else 0.0
        )

    def parse(self, request: ParseRequest) -> ParseOutcome:
        try:
            payload = json.loads(request.source.content)
            if not self.detect(request.source).is_match:
                raise ValueError("Unknown snapshot")
            version = str(payload["version"])
            if not re.fullmatch(r"23(?:[.][0-9A-Za-z_-]+)*", version):
                raise ValueError("Unsupported firmware")
            if payload.get("context_type") != "classic":
                raise ValueError("Unsupported context")
            for key in ("objects", "zones"):
                if not isinstance(payload[key], list):
                    raise ValueError("Invalid collection")
            for table in ("forward", "input", "dnat", "snat"):
                if not isinstance(payload["tables"][table], list):
                    raise ValueError("Invalid table")
            return self._parse(request, payload, version)
        except (ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError):
            return ParseFailure(
                parser_id=self.metadata.parser_id,
                source_name=request.source.source_name,
                content_sha256=request.source.content_sha256,
                errors=(
                    ParseIssue(
                        code="IDECO_INVALID_SNAPSHOT",
                        level=ParseIssueLevel.ERROR,
                        message="Некорректный снимок классического Ideco NGFW v23.",
                    ),
                ),
            )

    def _parse(self, request: ParseRequest, payload: dict[str, Any], version: str) -> ParseResult:
        config = Configuration(
            source_name=request.source.source_name,
            device_id=str(payload.get("node") or "ideco"),
            vendor="ideco",
            platform=f"ideco-classic-{version}",
            parser_version=self.metadata.version,
            content_sha256=request.source.content_sha256,
            captured_at=request.source.captured_at,
            imported_at=request.imported_at,
        )
        objects: dict[str, Any] = {}
        for obj in payload["objects"]:
            identifier = obj["id"]
            if not isinstance(identifier, str) or identifier in objects:
                raise ValueError("Invalid object identity")
            objects[identifier] = obj
        zones = {str(obj["id"]): str(obj["title"]) for obj in payload["zones"]}
        rules: list[Rule] = []
        unsupported: list[UnsupportedConstruct] = []
        seen: set[str] = set()
        for table in ("forward", "input"):
            for index, raw in enumerate(payload["tables"][table]):
                identifier = raw["id"]
                if (
                    not isinstance(identifier, str)
                    or not identifier
                    or f"{table}:{identifier}" in seen
                ):
                    raise ValueError("Invalid rule identity")
                seen.add(f"{table}:{identifier}")
                location = SourceLocation(
                    source_name=config.source_name,
                    object_path=f"$.tables.{table}[{index}]",
                    object_id=identifier,
                )
                src, src_status = self._addresses(raw.get("sources"), objects)
                dst, dst_status = self._addresses(raw.get("destinations"), objects)
                services, svc_status = self._services(raw, objects)
                src_zone, src_zone_ok = self._zone(raw.get("incoming_interface"), zones)
                dst_zone, dst_zone_ok = self._zone(raw.get("outgoing_interface"), zones)
                known_keys = {
                    "id",
                    "parent_id",
                    "enabled",
                    "logging",
                    "protocol",
                    "sources",
                    "destinations",
                    "source_ports",
                    "destination_ports",
                    "incoming_interface",
                    "outgoing_interface",
                    "hip_profiles",
                    "dpi_profile",
                    "dpi_enabled",
                    "ips_profile",
                    "ips_enabled",
                    "timetable",
                    "comment",
                    "action",
                }
                limited = any(key not in known_keys for key in raw)
                limited = limited or any(
                    raw.get(key) not in (None, [], ["any"], "any", "")
                    for key in ("hip_profiles", "timetable")
                )
                limited = limited or raw.get("dpi_enabled") is not False
                limited = limited or raw.get("ips_enabled") is not False
                limited = limited or raw.get("source_ports") != ["any"]
                action = {
                    "accept": RuleAction.ALLOW,
                    "drop": RuleAction.DROP,
                    "reject": RuleAction.REJECT,
                }.get(raw.get("action"), RuleAction.UNKNOWN)
                known = (
                    not limited
                    and src_zone_ok
                    and dst_zone_ok
                    and action != RuleAction.UNKNOWN
                    and all(s == DataStatus.KNOWN for s in (src_status, dst_status, svc_status))
                )
                if type(raw.get("enabled")) is not bool:
                    raise ValueError("Missing rule state")
                mode = payload.get("firewall_settings", {}).get("log_mode")
                # Selective logging also depends on action filters and logging rules.
                logging = False if mode == "nothing" else True if mode == "all" else None
                state = payload.get("firewall_state", {}).get("enabled")
                # Module disablement also disables all collected user rules.
                enabled = raw["enabled"] and state is not False
                if type(state) is not bool:
                    known = False
                rules.append(
                    Rule(
                        rule_id=f"ideco:{table}:{identifier}",
                        configuration_id=config.configuration_id,
                        name=identifier,
                        sequence=index,
                        action=action,
                        enabled=enabled,
                        sources=src,
                        destinations=dst,
                        services=services,
                        source_zone=src_zone,
                        destination_zone=dst_zone,
                        source_status=src_status,
                        destination_status=dst_status,
                        service_status=svc_status,
                        zone_status=DataStatus.KNOWN
                        if src_zone_ok and dst_zone_ok
                        else DataStatus.UNKNOWN,
                        match_status=DataStatus.KNOWN if known else DataStatus.UNSUPPORTED,
                        logging_enabled=logging,
                        logging_status=DataStatus.KNOWN
                        if logging is not None
                        else DataStatus.UNKNOWN,
                        description=raw.get("comment") or None,
                        description_status=DataStatus.KNOWN
                        if raw.get("comment")
                        else DataStatus.ABSENT,
                        policy_id=f"ideco-{table}",
                        policy_direction="in" if table == "input" else None,
                        source_location=location,
                    )
                )
                if not known:
                    unsupported.append(
                        UnsupportedConstruct(
                            construct_type="ideco-rule-condition",
                            source_location=location,
                            message="Условия Ideco не полностью поддержаны "
                            "или ссылки не разрешены.",
                        )
                    )
        for table in ("dnat", "snat"):
            for index, _ in enumerate(payload["tables"][table]):
                unsupported.append(
                    UnsupportedConstruct(
                        construct_type="ideco-nat",
                        message="NAT сохранён в снимке без расчёта трансляций.",
                        source_location=SourceLocation(
                            source_name=config.source_name, object_path=f"$.tables.{table}[{index}]"
                        ),
                    )
                )
        unsupported.append(
            UnsupportedConstruct(
                construct_type="ideco-policy-scope",
                message="Полнота системных правил, правил Ideco Center и порядок исполнения "
                "не подтверждены; эффективная политика не рассчитана.",
                source_location=SourceLocation(
                    source_name=config.source_name, object_path="$.tables"
                ),
            )
        )
        total = sum(len(payload["tables"][key]) for key in ("forward", "input", "dnat", "snat")) + 1
        return ParseResult(
            configuration=config,
            rules=tuple(rules),
            endpoints=tuple(obj for rule in rules for obj in (*rule.sources, *rule.destinations)),
            services=tuple(obj for rule in rules for obj in rule.services),
            unsupported_constructs=tuple(unsupported),
            warnings=tuple(
                ParseIssue(
                    code="IDECO_PARTIAL_SEMANTICS",
                    level=ParseIssueLevel.WARNING,
                    message=item.message,
                    source_location=item.source_location,
                )
                for item in unsupported
            ),
            source_map={rule.rule_id: rule.source_location for rule in rules},
            coverage=ParseCoverage(
                discovered_constructs=total,
                recognized_constructs=total - len(unsupported),
                unsupported_constructs=len(unsupported),
            ),
        )

    @staticmethod
    def _zone(ref: Any, zones: dict[str, str]) -> tuple[str | None, bool]:
        if ref == "any":
            return None, True
        # Special interface groups and interface IDs are not equivalent to zone IDs.
        if isinstance(ref, str) and ref in zones:
            return zones[ref], True
        return None, False

    @classmethod
    def _addresses(
        cls, groups: Any, objects: dict[str, Any]
    ) -> tuple[tuple[Endpoint, ...], DataStatus]:
        try:
            if not isinstance(groups, list) or len(groups) != 1:
                raise ValueError("AND conditions unsupported")
            group = groups[0]
            if (
                set(group) != {"addresses", "addresses_negate"}
                or group["addresses_negate"] is not False
            ):
                raise ValueError("Negation unsupported")
            refs = group["addresses"]
            if not isinstance(refs, list) or not refs:
                raise ValueError("Empty selector")
            result = tuple(endpoint for ref in refs for endpoint in cls._address(ref, objects, ()))
            return result, DataStatus.KNOWN
        except (ValueError, KeyError, TypeError):
            return (), DataStatus.UNSUPPORTED

    @classmethod
    def _address(
        cls, ref: Any, objects: dict[str, Any], path: tuple[str, ...]
    ) -> tuple[Endpoint, ...]:
        if not isinstance(ref, str) or ref in path or len(path) > 16:
            raise ValueError("Invalid reference")
        if ref == "any":
            return (Endpoint(endpoint_id="ideco:any", name="Any", kind=EndpointKind.ANY),)
        obj = objects.get(ref)
        if obj is None:
            return (
                Endpoint(
                    endpoint_id=f"ideco:{ref}", name=ref, kind=EndpointKind.SUBNET, cidrs=(ref,)
                ),
            )
        kind = obj.get("type")
        name = str(obj.get("title") or ref)
        if kind in {"ip", "subnet"}:
            return (
                Endpoint(
                    endpoint_id=f"ideco:{ref}",
                    name=name,
                    kind=EndpointKind.SUBNET,
                    cidrs=(obj["value"],),
                ),
            )
        if kind == "ip_range":
            return (
                Endpoint(
                    endpoint_id=f"ideco:{ref}",
                    name=name,
                    kind=EndpointKind.RANGE,
                    ip_ranges=(IpRange(start=obj["start"], end=obj["end"]),),
                ),
            )
        if kind == "address_list" and isinstance(obj.get("values"), list) and obj["values"]:
            return tuple(
                ep for child in obj["values"] for ep in cls._address(child, objects, (*path, ref))
            )
        raise ValueError("Unsupported address object")

    @classmethod
    def _ports(
        cls, ref: Any, objects: dict[str, Any], path: tuple[str, ...]
    ) -> tuple[PortRange, ...]:
        key = str(ref)
        if key in path or len(path) > 16:
            raise ValueError("Cyclic reference")
        obj = objects.get(key)
        if obj is not None:
            kind = obj.get("type")
            if kind == "port":
                return (PortRange(start=obj["value"], end=obj["value"]),)
            if kind == "port_range":
                return (PortRange(start=obj["start"], end=obj["end"]),)
            if kind == "port_list" and isinstance(obj.get("values"), list) and obj["values"]:
                return tuple(
                    p for child in obj["values"] for p in cls._ports(child, objects, (*path, key))
                )
            raise ValueError("Unsupported port object")
        if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", key):
            raise ValueError("Invalid port")
        bounds = key.split("-")
        return (PortRange(start=int(bounds[0]), end=int(bounds[-1])),)

    @classmethod
    def _services(
        cls, raw: dict[str, Any], objects: dict[str, Any]
    ) -> tuple[tuple[Service, ...], DataStatus]:
        try:
            protocol = {
                "any": Protocol.IP,
                "protocol.tcp": Protocol.TCP,
                "protocol.udp": Protocol.UDP,
                "protocol.icmp": Protocol.ICMP,
            }[raw["protocol"]]
            refs = raw["destination_ports"]
            if not isinstance(refs, list) or not refs:
                raise ValueError("Missing ports")
            ports = (
                ()
                if refs == ["any"]
                else tuple(p for ref in refs for p in cls._ports(ref, objects, ()))
            )
            return (
                Service(
                    service_id=f"ideco:service:{raw['id']}",
                    name=str(raw["protocol"]),
                    protocol=protocol,
                    port_ranges=ports,
                ),
            ), DataStatus.KNOWN
        except (ValueError, KeyError, TypeError):
            return (), DataStatus.UNSUPPORTED
