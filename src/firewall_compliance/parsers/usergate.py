"""Conservative import of read-only UserGate XML-RPC snapshots (UGOS 6/7)."""

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
from firewall_compliance.parsers.contracts import (
    DetectionResult,
    ParseFailure,
    ParseOutcome,
    ParseRequest,
    ParserMetadata,
    SourceDocument,
)


class UserGateParser:
    """Import collected facts without treating unknown conditions as unrestricted access."""

    metadata = ParserMetadata(parser_id="usergate-xmlrpc", version="0.1.0", vendor="usergate")

    def detect(self, source: SourceDocument) -> DetectionResult:
        try:
            payload = json.loads(source.content)
            match = isinstance(payload, dict) and payload.get("format") == "arxion-usergate-v1"
        except (ValueError, UnicodeError):
            match = False
        return DetectionResult(
            parser_id=self.metadata.parser_id,
            is_match=match,
            confidence=1.0 if match else 0.0,
        )

    def parse(self, request: ParseRequest) -> ParseOutcome:
        try:
            payload = json.loads(request.source.content)
            if not self.detect(request.source).is_match:
                raise ValueError("Unsupported snapshot format")
            version = str(payload["version"])
            match = re.match(r"^(6|7)\.(\d+)\.(\d+)(?:[.A-Za-z_-]|$)", version)
            if match is None:
                raise ValueError("Only UGOS 6 and 7 snapshots are supported")
            if tuple(map(int, match.groups())) < (6, 1, 5):
                raise ValueError("UGOS 6.1.5 or newer is required")
            for key in ("firewall_rules", "zones", "services", "ip_lists"):
                if not isinstance(payload[key], list):
                    raise ValueError("Snapshot collection must be an array")
            return self._parse(request, payload, version)
        except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
            return ParseFailure(
                parser_id=self.metadata.parser_id,
                source_name=request.source.source_name,
                content_sha256=request.source.content_sha256,
                errors=(
                    ParseIssue(
                        code="USERGATE_INVALID_SNAPSHOT",
                        level=ParseIssueLevel.ERROR,
                        message="Некорректный снимок UserGate 6/7.",
                    ),
                ),
            )

    def _parse(self, request: ParseRequest, payload: dict[str, Any], version: str) -> ParseResult:
        config = Configuration(
            source_name=request.source.source_name,
            device_id=str(payload.get("node") or "usergate"),
            vendor="usergate",
            platform=f"ugos-{version}",
            parser_version=self.metadata.version,
            content_sha256=request.source.content_sha256,
            captured_at=request.source.captured_at,
            imported_at=request.imported_at,
        )
        addresses = {str(obj["id"]): obj for obj in payload["ip_lists"]}
        services = {str(obj["id"]): obj for obj in payload["services"]}
        zones = {str(obj["id"]): str(obj["name"]) for obj in payload["zones"]}
        rules: list[Rule] = []
        unsupported: list[UnsupportedConstruct] = []
        warnings: list[ParseIssue] = []
        for index, raw in enumerate(payload["firewall_rules"]):
            location = SourceLocation(
                source_name=config.source_name,
                object_path=f"$.firewall_rules[{index}]",
                object_id=str(raw.get("id", index)),
            )
            sources, src_status = self._endpoints(raw.get("src_ips"), addresses)
            destinations, dst_status = self._endpoints(raw.get("dst_ips"), addresses)
            parsed_services, svc_status = self._services(raw.get("services"), services)
            src_zone, src_zone_ok = self._zone(raw.get("src_zones"), zones)
            dst_zone, dst_zone_ok = self._zone(raw.get("dst_zones"), zones)
            # These selectors cannot be faithfully represented by the canonical L3/L4 model.
            limited = any(
                raw.get(key)
                for key in (
                    "users",
                    "apps",
                    "time_restrictions",
                    "scenario_rule_id",
                    "src_ips_negate",
                    "dst_ips_negate",
                    "services_negate",
                    "src_zones_negate",
                    "dst_zones_negate",
                    "fragmented",
                    "hip_profiles",
                    "applications",
                    "application_profiles",
                )
            )
            known_keys = {
                "id",
                "name",
                "description",
                "action",
                "enabled",
                "src_ips",
                "dst_ips",
                "services",
                "src_zones",
                "dst_zones",
                "log",
                "log_session_start",
                "position",
                "row_number",
                "users",
                "apps",
                "time_restrictions",
                "scenario_rule_id",
                "src_ips_negate",
                "dst_ips_negate",
                "services_negate",
                "src_zones_negate",
                "dst_zones_negate",
                "fragmented",
                "hip_profiles",
                "applications",
                "application_profiles",
                "created_at",
                "updated_at",
                "send_host_icmp",
                "limit",
                "limit_burst",
                "limit_enabled",
                "log_limit",
                "log_limit_burst",
                "log_limit_enabled",
            }
            limited = limited or any(value for key, value in raw.items() if key not in known_keys)
            limited = limited or bool(raw.get("limit_enabled"))
            known = (
                not limited
                and src_zone_ok
                and dst_zone_ok
                and all(s == DataStatus.KNOWN for s in (src_status, dst_status, svc_status))
            )
            action = {
                "accept": RuleAction.ALLOW,
                "allow": RuleAction.ALLOW,
                "drop": RuleAction.DROP,
                "deny": RuleAction.DENY,
                "reject": RuleAction.REJECT,
            }.get(raw.get("action"), RuleAction.UNKNOWN)
            known = known and action != RuleAction.UNKNOWN
            if type(raw.get("enabled")) is not bool:
                raise ValueError("Missing rule enabled state")
            description = raw.get("description") or None
            logging = raw.get("log") if type(raw.get("log")) is bool else None
            rule = Rule(
                rule_id=f"usergate:firewall:{index}:{raw.get('id', index)}",
                configuration_id=config.configuration_id,
                name=str(raw.get("name") or index),
                sequence=index,
                action=action,
                enabled=raw["enabled"],
                sources=sources,
                destinations=destinations,
                services=parsed_services,
                source_zone=src_zone,
                destination_zone=dst_zone,
                source_status=src_status,
                destination_status=dst_status,
                service_status=svc_status,
                zone_status=DataStatus.KNOWN if src_zone_ok and dst_zone_ok else DataStatus.UNKNOWN,
                match_status=DataStatus.KNOWN if known else DataStatus.UNSUPPORTED,
                logging_enabled=logging,
                logging_status=DataStatus.KNOWN if logging is not None else DataStatus.UNKNOWN,
                description=description,
                description_status=DataStatus.KNOWN if description else DataStatus.ABSENT,
                policy_id="usergate-firewall",
                policy_semantics="first_match",
                source_location=location,
            )
            rules.append(rule)
            if not known:
                unsupported.append(
                    UnsupportedConstruct(
                        construct_type="usergate-rule-condition",
                        message="Условия правила не полностью поддержаны или ссылки не разрешены.",
                        source_location=location,
                    )
                )
        for index, _raw in enumerate(payload.get("traffic_rules", [])):
            unsupported.append(
                UnsupportedConstruct(
                    construct_type="usergate-nat",
                    message="NAT сохранён в снимке без интерпретации.",
                    source_location=SourceLocation(
                        source_name=config.source_name, object_path=f"$.traffic_rules[{index}]"
                    ),
                )
            )
        warnings.extend(
            ParseIssue(
                code="USERGATE_PARTIAL_SEMANTICS",
                level=ParseIssueLevel.WARNING,
                message=item.message,
                source_location=item.source_location,
            )
            for item in unsupported
        )
        warnings.append(
            ParseIssue(
                code="USERGATE_SNAPSHOT_SCOPE",
                level=ParseIssueLevel.WARNING,
                message="Снимок содержит правила МЭ и справочники; полнота конфигурации и "
                "согласованность нескольких запросов во времени не подтверждены.",
            )
        )
        total = len(rules) + len(payload.get("traffic_rules", []))
        return ParseResult(
            configuration=config,
            rules=tuple(rules),
            warnings=tuple(warnings),
            endpoints=tuple(obj for rule in rules for obj in (*rule.sources, *rule.destinations)),
            services=tuple(obj for rule in rules for obj in rule.services),
            unsupported_constructs=tuple(unsupported),
            source_map={rule.rule_id: rule.source_location for rule in rules},
            coverage=ParseCoverage(
                discovered_constructs=total,
                recognized_constructs=total - len(unsupported),
                unsupported_constructs=len(unsupported),
            ),
        )

    @staticmethod
    def _zone(refs: Any, zones: dict[str, str]) -> tuple[str | None, bool]:
        if refs == []:
            return None, True
        if isinstance(refs, list) and len(refs) == 1 and str(refs[0]) in zones:
            return zones[str(refs[0])], True
        return None, False

    @staticmethod
    def _endpoints(refs: Any, objects: dict[str, Any]) -> tuple[tuple[Endpoint, ...], DataStatus]:
        if refs is None:
            return (), DataStatus.UNKNOWN
        if refs == []:
            return (
                Endpoint(endpoint_id="usergate:any", name="Any", kind=EndpointKind.ANY),
            ), DataStatus.KNOWN
        result: list[Endpoint] = []
        try:
            if not isinstance(refs, list):
                raise ValueError("Missing selector")
            for kind, identifier in refs:
                if kind != "list_id":
                    raise ValueError("Unsupported selector")
                obj = objects[str(identifier)]
                content = obj["content"]
                if (
                    not content
                    or obj.get("url")
                    or obj.get("list_type_update") not in (None, "static")
                ):
                    raise ValueError("Dynamic or empty list")
                cidrs = tuple(entry["value"] for entry in content)
                result.append(
                    Endpoint(
                        endpoint_id=f"usergate:ip:{identifier}",
                        name=obj["name"],
                        kind=EndpointKind.GROUP,
                        cidrs=cidrs,
                    )
                )
        except (ValueError, KeyError, TypeError):
            return (), DataStatus.UNSUPPORTED
        return tuple(result), DataStatus.KNOWN

    @staticmethod
    def _services(refs: Any, objects: dict[str, Any]) -> tuple[tuple[Service, ...], DataStatus]:
        if refs is None:
            return (), DataStatus.UNKNOWN
        if refs == []:
            return (
                Service(service_id="usergate:any", name="Any", protocol=Protocol.IP),
            ), DataStatus.KNOWN
        result: list[Service] = []
        try:
            if not isinstance(refs, list):
                raise ValueError("Missing selector")
            for ref in refs:
                identifier = ref
                if isinstance(ref, list):
                    if len(ref) != 2 or ref[0] != "service":
                        raise ValueError("Unsupported service group")
                    identifier = ref[1]
                obj = objects[str(identifier)]
                if not obj["protocols"]:
                    raise ValueError("Missing protocol")
                for index, item in enumerate(obj["protocols"]):
                    if any(
                        value
                        for key, value in item.items()
                        if key not in {"proto", "port", "source_port"}
                    ):
                        raise ValueError("Unsupported protocol constraints")
                    protocol = Protocol(item["proto"])
                    if protocol not in {Protocol.TCP, Protocol.UDP, Protocol.IP} or item.get(
                        "source_port"
                    ):
                        raise ValueError("Unsupported service constraints")
                    ranges = []
                    for part in str(item.get("port") or "").split(","):
                        if part:
                            bounds = part.split("-")
                            ranges.append(PortRange(start=int(bounds[0]), end=int(bounds[-1])))
                    result.append(
                        Service(
                            service_id=f"usergate:service:{identifier}:{index}",
                            name=obj["name"],
                            protocol=protocol,
                            port_ranges=tuple(ranges),
                        )
                    )
        except (ValueError, KeyError, TypeError):
            return (), DataStatus.UNSUPPORTED
        return tuple(result), DataStatus.KNOWN
