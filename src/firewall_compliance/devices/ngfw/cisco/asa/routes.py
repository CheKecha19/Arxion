"""Узкая грамматика настроенных маршрутов и IPv4 RIB ASA."""

import re
from ipaddress import IPv4Address, IPv4Network

from firewall_compliance.devices.ngfw.cisco.asa.common import ParsedNetworkFacts
from firewall_compliance.domain import (
    DataOrigin,
    DataStatus,
    ParseCoverage,
    ParseIssue,
    ParseIssueLevel,
    Route,
    SourceLocation,
    UnsupportedConstruct,
)
from firewall_compliance.parsers.network_contracts import NetworkParseRequest

_CONNECTED = re.compile(r"C\s+(\S+)\s+(\S+)\s+is directly connected,\s+(\S+)")
_STATIC = re.compile(
    r"(S\*?)\s+(\S+)\s+(\S+)\s+\[([^\s/\]]+)/([^\s/\]]+)\]"
    r"\s+via\s+(\S+),\s+(\S+)"
)
_GATEWAY = re.compile(r"Gateway of last resort is (\S+) to network 0\.0\.0\.0")


class _Unsupported(ValueError):
    pass


def _network(address: str, mask: str) -> str:
    if ":" in address or ":" in mask:
        raise _Unsupported("IPv6 вне поддержанной области.")
    value = int(IPv4Address(mask))
    inverse = value ^ 0xFFFFFFFF
    if inverse & (inverse + 1):
        raise ValueError("Маска IPv4 должна быть непрерывной.")
    # IPv4Network допускает hostmask; здесь разрешена только dotted netmask.
    prefix = value.bit_count()
    return str(IPv4Network((str(IPv4Address(address)), prefix), strict=True))


def _gateway(address: str) -> str:
    if ":" in address:
        raise _Unsupported("IPv6 вне поддержанной области.")
    gateway = IPv4Address(address)
    if gateway.is_multicast or gateway.is_unspecified or int(gateway) == 0xFFFFFFFF:
        raise ValueError("Следующий переход должен быть ненулевым unicast IPv4.")
    return str(gateway)


def _number(token: str, maximum: int | None = None, minimum: int = 0) -> int:
    if re.fullmatch(r"[0-9]+", token) is None:
        raise ValueError("Некорректное целое значение приоритета маршрута.")
    value = int(token)
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError("Приоритет маршрута вне допустимого диапазона.")
    return value


def _parse_line(
    request: NetworkParseRequest, line: str, location: SourceLocation
) -> tuple[Route | None, str | None]:
    metadata = request.metadata
    label: str | None = None
    next_hop: str | None = None
    distance: int | None = None
    metric: int | None = None
    blackhole = False
    kind = "static"
    if metadata.source_kind == "asa_running_config_static_routes":
        tokens = line.split()
        if not tokens or tokens[0] != "route":
            raise _Unsupported("Неизвестная строка конфигурации маршрутов.")
        if len(tokens) >= 2 and tokens[1].casefold() == "null0":
            if len(tokens) != 4:
                raise _Unsupported("Неподдержанная форма route null0.")
            destination = _network(tokens[2], tokens[3])
            blackhole = True
        else:
            if len(tokens) != 6:
                raise _Unsupported("Нужен полный route с явной distance без хвоста.")
            label = tokens[1]
            destination = _network(tokens[2], tokens[3])
            next_hop = _gateway(tokens[4])
            distance = _number(tokens[5], maximum=254, minimum=1)
    elif metadata.source_kind == "asa_ipv4_rib":
        if line == "Gateway of last resort is not set":
            return None, None
        header = _GATEWAY.fullmatch(line)
        if header:
            _gateway(header[1])
            return None, None
        connected = _CONNECTED.fullmatch(line)
        static = _STATIC.fullmatch(line)
        if connected:
            destination = _network(connected[1], connected[2])
            label = connected[3]
            kind = "connected"
        elif static:
            destination = _network(static[2], static[3])
            if static[1] == "S*" and destination != "0.0.0.0/0":
                raise ValueError("S* допустим только для default route.")
            distance = _number(static[4], maximum=254)
            metric = _number(static[5])
            next_hop = _gateway(static[6])
            label = static[7]
        else:
            raise _Unsupported("Строка вне поддержанных форм C/S/S* и заголовка RIB.")
        if label.casefold() == "null0":
            raise _Unsupported("Форма Null0 в RIB не подтверждена.")
    else:
        raise _Unsupported("Роль документа не относится к маршрутам.")
    interface_id = request.interface_labels.get(label.casefold()) if label is not None else None
    missing_label = label if label is not None and interface_id is None else None
    route = Route(
        route_id=f"route:{metadata.source_kind}:{metadata.source_document_id}:{location.line_start}",
        device_id=metadata.device_id,
        origin=DataOrigin.IMPORTED,
        source_document_id=metadata.source_document_id,
        source_location=location,
        destination=destination,
        next_hop=next_hop,
        outgoing_interface_id=interface_id,
        administrative_distance=distance,
        metric=metric,
        route_kind="connected" if kind == "connected" else "static",
        table_id=metadata.table_id,
        is_blackhole=blackhole,
        data_status=DataStatus.UNKNOWN if missing_label is not None else DataStatus.KNOWN,
    )
    return route, missing_label


def parse_routes(request: NetworkParseRequest, text: str) -> ParsedNetworkFacts:
    """Учесть каждую значимую строку, не выводя полноту или установку маршрута."""
    routes: list[Route] = []
    warnings: list[ParseIssue] = []
    errors: list[ParseIssue] = []
    unsupported: list[UnsupportedConstruct] = []
    discovered = recognized = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        discovered += 1
        location = SourceLocation(
            source_name=request.source.source_name, line_start=number, line_end=number
        )
        try:
            route, missing_label = _parse_line(request, line, location)
        except _Unsupported as exc:
            unsupported.append(
                UnsupportedConstruct(
                    construct_type="ASA_UNSUPPORTED_ROUTE",
                    message=str(exc),
                    source_location=location,
                )
            )
            warnings.append(
                ParseIssue(
                    code="ASA_UNSUPPORTED_ROUTE",
                    level=ParseIssueLevel.WARNING,
                    message=str(exc),
                    source_location=location,
                )
            )
            continue
        except ValueError as exc:
            errors.append(
                ParseIssue(
                    code="ASA_INVALID_ROUTE",
                    level=ParseIssueLevel.ERROR,
                    message=str(exc),
                    source_location=location,
                )
            )
            continue
        recognized += 1
        if route is not None:
            routes.append(route)
        if missing_label is not None:
            warnings.append(
                ParseIssue(
                    code="ASA_UNKNOWN_INTERFACE_LABEL",
                    level=ParseIssueLevel.WARNING,
                    message=f"Нет привязки интерфейса для label {missing_label}.",
                    source_location=location,
                )
            )
    return ParsedNetworkFacts(
        routes=tuple(routes),
        warnings=tuple(warnings),
        errors=tuple(errors),
        unsupported_constructs=tuple(unsupported),
        coverage=ParseCoverage(
            discovered_constructs=discovered,
            recognized_constructs=recognized,
            unsupported_constructs=len(unsupported),
        ),
    )
