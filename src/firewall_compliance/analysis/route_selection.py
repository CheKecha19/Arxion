"""Чистый выбор маршрута по полной наблюдаемой RIB, без ACL и NAT."""

from ipaddress import ip_address, ip_interface, ip_network
from typing import Any, Literal

from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.domain.finding import Evidence
from firewall_compliance.domain.reachability import (
    AnalysisReason,
    PathHop,
    ReachabilityQuery,
    ReachabilityResult,
    RouteSelectionResult,
    RouteSelectionStatus,
)
from firewall_compliance.domain.revision import DeviceRevision, Route


def _reason(
    code: str,
    category: Literal["missing_evidence", "unsupported", "contradiction", "pending"],
    message: str,
    routes: tuple[Route, ...] = (),
) -> AnalysisReason:
    return AnalysisReason(
        code=code,
        category=category,
        message=message,
        related_route_ids=tuple(route.route_id for route in routes),
    )


def _input_reasons(revision: DeviceRevision, query: ReachabilityQuery) -> list[AnalysisReason]:
    reasons: list[AnalysisReason] = []
    if query.revision_id != revision.revision_id or query.device_id != revision.device.device_id:
        reasons.append(
            _reason(
                "revision_mismatch",
                "contradiction",
                "Запрос относится к другой ревизии или устройству.",
            )
        )
    if query.device_context != revision.device.context:
        reasons.append(
            _reason(
                "context_mismatch",
                "contradiction",
                "Контекст запроса не совпадает с контекстом устройства.",
            )
        )
    if query.table_id != "default" or any(route.table_id != "default" for route in revision.routes):
        reasons.append(
            _reason(
                "table_scope_unsupported",
                "unsupported",
                "Первый срез допускает только единственную таблицу default; "
                "полнота отдельных таблиц ещё не моделируется.",
            )
        )
    if ip_address(query.destination_ip).version != 4:
        reasons.append(
            _reason(
                "address_family_unsupported",
                "unsupported",
                "Первый срез выбора маршрута ограничен IPv4.",
            )
        )
    if any(ip_network(route.destination).version != 4 for route in revision.routes):
        reasons.append(
            _reason(
                "rib_family_unsupported",
                "unsupported",
                "Смешанная или IPv6 RIB не доказывает полноту единственной IPv4 таблицы.",
            )
        )
    if revision.interfaces_status != DataStatus.KNOWN:
        reasons.append(
            _reason(
                "interfaces_unresolved",
                "unsupported"
                if revision.interfaces_status in {DataStatus.UNSUPPORTED, DataStatus.NOT_APPLICABLE}
                else "missing_evidence",
                "Нужен известный набор интерфейсов с согласованным временем наблюдения.",
            )
        )
    ingress = next(
        (item for item in revision.interfaces if item.interface_id == query.ingress_interface_id),
        None,
    )
    if ingress is None:
        reasons.append(
            _reason(
                "ingress_missing",
                "contradiction"
                if revision.interfaces_status in {DataStatus.KNOWN, DataStatus.ABSENT}
                else "missing_evidence",
                "Входной интерфейс отсутствует в ревизии.",
            )
        )
    elif ingress.data_status != DataStatus.KNOWN:
        reasons.append(
            _reason(
                "ingress_unresolved",
                "unsupported"
                if ingress.data_status == DataStatus.UNSUPPORTED
                else "missing_evidence",
                "Факт входного интерфейса не подтверждён.",
            )
        )
    if revision.observed_at is None:
        reasons.append(
            _reason(
                "observation_missing",
                "missing_evidence",
                "Не доказано общее время наблюдения ревизии.",
            )
        )
    basis = revision.routes_evidence
    if basis is None or basis.scope != "routing_table":
        reasons.append(
            _reason(
                "rib_missing",
                "missing_evidence",
                "Требуется наблюдаемая RIB; настроенные маршруты не заменяют её.",
            )
        )
    elif not basis.complete:
        reasons.append(
            _reason(
                "rib_incomplete",
                "missing_evidence",
                "Таблица неполна: может отсутствовать более специфичный маршрут.",
            )
        )
    if revision.routes_status not in {DataStatus.KNOWN, DataStatus.ABSENT}:
        reasons.append(
            _reason(
                "rib_status_unresolved",
                "unsupported"
                if revision.routes_status in {DataStatus.UNSUPPORTED, DataStatus.NOT_APPLICABLE}
                else "missing_evidence",
                "Статус таблицы не позволяет доказать выбор либо отсутствие маршрута.",
            )
        )
    return reasons


def _unresolved_status(reasons: list[AnalysisReason]) -> RouteSelectionStatus:
    if any(reason.category in {"unsupported", "contradiction"} for reason in reasons):
        return "unknown"
    return "not_enough_evidence"


def _preferred_routes(
    matched: tuple[Route, ...],
) -> tuple[tuple[Route, ...], list[AnalysisReason], dict[str, Any]]:
    longest = max(ip_network(route.destination).prefixlen for route in matched)
    trace: dict[str, Any] = {"longest_prefix_length": longest}
    candidates = tuple(
        route for route in matched if ip_network(route.destination).prefixlen == longest
    )
    reasons: list[AnalysisReason] = []
    if len(candidates) > 1:
        if any(route.administrative_distance is None for route in candidates):
            reasons.append(
                _reason(
                    "distance_missing",
                    "missing_evidence",
                    "Нельзя сравнить маршруты с неизвестным administrative distance.",
                    candidates,
                )
            )
        else:
            distance = min(
                route.administrative_distance
                for route in candidates
                if route.administrative_distance is not None
            )
            trace["administrative_distance"] = distance
            candidates = tuple(
                route for route in candidates if route.administrative_distance == distance
            )
    unsupported = tuple(
        route
        for route in candidates
        if route.route_kind not in {"connected", "static"} or route.data_status != DataStatus.KNOWN
    )
    if unsupported:
        reasons.append(
            _reason(
                "route_kind_unsupported",
                "unsupported",
                "Семантика оставшихся наиболее предпочтительных маршрутов не поддержана.",
                unsupported,
            )
        )
    if any(route.administrative_distance == 255 for route in candidates):
        reasons.append(
            _reason(
                "route_priority_unsupported",
                "unsupported",
                "AD=255 не интерпретируется как установленный пригодный маршрут.",
                candidates,
            )
        )
    if not reasons and len(candidates) > 1:
        if len({route.route_kind for route in candidates}) != 1:
            reasons.append(
                _reason(
                    "metric_not_comparable",
                    "unsupported",
                    "Равные AD разных типов не дают нейтрального сравнения metric.",
                    candidates,
                )
            )
        elif any(route.metric is None for route in candidates):
            reasons.append(
                _reason(
                    "metric_missing",
                    "missing_evidence",
                    "Нельзя сравнить равные AD при неизвестной metric.",
                    candidates,
                )
            )
        else:
            metric = min(route.metric for route in candidates if route.metric is not None)
            trace["metric"] = metric
            candidates = tuple(route for route in candidates if route.metric == metric)
    return candidates, reasons, trace


def select_route(revision: DeviceRevision, query: ReachabilityQuery) -> RouteSelectionResult:
    """Сохранить причины неопределённости вместо угадывания пути и приоритетов."""
    revision = DeviceRevision.model_validate(revision.model_dump(mode="python"))
    query = ReachabilityQuery.model_validate(query.model_dump(mode="python"))
    destination = ip_address(query.destination_ip)
    matched = tuple(
        sorted(
            (
                route
                for route in revision.routes
                if route.table_id == query.table_id
                and ip_network(route.destination).version == destination.version
                and destination in ip_network(route.destination)
            ),
            key=lambda route: route.route_id,
        )
    )
    reasons = _input_reasons(revision, query)
    candidates = matched
    status: RouteSelectionStatus
    trace: dict[str, Any] = {}
    if reasons:
        unsupported = tuple(
            route
            for route in matched
            if route.route_kind not in {"connected", "static"}
            or route.data_status == DataStatus.UNSUPPORTED
        )
        if unsupported:
            reasons.append(
                _reason(
                    "route_kind_unsupported",
                    "unsupported",
                    "Есть неподдержанные совпавшие маршруты; "
                    "нехватка входных данных не устраняет это ограничение.",
                    unsupported,
                )
            )
        status = _unresolved_status(reasons)
    elif any(
        destination == ip_interface(address).ip
        for interface in revision.interfaces
        if interface.addresses_status == DataStatus.KNOWN
        for address in interface.addresses
    ):
        reasons.append(
            _reason(
                "local_delivery_unsupported",
                "unsupported",
                "Назначение совпадает с адресом устройства; local delivery не реализована.",
            )
        )
        status = "unknown"
    elif not matched:
        status = "no_route"
        candidates = ()
    else:
        candidates, reasons, trace = _preferred_routes(matched)
        if reasons:
            status = _unresolved_status(reasons)
        elif len(candidates) > 1:
            if any(route.is_blackhole for route in candidates):
                reasons.append(
                    _reason(
                        "discard_tie",
                        "contradiction",
                        "Равные предпочтения с discard не дают однозначного действия.",
                        candidates,
                    )
                )
                status = "unknown"
            else:
                status = "equal_cost"
        else:
            status = "blackhole" if candidates[0].is_blackhole else "selected"

    hops = (
        tuple(
            PathHop(
                device_id=revision.device.device_id,
                revision_id=revision.revision_id,
                table_id=route.table_id,
                route_id=route.route_id,
                destination=route.destination,
                next_hop=route.next_hop,
                outgoing_interface_id=route.outgoing_interface_id,
                disposition="discard" if route.is_blackhole else "forward_candidate",
                evidence=Evidence(
                    summary="Основание кандидата из наблюдаемой таблицы маршрутизации.",
                    source_locations=(route.source_location,) if route.source_location else (),
                    facts=route.model_dump(mode="json"),
                ),
            )
            for route in candidates
        )
        if status in {"selected", "blackhole", "equal_cost"}
        else ()
    )
    return RouteSelectionResult(
        query=query,
        status=status,
        matched_route_ids=tuple(route.route_id for route in matched),
        candidate_route_ids=tuple(route.route_id for route in candidates),
        hops=hops,
        reasons=tuple(reasons),
        sources=tuple(sorted(revision.sources, key=lambda source: str(source.source_document_id))),
        revision_schema_version=revision.schema_version,
        application_version=revision.application_version,
        evidence=Evidence(
            summary="Решение только по RIB, без доказательства доступности потока.",
            source_locations=tuple(
                route.source_location for route in matched if route.source_location
            ),
            facts={
                "routes_status": revision.routes_status.value,
                "collection_evidence": revision.routes_evidence.model_dump(mode="json")
                if revision.routes_evidence
                else None,
                "observed_at": revision.observed_at.isoformat() if revision.observed_at else None,
                "observation_window": revision.observation_window.model_dump(mode="json")
                if revision.observation_window
                else None,
                "selection_trace": trace,
                "matched_routes": [route.model_dump(mode="json") for route in matched],
                "device": revision.device.model_dump(mode="json"),
                "parser_version": revision.parse_result.configuration.parser_version,
                "interfaces_status": revision.interfaces_status.value,
                "ingress_interface": next(
                    (
                        interface.model_dump(mode="json")
                        for interface in revision.interfaces
                        if interface.interface_id == query.ingress_interface_id
                    ),
                    None,
                ),
            },
            limitations=(
                "Полнота относится к единственной IPv4 таблице default в указанной ревизии.",
                "PathHop не подтверждает ARP, рекурсивный next-hop, "
                "состояние интерфейса или реальную передачу.",
                "Равные кандидаты не доказывают ECMP и не выбирают ветвь для конкретного потока.",
            ),
        ),
    )


def analyze_reachability(revision: DeviceRevision, query: ReachabilityQuery) -> ReachabilityResult:
    """Вернуть предварительный ответ без ложного reachable или blocked."""
    selection = select_route(revision, query)
    pending = _reason(
        "forward_chain_pending",
        "pending",
        "ACL, NAT/PBR, состояние интерфейсов, рекурсивный next-hop и обратный путь "
        "ещё не проверены; решение RIB не является итогом потока.",
    )
    return ReachabilityResult(
        status="not_enough_evidence" if selection.status == "not_enough_evidence" else "unknown",
        route_selection=selection,
        reasons=(*selection.reasons, pending),
    )
