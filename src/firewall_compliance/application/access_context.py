"""Сопоставление явного сеанса с адресным условием матрицы доступа."""

import json
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from hashlib import sha256
from ipaddress import ip_address, ip_network

from firewall_compliance.domain.access_context import (
    AccessContextCondition,
    AccessContextResolution,
    AccessContextSnapshot,
    AccessDeviceObservation,
    AccessGroupMembership,
    AccessSession,
    AccessVpnPool,
    ContextResolutionCode,
)
from firewall_compliance.domain.matrix_context_inputs import MatrixContextInputs, MatrixContextSource


def access_context_digest(snapshot: AccessContextSnapshot) -> str:
    payload = json.dumps(
        snapshot.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def matrix_context_sources_by_digest(inputs: MatrixContextInputs | None) -> dict[str, MatrixContextSource]:
    return {access_context_digest(source.snapshot): source for source in inputs.contexts} if inputs else {}


def assigned_session_context(inputs: MatrixContextInputs | None, requirement_id: str, session_id: str) -> str | None:
    if inputs is None:
        return None
    for selection in inputs.sessions:
        if selection.requirement_id == requirement_id and selection.session_id.strip() == session_id:
            return inputs.context_for_selection(selection)
    return None


def matrix_session_search(inputs: MatrixContextInputs | None) -> dict[str, str]:
    if inputs is None:
        return {}
    return {
        selection.requirement_id: f"{selection.session_id} {inputs.context_for_selection(selection)}"
        for selection in inputs.sessions
    }


class AccessContextIndex:
    """Повторно использует индексы одного неизменяемого снимка для строк матрицы."""

    def __init__(self, snapshot: AccessContextSnapshot) -> None:
        self.snapshot = snapshot
        self.digest = access_context_digest(snapshot)
        self._sessions = {session.session_id: session for session in snapshot.sessions}
        self._addresses: dict[str, list[AccessSession]] = defaultdict(list)
        self._memberships: dict[tuple[str, str], list[AccessGroupMembership]] = defaultdict(list)
        self._devices: dict[str, list[AccessDeviceObservation]] = defaultdict(list)
        self._pools: dict[str, list[AccessVpnPool]] = defaultdict(list)
        for session in snapshot.sessions:
            self._addresses[session.assigned_ip].append(session)
        for membership in snapshot.memberships:
            self._memberships[membership.principal_id, membership.group_id].append(membership)
        for device in snapshot.devices:
            self._devices[device.device_id].append(device)
        for pool in snapshot.pools:
            self._pools[pool.pool_id].append(pool)

    def resolve(
        self,
        condition: AccessContextCondition,
        *,
        session_id: str | None,
        project_id: str,
        scope_id: str,
        context_id: str | None,
        at: datetime | None,
        source_prefixes: Iterable[str] | None,
    ) -> AccessContextResolution:
        """Возвращает адрес узла для наблюдаемого сеанса в указанное время.

        Политика по IP проверяется отдельно. Сведения о сеансе сами по себе
        не подтверждают применение правил к пользователю или устройству.
        """
        snapshot = self.snapshot
        evidence: list[str] = []
        session_id = (session_id or "").strip() or None
        valid_time = at is not None and at.utcoffset() is not None

        def unknown(code: ContextResolutionCode, message: str) -> AccessContextResolution:
            return AccessContextResolution(
                status="unknown", code=code, message=message, snapshot_digest=self.digest,
                session_id=session_id if session_id is not None and len(session_id) <= 512 else None,
                evaluated_at=at if valid_time else None, evidence_ids=tuple(evidence),
            )

        if (project_id, scope_id, context_id) != (
            snapshot.project_id, snapshot.scope_id, snapshot.context_id,
        ):
            return unknown(
                "scope_mismatch", "Снимок сеансов относится к другой области или сетевому контексту.",
            )
        if at is None or not valid_time:
            return unknown("invalid_time", "Укажите время проверки с часовым поясом.")
        if at > snapshot.captured_at:
            return unknown("outside_snapshot", "Время проверки позже времени снимка сеансов.")
        if not session_id:
            return unknown(
                "session_required", "Выберите конкретный сеанс. VPN-пул не связывает адрес с пользователем.",
            )
        session = self._sessions.get(session_id)
        if session is None:
            return unknown("session_missing", "Выбранный сеанс отсутствует в снимке.")
        evidence.append(session.evidence_id)
        if not session.active_at(at):
            return unknown("session_inactive", "Свидетельство сеанса не охватывает время проверки.")
        if session.channel != condition.channel:
            return unknown("channel_mismatch", "Тип подключения сеанса отличается от указанного в требовании.")
        if condition.device_id is not None and session.device_id != condition.device_id:
            return unknown("device_mismatch", "Устройство сеанса отличается от указанного в требовании.")

        competing = tuple(
            item for item in self._addresses[session.assigned_ip]
            if item.session_id != session.session_id and item.active_at(at)
        )
        if competing:
            evidence.extend(item.evidence_id for item in competing)
            return unknown(
                "address_ambiguous", "Тот же адрес относится к нескольким активным сеансам в этом контексте.",
            )

        members = tuple(
            item for item in self._memberships.get((session.principal_id, condition.group_id), ())
            if item.active_at(at)
        )
        evidence.extend(item.evidence_id for item in members)
        membership = {item.member for item in members}
        if not membership:
            return unknown("membership_missing", "Членство пользователя в группе не подтверждено на время проверки.")
        if len(membership) > 1:
            return unknown("membership_conflict", "Действующие свидетельства членства противоречат друг другу.")
        if membership == {False}:
            return unknown("membership_denied", "Свидетельство указывает, что пользователь не состоит в нужной группе.")

        devices = tuple(
            item for item in self._devices.get(session.device_id, ()) if item.active_at(at)
        )
        evidence.extend(item.evidence_id for item in devices)
        corporate = {item.corporate for item in devices}
        if not corporate:
            return unknown("device_missing", "Сведения об устройстве сеанса отсутствуют на время проверки.")
        if len(corporate) > 1:
            return unknown("device_conflict", "Действующие сведения об устройстве противоречат друг другу.")
        if condition.corporate_device_required and corporate == {False}:
            return unknown("device_untrusted", "Для сеанса требуется корпоративное устройство.")

        address = ip_address(session.assigned_ip)
        if session.pool_id is not None:
            pools = tuple(
                item for item in self._pools.get(session.pool_id, ()) if item.active_at(at)
            )
            evidence.extend(item.evidence_id for item in pools)
            if not pools:
                return unknown("pool_missing", "Указанный в сеансе VPN-пул не подтверждён на время проверки.")
            if not all(any(address in ip_network(prefix) for prefix in pool.prefixes) for pool in pools):
                return unknown("pool_mismatch", "Адрес сеанса не входит в подтверждённый VPN-пул.")

        raw_prefixes = tuple(source_prefixes or ())
        if not raw_prefixes or any(
            not isinstance(prefix, str) or "%" in prefix for prefix in raw_prefixes
        ):
            return unknown("source_unresolved", "Для источника нужны известные префиксы в контексте снимка.")
        try:
            prefixes = tuple(ip_network(prefix, strict=True) for prefix in raw_prefixes)
        except (ValueError, TypeError):
            return unknown("source_unresolved", "Адресные префиксы источника не удалось подтвердить.")
        if not any(address in prefix for prefix in prefixes):
            return unknown("source_mismatch", "Адрес сеанса находится вне подтверждённых префиксов источника.")
        return AccessContextResolution(
            status="resolved", code="session_bound", snapshot_digest=self.digest,
            message=(
                "Адрес подтверждён для выбранного сеанса и времени. "
                "Применение identity-политики не установлено."
            ),
            session_id=session.session_id, evaluated_at=at,
            source_cidr=f"{address}/{address.max_prefixlen}", evidence_ids=tuple(evidence),
        )
