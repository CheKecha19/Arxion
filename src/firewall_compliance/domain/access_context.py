"""Офлайн-сведения о пользователе, устройстве и адресе конкретного сеанса."""

from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import Annotated, Literal, Self

from pydantic import (
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from firewall_compliance.domain.base import DomainModel


def _utc(value: object) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.strip())
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("Укажите дату и время с явным часовым поясом")
    return value.astimezone(UTC)


ContextTime = Annotated[datetime, BeforeValidator(_utc)]
ContextIdentifier = Annotated[str, Field(min_length=1, max_length=512)]
ContextDigest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
AccessChannel = Literal["office", "vpn"]
ContextResolutionCode = Literal[
    "session_bound", "scope_mismatch", "invalid_time", "outside_snapshot",
    "session_required", "session_missing", "session_inactive", "channel_mismatch",
    "device_missing", "device_mismatch", "device_conflict", "device_untrusted",
    "membership_missing", "membership_denied", "membership_conflict",
    "address_ambiguous", "pool_missing", "pool_mismatch", "source_unresolved",
    "source_mismatch",
]


class _ContextModel(DomainModel):
    model_config = ConfigDict(frozen=True, revalidate_instances="always")


class AccessContextCondition(_ContextModel):
    """Явные условия требования, проверяемые для выбранного сеанса."""

    group_id: ContextIdentifier
    channel: AccessChannel
    corporate_device_required: bool = Field(default=True, strict=True)
    device_id: ContextIdentifier | None = None


class AccessContextOrigin(_ContextModel):
    source_name: ContextIdentifier
    record_id: ContextIdentifier
    observed_at: ContextTime
    content_sha256: ContextDigest | None = None


class _ContextFact(_ContextModel):
    evidence_id: ContextIdentifier
    origin: AccessContextOrigin
    valid_from: ContextTime
    valid_until: ContextTime

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        if self.valid_until <= self.valid_from:
            raise ValueError("Конец интервала свидетельства должен быть позже начала")
        return self

    def active_at(self, at: datetime) -> bool:
        return self.valid_from <= at < self.valid_until


class AccessGroupMembership(_ContextFact):
    principal_id: ContextIdentifier
    group_id: ContextIdentifier
    member: bool = Field(default=True, strict=True)


class AccessDeviceObservation(_ContextFact):
    device_id: ContextIdentifier
    corporate: bool = Field(strict=True)


class AccessSession(_ContextFact):
    session_id: ContextIdentifier
    principal_id: ContextIdentifier
    device_id: ContextIdentifier
    channel: AccessChannel
    assigned_ip: str
    pool_id: ContextIdentifier | None = None

    @field_validator("assigned_ip")
    @classmethod
    def validate_address(cls, value: str) -> str:
        # Зона интерфейса должна быть частью явного context_id снимка.
        if "%" in value:
            raise ValueError("Адрес сеанса должен быть без идентификатора зоны IPv6")
        address = ip_address(value)
        if address.is_unspecified or address.is_multicast:
            raise ValueError("Сеансу требуется назначенный адрес узла")
        return str(address)

    @model_validator(mode="after")
    def validate_channel(self) -> Self:
        if self.pool_id is not None and self.channel != "vpn":
            raise ValueError("Ссылка на VPN-пул допустима для VPN-сеанса")
        return self


class AccessVpnPool(_ContextFact):
    pool_id: ContextIdentifier
    prefixes: tuple[str, ...] = Field(min_length=1)

    @field_validator("prefixes")
    @classmethod
    def validate_prefixes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any("%" in value for value in values):
            raise ValueError("Префикс VPN-пула должен быть без идентификатора зоны IPv6")
        return tuple(dict.fromkeys(str(ip_network(value, strict=True)) for value in values))


class AccessContextSnapshot(_ContextModel):
    """Свидетельства одной области и одного адресного пространства."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    project_id: ContextIdentifier
    scope_id: ContextIdentifier
    context_id: ContextIdentifier
    captured_at: ContextTime
    memberships: tuple[AccessGroupMembership, ...] = ()
    devices: tuple[AccessDeviceObservation, ...] = ()
    sessions: tuple[AccessSession, ...] = ()
    pools: tuple[AccessVpnPool, ...] = ()

    @model_validator(mode="after")
    def validate_facts(self) -> Self:
        identifiers: set[str] = set()
        for facts in (self.memberships, self.devices, self.sessions, self.pools):
            for fact in facts:
                if fact.evidence_id in identifiers:
                    raise ValueError("Идентификаторы свидетельств снимка должны быть уникальны")
                if fact.origin.observed_at > self.captured_at:
                    raise ValueError("Время свидетельства не может быть позже времени снимка")
                identifiers.add(fact.evidence_id)
        if len({session.session_id for session in self.sessions}) != len(self.sessions):
            raise ValueError("Идентификаторы сеансов снимка должны быть уникальны")
        return self


class AccessContextResolution(_ContextModel):
    """Проверка принадлежности адреса одному сеансу и её точное основание."""

    status: Literal["resolved", "unknown"]
    code: ContextResolutionCode
    message: str = Field(min_length=1)
    snapshot_digest: ContextDigest
    session_id: ContextIdentifier | None = None
    evaluated_at: ContextTime | None = None
    source_cidr: str | None = None
    evidence_ids: tuple[ContextIdentifier, ...] = ()

    @model_validator(mode="after")
    def validate_resolution(self) -> Self:
        if self.status == "resolved":
            if (
                self.code != "session_bound" or self.session_id is None or self.source_cidr is None
                or self.evaluated_at is None or not self.evidence_ids
            ):
                raise ValueError("Подтверждённому адресу требуются сеанс и свидетельства")
            network = ip_network(self.source_cidr, strict=True)
            if (
                "/" not in self.source_cidr or "%" in self.source_cidr
                or network.num_addresses != 1
            ):
                raise ValueError("Результат может содержать только адрес одного узла в CIDR")
        elif self.source_cidr is not None or self.code == "session_bound":
            raise ValueError("Неопределённое сопоставление не может задавать адрес")
        return self
