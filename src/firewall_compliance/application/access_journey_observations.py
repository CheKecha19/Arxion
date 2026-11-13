"""Сопоставление офлайн-наблюдений с условиями сохранённой цепочки."""

from bisect import bisect_right
from collections.abc import Callable, Mapping, Sequence
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from itertools import pairwise
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from firewall_compliance.application.access_journey import (
    JourneyAssessment, JourneyStepAssessment, evaluate_journey, evaluate_scope_journey,
)
from firewall_compliance.application.access_matrix_v2 import (
    CatalogBindings, MatrixPolicyGroupResolver, MatrixSessionResolver,
)
from firewall_compliance.application.cloud_sg_revision import CloudSGSelection
from firewall_compliance.application.matrix_artifact import MatrixAssessmentArtifact
from firewall_compliance.application.matrix_catalog_bindings import split_catalog_bindings
from firewall_compliance.application.matrix_policy import matrix_catalog_switch_policy_contexts, matrix_policy_contexts
from firewall_compliance.application.matrix_scope_assessment import (
    MatrixScopeAssessment, matrix_scope_checksum, matrix_scope_revision_checksum,
)
from firewall_compliance.domain.access_context import AccessContextResolution
from firewall_compliance.domain.access_journey import AccessJourney
from firewall_compliance.domain.access_journey_observations import (
    JourneyObservation,
    JourneyObservationOutcome,
    JourneyObservationSnapshot,
)
from firewall_compliance.domain.access_matrix import AccessMatrix, MatrixRequirement
from firewall_compliance.domain.controls import ControlModel
from firewall_compliance.domain.policy_matching import AddressSet, resolve_addresses
from firewall_compliance.domain.revision import DeviceRevision

JourneyObservationDisposition = Literal[
    "observed_success", "observed_denial", "inconclusive", "outside_requirement", "unmatched",
]
type ObservationCode = JourneyObservationOutcome | Literal[
    "step_unknown", "requirement_missing", "assessment_unavailable", "source_unavailable",
    "context_unconfirmed", "context_mismatch",
    "family_mismatch", "address_unconfirmed", "address_outside", "service_outside", "identity_unconfirmed",
    "session_unconfirmed", "zones_unconfirmed", "zones_mismatch", "interface_mismatch",
]
type TransactionCode = Literal[
    "completed", "stage_count_mismatch", "sample_missing", "sample_repeated", "stage_order_mismatch",
    "trace_mismatch", "sample_not_successful", "sample_time_mismatch", "intermediate_mismatch",
]

_OUTCOMES: dict[JourneyObservationOutcome, tuple[JourneyObservationDisposition, str]] = {
    "connected": ("observed_success", "В источнике записано установление TCP-соединения для этой попытки."),
    "response_observed": ("observed_success", "В источнике записан ответ для этой попытки."),
    "denied": ("observed_denial", "В источнике записан явный отказ для этой попытки."),
    "timeout": ("inconclusive", "Истекло время ожидания. Причина отсутствия ответа неизвестна."),
    "unknown": ("inconclusive", "Источник не содержит определённого результата попытки."),
}


class JourneyObservationResult(ControlModel):
    observation_index: int = Field(ge=0, strict=True)
    step_id: str
    disposition: JourneyObservationDisposition
    code: ObservationCode
    message: str
    artifact_id: UUID | None = None
    revision_id: UUID | None = None
    context_resolution: AccessContextResolution | None = None


class JourneyTransactionResult(ControlModel):
    transaction_index: int = Field(ge=0, strict=True)
    trace_id: str
    disposition: Literal["observed_completed", "unconfirmed"]
    code: TransactionCode
    message: str
    observation_indices: tuple[int, ...]

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        if (self.disposition == "observed_completed") != (self.code == "completed"):
            raise ValueError("Итог транзакции не соответствует коду результата")
        return self


def _evaluate_transactions(
    journey: AccessJourney, snapshot: JourneyObservationSnapshot, observations: Sequence[JourneyObservationResult],
) -> tuple[JourneyTransactionResult, ...]:
    if not snapshot.transactions:
        return ()
    index_by_record = {
        (sample.origin.source_name, sample.origin.record_id): index
        for index, sample in enumerate(snapshot.observations)
    }
    expected_steps = tuple(step.step_id for step in journey.steps)
    results = []
    for index, transaction in enumerate(snapshot.transactions):
        references = tuple(index_by_record.get((sample.source_name, sample.record_id)) for sample in transaction.samples)
        indices = tuple(position for position in references if position is not None)
        samples = tuple(snapshot.observations[position] for position in indices)
        times = tuple(sample.origin.observed_at for sample in samples)
        code: TransactionCode
        if len(references) != len(expected_steps):
            code, message = "stage_count_mismatch", "Для транзакции нужна отдельная ссылка на каждый участок цепочки."
        elif len(indices) != len(references):
            code, message = "sample_missing", "Часть записей транзакции отсутствует в импортированном снимке."
        elif len(indices) != len(set(indices)):
            code, message = "sample_repeated", "Одна запись указана для нескольких участков транзакции."
        elif tuple(sample.step_id for sample in samples) != expected_steps:
            code, message = "stage_order_mismatch", "Порядок участков в источнике отличается от утверждённой цепочки."
        elif any(sample.trace_id != transaction.trace_id for sample in samples):
            code, message = "trace_mismatch", "Записи участков должны иметь тот же идентификатор трассы."
        elif any(observations[position].disposition != "observed_success" for position in indices):
            code, message = "sample_not_successful", "Для каждого участка нужно сопоставленное соединение или ответ."
        elif any(not transaction.started_at <= time <= transaction.completed_at for time in times) or any(
            before > after for before, after in pairwise(times)
        ):
            code, message = "sample_time_mismatch", "Времена записей выходят за интервал транзакции или нарушают порядок."
        elif any(
            (before.destination_ip, before.context_id) != (after.source_ip, after.context_id)
            for before, after in pairwise(samples)
        ):
            code, message = "intermediate_mismatch", "Адрес или контекст промежуточного узла меняется между участками."
        else:
            code, message = "completed", "В источнике записано завершение этой транзакции, и записи всех участков сопоставлены."
        results.append(JourneyTransactionResult(
            transaction_index=index, trace_id=transaction.trace_id,
            disposition="observed_completed" if code == "completed" else "unconfirmed", code=code,
            message=message, observation_indices=indices,
        ))
    return tuple(results)


class JourneyObservationAssessment(ControlModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    configuration: JourneyAssessment
    snapshot: JourneyObservationSnapshot
    observations: tuple[JourneyObservationResult, ...]
    transactions: tuple[JourneyTransactionResult, ...] = ()
    limitations: tuple[str, ...] = (
        "Записи относятся к отдельным попыткам и времени наблюдения. Общая доступность не оценивается.",
        "Происхождение записи взято из импортированного файла. Подлинность исходного журнала не проверяется.",
        "Сопоставление использует сохранённые адреса, условия и контексты. Применение конкретной конфигурации в момент наблюдения не доказано.",
        "Причина отказа и его место на пути требуют самостоятельных сведений. Тайм-аут не подтверждает запрет.",
        "Завершение показывается для явно записанной транзакции со связью всех участков. Оно относится к указанному событию.",
    )

    @model_validator(mode="after")
    def validate_alignment(self) -> Self:
        configuration, snapshot = self.configuration, self.snapshot
        if (
            configuration.project_id, configuration.journey.scope_id, configuration.matrix_id,
            configuration.matrix_version, configuration.journey.journey_id,
        ) != (snapshot.project_id, snapshot.scope_id, snapshot.matrix_id, snapshot.matrix_version, snapshot.journey_id):
            raise ValueError("Наблюдения относятся к другой версии или области цепочки")
        scope = configuration.scope_assessment
        if scope is not None and scope.matrix_checksum != snapshot.matrix_checksum:
            raise ValueError("Наблюдения относятся к другой версии матрицы")
        if len(self.observations) != len(snapshot.observations) or any(
            row.observation_index != index or row.step_id != snapshot.observations[index].step_id
            for index, row in enumerate(self.observations)
        ):
            raise ValueError("Результаты должны соответствовать записям снимка")
        steps = {step.step_id: step for step in configuration.steps}
        for row, observation in zip(self.observations, snapshot.observations, strict=True):
            step = steps.get(row.step_id)
            if row.artifact_id is not None or row.revision_id is not None:
                if step is None or (row.artifact_id, row.revision_id) != (step.artifact_id, step.revision_id):
                    raise ValueError("Результат ссылается на другую сверку участка")
            reference = row.revision_id if scope is not None else row.artifact_id
            if row.disposition in {"observed_success", "observed_denial", "inconclusive"} and (
                reference is None or row.code != observation.outcome
                or row.disposition != _OUTCOMES[observation.outcome][0]
            ):
                raise ValueError("Результат должен соответствовать наблюдаемому исходу попытки")
        if self.transactions != _evaluate_transactions(configuration.journey, snapshot, self.observations):
            raise ValueError("Результаты транзакций должны соответствовать связанным записям")
        return self


def _contains(addresses: AddressSet, address: IPv4Address | IPv6Address) -> bool:
    intervals = addresses[0 if address.version == 4 else 1]
    value = int(address)
    index = bisect_right(intervals, value, key=lambda interval: interval[0]) - 1
    return index >= 0 and value <= intervals[index][1]


class _ObservationMatcher:
    def __init__(
        self, matrix: AccessMatrix, revision: DeviceRevision, bindings: CatalogBindings, *,
        project_id: str, scope_id: str, artifact_id: UUID | None = None, cloud_selection: CloudSGSelection | None = None,
        session_resolver: MatrixSessionResolver | None = None,
        bindings_by_vrf: Mapping[str, CatalogBindings] | None = None,
    ) -> None:
        self.revision = revision
        self.project_id = project_id
        self.scope_id = scope_id
        self.artifact_id = artifact_id
        self.cloud_selection = cloud_selection
        self.interface_addresses: AddressSet | None = None
        if artifact_id is None and cloud_selection is not None:
            endpoints = tuple(endpoint for endpoint in revision.parse_result.endpoints
                              if endpoint.endpoint_id == f"interface:{cloud_selection.interface_id}")
            if len(endpoints) == 1:
                self.interface_addresses = resolve_addresses(endpoints)
        self.groups = MatrixPolicyGroupResolver(matrix, revision, bindings, bindings_by_vrf or {}, lambda: None)
        self.policy_contexts = matrix_policy_contexts(revision)
        self.session_resolver = session_resolver
        self.policy_ids = (
            {rule.policy_id for rule in revision.parse_result.rules if rule.enabled}
            if artifact_id is None else set()
        )

    def match(
        self, index: int, observation: JourneyObservation, requirement: MatrixRequirement,
    ) -> JourneyObservationResult:
        def result(
            disposition: JourneyObservationDisposition, code: ObservationCode, message: str,
            resolution: AccessContextResolution | None = None,
        ) -> JourneyObservationResult:
            return JourneyObservationResult(
                observation_index=index, step_id=observation.step_id, disposition=disposition, code=code,
                message=message, artifact_id=self.artifact_id, revision_id=self.revision.revision_id,
                context_resolution=resolution,
            )

        if self.artifact_id is None and (requirement.policy_id is None or requirement.policy_id not in self.policy_ids):
            return result("unmatched", "source_unavailable", "В исходной ревизии не найдена политика этого участка.")
        if requirement.zone_pair is not None:
            if observation.zone_pair is None:
                return result("unmatched", "zones_unconfirmed", "В записи отсутствуют зоны источника и назначения.")
            if observation.zone_pair != requirement.zone_pair:
                return result("outside_requirement", "zones_mismatch", "Пара зон записи отличается от условий участка.")

        context = self.policy_contexts.get(requirement.policy_id or "", self.revision.device.context)
        if context is None:
            return result("unmatched", "context_unconfirmed", "В сохранённой сверке не подтверждён сетевой контекст.")
        if context != observation.context_id:
            return result("outside_requirement", "context_mismatch", "Наблюдение относится к другому сетевому контексту.")

        source_ip, destination_ip = ip_address(observation.source_ip), ip_address(observation.destination_ip)
        if (selection := self.cloud_selection) is not None:
            if selection.family != source_ip.version:
                return result("outside_requirement", "family_mismatch", "Наблюдение относится к другому семейству IP.")
            if self.artifact_id is None:
                interface_ip = destination_ip if selection.direction == "ingress" else source_ip
                if self.interface_addresses is None:
                    return result("unmatched", "source_unavailable", "Адреса интерфейса группы безопасности не подтверждены.")
                if not _contains(self.interface_addresses, interface_ip):
                    return result("outside_requirement", "interface_mismatch", "Наблюдение относится к другому облачному интерфейсу.")
        groups = self.groups.for_policy(requirement.policy_id)
        source = groups.resolve(requirement.source_group)
        destination = groups.resolve(requirement.destination_group)
        if source is None or destination is None:
            return result("unmatched", "address_unconfirmed", "В сохранённой сверке состав адресных групп не подтверждён.")
        if not _contains(source, source_ip) or not _contains(destination, destination_ip):
            return result("outside_requirement", "address_outside", "Адреса попытки выходят за сохранённые условия участка.")

        service = requirement.service
        port = observation.destination_port
        if service.protocol not in {"ip", observation.protocol} or (
            service.protocol in {"tcp", "udp"} and not service.any_ports
            and (port is None or not any(item.start <= port <= item.end for item in service.ports))
        ):
            return result("outside_requirement", "service_outside", "Протокол или порт назначения выходят за условия участка.")
        if requirement.identity is not None or requirement.schedule is not None:
            return result("unmatched", "identity_unconfirmed", "Текстовое условие пользователя или расписания не сопоставлено.")

        resolution = None
        if requirement.access_context is not None:
            if (
                self.session_resolver is None or observation.session_id is None
                or self.session_resolver.session_for(requirement.requirement_id) != observation.session_id
            ):
                return result("unmatched", "session_unconfirmed", "Нужна ссылка на выбранный сеанс сохранённой сверки.")
            # Адрес уже входит в сохранённую группу. Теперь проверяется, что
            # этот узел относился к указанному сеансу в момент наблюдения.
            session_index = self.session_resolver.index_for(requirement.requirement_id, context)
            resolution = session_index.resolve(
                requirement.access_context, session_id=observation.session_id, project_id=self.project_id,
                scope_id=self.scope_id, context_id=context, at=observation.origin.observed_at,
                source_prefixes=(f"{source_ip}/{source_ip.max_prefixlen}",),
            )
            if resolution.source_cidr is None or source_ip != ip_network(resolution.source_cidr).network_address:
                return result("unmatched", "session_unconfirmed", resolution.message, resolution)

        disposition, message = _OUTCOMES[observation.outcome]
        return result(disposition, observation.outcome, message, resolution)


def _validate_snapshot(
    matrix: AccessMatrix, journey: AccessJourney,
    snapshot: JourneyObservationSnapshot, *, project_id: str, matrix_checksum: str,
) -> None:
    expected = (project_id, journey.scope_id, matrix.matrix_id, matrix.version, matrix_checksum, journey.journey_id)
    actual = (
        snapshot.project_id, snapshot.scope_id, snapshot.matrix_id, snapshot.matrix_version,
        snapshot.matrix_checksum, snapshot.journey_id,
    )
    if journey not in matrix.journeys or actual != expected:
        raise ValueError("Снимок наблюдений должен относиться к этой утверждённой цепочке и версии матрицы")


def _observe(
    matrix: AccessMatrix, configuration: JourneyAssessment, snapshot: JourneyObservationSnapshot,
    matcher_for: Callable[[JourneyStepAssessment], _ObservationMatcher | None],
) -> JourneyObservationAssessment:
    steps = {step.step_id: step for step in configuration.steps}
    requirements = {row.requirement_id: row for row in matrix.requirements}
    scope = configuration.scope_assessment is not None
    results: list[JourneyObservationResult] = []
    for index, observation in enumerate(snapshot.observations):
        step = steps.get(observation.step_id)
        code: ObservationCode
        if step is None:
            code, message = "step_unknown", "Участок наблюдения отсутствует в утверждённой цепочке."
        elif step.requirement_id is None:
            code, message = "requirement_missing", "Для участка нет утверждённых условий доступа."
        elif (step.revision_id if scope else step.artifact_id) is None:
            code, message = "assessment_unavailable", "Для участка нужна совместимая сохранённая сверка."
        elif (matcher := matcher_for(step)) is None:
            code, message = "source_unavailable", "Исходная ревизия участка недоступна или не совпадает со сверкой."
        else:
            results.append(matcher.match(index, observation, requirements[step.requirement_id]))
            continue
        results.append(JourneyObservationResult(
            observation_index=index, step_id=observation.step_id, disposition="unmatched", code=code, message=message,
        ))

    return JourneyObservationAssessment(
        configuration=configuration, snapshot=snapshot, observations=tuple(results),
        transactions=_evaluate_transactions(configuration.journey, snapshot, results),
    )


def evaluate_journey_observations(
    matrix: AccessMatrix, journey: AccessJourney, assessments: Mapping[str, MatrixAssessmentArtifact],
    snapshot: JourneyObservationSnapshot, *, project_id: str,
) -> JourneyObservationAssessment:
    """Показать наблюдения и локальные сверки независимо, сохраняя исходные записи."""
    _validate_snapshot(matrix, journey, snapshot, project_id=project_id, matrix_checksum=matrix_scope_checksum(matrix))
    configuration = evaluate_journey(matrix, journey, assessments, project_id=project_id)
    matchers: dict[UUID, _ObservationMatcher] = {}

    def matcher_for(step: JourneyStepAssessment) -> _ObservationMatcher:
        artifact = assessments[step.step_id]
        matcher = matchers.get(artifact.artifact_id)
        if matcher is None:
            inputs, selection = artifact.context_inputs, artifact.cloud_selection
            bindings, bindings_by_vrf = split_catalog_bindings(artifact.bindings)
            matcher = _ObservationMatcher(
                artifact.matrix, artifact.revision, bindings,
                project_id=artifact.origin_project_id, scope_id=artifact.assessment.scope_id,
                artifact_id=artifact.artifact_id, cloud_selection=selection,
                session_resolver=MatrixSessionResolver(inputs) if inputs is not None else None,
                bindings_by_vrf=bindings_by_vrf,
            )
            matchers[artifact.artifact_id] = matcher
        return matcher

    return _observe(matrix, configuration, snapshot, matcher_for)


def evaluate_scope_journey_observations(
    matrix: AccessMatrix, journey: AccessJourney, result: MatrixScopeAssessment,
    snapshot: JourneyObservationSnapshot, *, project_id: str, artifact_id: UUID | None = None,
    load_revision: Callable[[UUID], DeviceRevision],
) -> JourneyObservationAssessment:
    """Сопоставить попытки по исходным ревизиям одной сохранённой сверки области."""
    _validate_snapshot(matrix, journey, snapshot, project_id=project_id, matrix_checksum=result.matrix_checksum)
    configuration = evaluate_scope_journey(matrix, journey, result, project_id=project_id, artifact_id=artifact_id)
    sources = {source.revision_id: source for source in result.sources}
    expected_contexts: dict[UUID, dict[str, str]] = {}
    for row in result.requirements:
        if row.revision_id is not None and row.policy_id is not None and row.policy_vrf is not None:
            expected_contexts.setdefault(row.revision_id, {})[row.policy_id] = row.policy_vrf
    matchers: dict[UUID, _ObservationMatcher | None] = {}
    inputs = result.context_inputs
    sessions = MatrixSessionResolver(inputs) if inputs is not None else None

    def matcher_for(step: JourneyStepAssessment) -> _ObservationMatcher | None:
        revision_id = step.revision_id
        if revision_id is None or (source := sources.get(revision_id)) is None:
            return None
        if revision_id in matchers:
            return matchers[revision_id]
        matchers[revision_id] = None
        try:
            revision = load_revision(revision_id)
        except (ValueError, OSError):
            return None
        device, config = revision.device, revision.parse_result.configuration
        switch = revision.parse_result.switch_facts
        device_label = device.hostname or (switch.hostname if switch is not None else None) or device.device_id
        if (
            revision.revision_id != revision_id
            or (device.device_id, device.platform, device.context)
            != (source.device_id, source.platform, source.device_context)
            or source.device_label not in {device_label, device.hostname or device.device_id}
            or (config.content_sha256, config.parser_version, config.captured_at)
            != (source.configuration_sha256, source.parser_version, source.captured_at)
            or matrix_scope_revision_checksum(revision) != source.revision_checksum
        ):
            return None
        if expected := expected_contexts.get(revision_id):
            confirmed = matrix_catalog_switch_policy_contexts(revision)
            if any(confirmed.get(policy) != vrf for policy, vrf in expected.items()):
                return None
        selection = source.cloud_selection
        try:
            bindings, bindings_by_vrf = split_catalog_bindings(source.bindings)
        except ValueError:
            return None
        matcher = _ObservationMatcher(
            matrix, revision, bindings,
            project_id=project_id, scope_id=result.scope_id, cloud_selection=selection,
            session_resolver=sessions, bindings_by_vrf=bindings_by_vrf,
        )
        matchers[revision_id] = matcher
        return matcher

    return _observe(matrix, configuration, snapshot, matcher_for)
