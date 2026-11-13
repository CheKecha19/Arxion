"""Зафиксированные сведения о сеансах для отдельной сверки матрицы."""

from typing import Any, Literal, Self

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from firewall_compliance.domain.access_context import AccessContextSnapshot, ContextIdentifier, ContextTime
from firewall_compliance.domain.controls import ControlModel


class MatrixSessionSelection(ControlModel):
    requirement_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=512)
    context_id: ContextIdentifier | None = None

    @model_serializer(mode="wrap")
    def serialize_context(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        if self.context_id is None:
            payload.pop("context_id", None)
        return payload


class MatrixContextSource(ControlModel):
    """Снимок и время проверки в одном сетевом контексте."""

    snapshot: AccessContextSnapshot
    evaluated_at: ContextTime


class MatrixContextInputs(ControlModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    snapshot: AccessContextSnapshot
    evaluated_at: ContextTime
    sessions: tuple[MatrixSessionSelection, ...] = ()
    additional_contexts: tuple[MatrixContextSource, ...] = ()

    @property
    def contexts(self) -> tuple[MatrixContextSource, ...]:
        # Поля основного источника уже проверены при чтении входов.
        primary = MatrixContextSource.model_construct(snapshot=self.snapshot, evaluated_at=self.evaluated_at)
        return (primary, *self.additional_contexts)

    def context_for_selection(self, selection: MatrixSessionSelection) -> str:
        return selection.context_id or self.snapshot.context_id

    @model_serializer(mode="wrap")
    def serialize_contexts(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        payload: dict[str, Any] = handler(self)
        if not self.additional_contexts:
            payload.pop("additional_contexts", None)
        return payload

    @model_validator(mode="after")
    def validate_selections(self) -> Self:
        identifiers = {row.requirement_id for row in self.sessions}
        if len(identifiers) != len(self.sessions):
            raise ValueError("Для требования допустим один выбранный сеанс")
        scope = (self.snapshot.project_id, self.snapshot.scope_id)
        contexts = {self.snapshot.context_id}
        for source in self.additional_contexts:
            snapshot = source.snapshot
            if (snapshot.project_id, snapshot.scope_id) != scope:
                raise ValueError("Снимки сеансов должны относиться к одному проекту и области")
            if snapshot.context_id in contexts:
                raise ValueError("Для сетевого контекста допустим один снимок сеансов")
            contexts.add(snapshot.context_id)
        if any(self.context_for_selection(row) not in contexts for row in self.sessions):
            raise ValueError("Назначение сеанса ссылается на отсутствующий сетевой контекст")
        return self
