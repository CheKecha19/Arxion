"""Нейтральные контракты адаптеров парсинга."""

from datetime import datetime
from hashlib import sha256
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from firewall_compliance.domain.enums import ParseIssueLevel
from firewall_compliance.domain.observation import ObservationEvidence
from firewall_compliance.domain.parse_result import ParseIssue, ParseResult

type ConfigurationView = Literal["unknown", "local", "effective", "effective_detail", "pending"]


class SourceDocument(BaseModel):
    """Неизменяемый входной документ, передаваемый парсеру в памяти."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    source_name: str = Field(min_length=1)
    content: bytes
    configuration_complete: bool = Field(default=False, strict=True)
    configuration_view: ConfigurationView = "unknown"
    configuration_node_path: str | None = Field(default=None, min_length=1)
    captured_at: datetime
    file_modified_at: datetime | None = None
    observation: ObservationEvidence | None = None

    @model_validator(mode="after")
    def validate_captured_at(self) -> "SourceDocument":
        """Проверить наличие часового пояса у времени получения файла."""
        if self.captured_at.tzinfo is None:
            raise ValueError("captured_at должен содержать часовой пояс")
        if self.file_modified_at is not None and self.file_modified_at.tzinfo is None:
            raise ValueError("file_modified_at должен содержать часовой пояс")
        if self.observation is not None and self.observation.observed_at > self.captured_at:
            raise ValueError("наблюдение не может быть позже получения документа")
        return self

    @property
    def content_sha256(self) -> str:
        """Вернуть SHA-256 исходного содержимого."""
        return sha256(self.content).hexdigest()


class ParserMetadata(BaseModel):
    """Постоянные сведения об адаптере парсинга."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    parser_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    vendor: str = Field(min_length=1)


class DetectionResult(BaseModel):
    """Результат безопасного определения формата документа."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    parser_id: str = Field(min_length=1)
    is_match: bool
    confidence: float = Field(ge=0, le=1)
    reasons: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_match_confidence(self) -> "DetectionResult":
        """Не допустить неявную положительную оценку неподходящего парсера."""
        if self.is_match and self.confidence == 0:
            raise ValueError("подходящий парсер должен иметь положительную уверенность")
        if not self.is_match and self.confidence != 0:
            raise ValueError("неподходящий парсер должен иметь нулевую уверенность")
        return self


class ParseRequest(BaseModel):
    """Контекст одного запуска парсинга."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: SourceDocument
    imported_at: datetime

    @model_validator(mode="after")
    def validate_imported_at(self) -> "ParseRequest":
        """Проверить порядок временных отметок импорта."""
        if self.imported_at.tzinfo is None:
            raise ValueError("imported_at должен содержать часовой пояс")
        if self.imported_at < self.source.captured_at:
            raise ValueError("imported_at не может быть раньше captured_at")
        return self


class ParseFailure(BaseModel):
    """Неуспешный parse без ложного создания частичной Configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    parser_id: str = Field(min_length=1)
    source_name: str = Field(min_length=1)
    content_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    errors: tuple[ParseIssue, ...]
    warnings: tuple[ParseIssue, ...] = ()

    @model_validator(mode="after")
    def validate_errors(self) -> "ParseFailure":
        """Не допустить failure без фактической ошибки."""
        if not self.errors:
            raise ValueError("ParseFailure должен содержать хотя бы одну ошибку")
        if any(issue.level != ParseIssueLevel.ERROR for issue in self.errors):
            raise ValueError("errors ParseFailure должны иметь уровень error")
        return self


type ParseOutcome = ParseResult | ParseFailure


@runtime_checkable
class ConfigurationParser(Protocol):
    """Контракт адаптера конкретного производителя или формата."""

    @property
    def metadata(self) -> ParserMetadata:
        """Вернуть постоянные сведения о парсере."""

    def detect(self, source: SourceDocument) -> DetectionResult:
        """Проверить применимость парсера без изменения SourceDocument."""

    def parse(self, request: ParseRequest) -> ParseOutcome:
        """Вернуть нормализованный результат или явную ошибку парсинга."""
