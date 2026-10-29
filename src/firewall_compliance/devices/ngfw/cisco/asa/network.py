"""Отдельный адаптер ASA с явными ролями и консервативной полнотой."""

import re
from typing import Literal

from firewall_compliance.devices.ngfw.cisco.asa.interfaces import parse_interfaces
from firewall_compliance.devices.ngfw.cisco.asa.routes import parse_routes
from firewall_compliance.domain import (
    DataStatus,
    ParseIssue,
    ParseIssueLevel,
    RevisionSource,
    SourceDocumentKind,
)
from firewall_compliance.domain.revision import CollectionEvidence
from firewall_compliance.parsers.contracts import (
    DetectionResult,
    ParseFailure,
    ParserMetadata,
    SourceDocument,
)
from firewall_compliance.parsers.network_contracts import (
    NetworkDocumentMetadata,
    NetworkParseOutcome,
    NetworkParseRequest,
    NetworkParseResult,
    NetworkSourceKind,
)

COMMANDS = {
    "asa_running_config_interfaces": "show running-config interface",
    "asa_running_config_static_routes": "show running-config route",
    "asa_ipv4_rib": "show route",
}
SCOPES: dict[NetworkSourceKind, Literal["interfaces", "configured_routes", "routing_table"]] = {
    "asa_running_config_interfaces": "interfaces",
    "asa_running_config_static_routes": "configured_routes",
    "asa_ipv4_rib": "routing_table",
}


def _metadata_errors(metadata: NetworkDocumentMetadata) -> tuple[ParseIssue, ...]:
    problems: list[tuple[str, str]] = []
    if re.fullmatch(r"9\.16(?:\([0-9]+\))?", metadata.declared_version) is None:
        problems.append(
            (
                "network_version_unsupported",
                "Заявленная версия не входит в профиль ASA 9.16/9.16(n).",
            )
        )
    if metadata.command != COMMANDS[metadata.source_kind]:
        problems.append(
            (
                "network_command_mismatch",
                "Роль требует точную команду профиля; параметры и pipe-filter не поддержаны.",
            )
        )
    if metadata.context_mode != "single" or metadata.firewall_mode != "routed":
        problems.append(
            ("network_mode_unsupported", "Профиль ограничен single context и routed mode.")
        )
    if (
        metadata.address_family != "ipv4"
        or metadata.table_role != "data"
        or metadata.table_id != "default"
    ):
        problems.append(
            ("network_scope_unsupported", "Требуется единственная IPv4 таблица data/default.")
        )
    return tuple(
        ParseIssue(code=code, level=ParseIssueLevel.ERROR, message=message)
        for code, message in problems
    )


class CiscoAsaNetworkParser:
    metadata = ParserMetadata(parser_id="cisco-asa-network-9.16", version="0.1.0", vendor="cisco")

    def detect(
        self, source: SourceDocument, metadata: NetworkDocumentMetadata | None = None
    ) -> DetectionResult:
        match = False
        reasons: tuple[str, ...]
        if metadata is None:
            reasons = ("Тело и имя файла не определяют сетевую роль; нужны явные метаданные.",)
        else:
            metadata = NetworkDocumentMetadata.model_validate(metadata.model_dump(mode="python"))
            errors = _metadata_errors(metadata)
            if source.content_sha256 != metadata.content_sha256.lower():
                reasons = ("SHA-256 не соответствует метаданным документа.",)
            elif errors:
                reasons = tuple(issue.message for issue in errors)
            else:
                match = True
                reasons = (
                    "Роль явно заявлена метаданными в поддержанном профиле; "
                    "это не проверка подлинности производителя.",
                )
        return DetectionResult(
            parser_id=self.metadata.parser_id,
            is_match=match,
            confidence=1 if match else 0,
            reasons=reasons,
        )

    def parse(self, request: NetworkParseRequest) -> NetworkParseOutcome:
        request = NetworkParseRequest.model_validate(request.model_dump(mode="python"))
        source, metadata = request.source, request.metadata
        errors = _metadata_errors(metadata)
        if errors:
            return ParseFailure(
                parser_id=self.metadata.parser_id,
                source_name=source.source_name,
                content_sha256=source.content_sha256,
                errors=errors,
            )
        try:
            text = source.content.decode(metadata.encoding, errors="strict")
        except UnicodeDecodeError:
            return ParseFailure(
                parser_id=self.metadata.parser_id,
                source_name=source.source_name,
                content_sha256=source.content_sha256,
                errors=(
                    ParseIssue(
                        code="network_encoding_invalid",
                        level=ParseIssueLevel.ERROR,
                        message="Байты не соответствуют заявленной кодировке.",
                    ),
                ),
            )
        parsed = (
            parse_interfaces(request, text)
            if metadata.source_kind == "asa_running_config_interfaces"
            else parse_routes(request, text)
        )
        warnings = parsed.warnings
        if source.observation is None:
            warnings += (
                ParseIssue(
                    code="network_observation_missing",
                    level=ParseIssueLevel.WARNING,
                    message="Время наблюдения не задано; полнота набора не доказана.",
                ),
            )
        if not metadata.complete:
            warnings += (
                ParseIssue(
                    code="network_capture_partial",
                    level=ParseIssueLevel.WARNING,
                    message="Метаданные не доказывают полный захват всей области.",
                ),
            )
        if not metadata.capture_success:
            warnings += (
                ParseIssue(
                    code="network_capture_failed",
                    level=ParseIssueLevel.WARNING,
                    message="Успешное получение документа не подтверждено.",
                ),
            )
        facts = (*parsed.interfaces, *parsed.routes)
        fully_parsed = (
            parsed.coverage.recognized_constructs == parsed.coverage.discovered_constructs
        )
        complete = (
            metadata.complete
            and source.observation is not None
            and fully_parsed
            and not (warnings or parsed.errors or parsed.unsupported_constructs)
            and all(fact.data_status == DataStatus.KNOWN for fact in facts)
        )
        status = (
            (DataStatus.KNOWN if facts else DataStatus.ABSENT) if complete else DataStatus.UNKNOWN
        )
        scope = SCOPES[metadata.source_kind]
        return NetworkParseResult(
            metadata=metadata,
            source=RevisionSource(
                source_document_id=metadata.source_document_id,
                source_name=source.source_name,
                content_sha256=source.content_sha256,
                captured_at=source.captured_at,
                file_modified_at=source.file_modified_at,
                observation=source.observation,
                kind=SourceDocumentKind.ROUTING_TABLE
                if scope == "routing_table"
                else SourceDocumentKind.CONFIGURATION,
            ),
            scope=scope,
            status=status,
            interfaces=parsed.interfaces,
            routes=parsed.routes,
            interface_labels=parsed.interface_labels,
            interface_settings=parsed.interface_settings,
            collection_evidence=CollectionEvidence(
                scope=scope, complete=complete, source_document_ids=(metadata.source_document_id,)
            ),
            warnings=warnings,
            errors=parsed.errors,
            unsupported_constructs=parsed.unsupported_constructs,
            source_map={
                **{
                    interface.interface_id: interface.source_location
                    for interface in parsed.interfaces
                    if interface.source_location is not None
                },
                **{
                    route.route_id: route.source_location
                    for route in parsed.routes
                    if route.source_location is not None
                },
            },
            coverage=parsed.coverage,
            limitations=(
                "Метаданные и наблюдение заявлены источником; "
                "SHA-256 не доказывает их подлинность.",
                "Настроенные маршруты не доказывают установку в RIB; "
                "connected из IP интерфейса не выводится.",
                "L, динамика, ECMP, operational state, ACL/NAT/PBR "
                "и достижимость не реализованы этим адаптером.",
            ),
        )
