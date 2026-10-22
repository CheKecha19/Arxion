"""Адаптеры и контракты парсинга конфигураций производителей."""

from firewall_compliance.parsers.cisco_asa import CiscoAsaParser
from firewall_compliance.parsers.cisco_asa_forwarding import CiscoAsaForwardingParser
from firewall_compliance.parsers.cisco_asa_network import CiscoAsaNetworkParser
from firewall_compliance.parsers.comware import ComwareParser
from firewall_compliance.parsers.contracts import (
    ConfigurationParser,
    DetectionResult,
    ParseFailure,
    ParseOutcome,
    ParseRequest,
    ParserMetadata,
    SourceDocument,
)
from firewall_compliance.parsers.forwarding_contracts import (
    ForwardingFactsParser,
    ForwardingParseOutcome,
    ForwardingParseRequest,
    ForwardingParseResult,
)
from firewall_compliance.parsers.hp_aruba import HpArubaParser
from firewall_compliance.parsers.network_contracts import (
    NetworkDocumentMetadata,
    NetworkFactsParser,
    NetworkInterfaceBinding,
    NetworkParseOutcome,
    NetworkParseRequest,
    NetworkParseResult,
)
from firewall_compliance.parsers.registry import (
    AmbiguousParserError,
    ParserContractError,
    ParserRegistry,
)

__all__ = [
    "AmbiguousParserError",
    "CiscoAsaParser",
    "CiscoAsaForwardingParser",
    "CiscoAsaNetworkParser",
    "ComwareParser",
    "HpArubaParser",
    "ConfigurationParser",
    "DetectionResult",
    "ForwardingFactsParser",
    "ForwardingParseOutcome",
    "ForwardingParseRequest",
    "ForwardingParseResult",
    "ParseFailure",
    "ParseOutcome",
    "ParseRequest",
    "ParserContractError",
    "ParserMetadata",
    "ParserRegistry",
    "SourceDocument",
    "NetworkDocumentMetadata",
    "NetworkFactsParser",
    "NetworkInterfaceBinding",
    "NetworkParseOutcome",
    "NetworkParseRequest",
    "NetworkParseResult",
]
