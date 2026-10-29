"""Адаптеры и контракты парсинга конфигураций производителей."""

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


from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from firewall_compliance.devices.network.hpe_aruba.policy import HpArubaParser
    from firewall_compliance.devices.network.hpe_h3c.comware.policy import ComwareParser
    from firewall_compliance.devices.ngfw.cisco.asa.forwarding import CiscoAsaForwardingParser
    from firewall_compliance.devices.ngfw.cisco.asa.network import CiscoAsaNetworkParser
    from firewall_compliance.devices.ngfw.cisco.asa.policy import CiscoAsaParser


_PARSERS = {
    "HpArubaParser": "firewall_compliance.devices.network.hpe_aruba.policy",
    "ComwareParser": "firewall_compliance.devices.network.hpe_h3c.comware.policy",
    "CiscoAsaForwardingParser": "firewall_compliance.devices.ngfw.cisco.asa.forwarding",
    "CiscoAsaNetworkParser": "firewall_compliance.devices.ngfw.cisco.asa.network",
    "CiscoAsaParser": "firewall_compliance.devices.ngfw.cisco.asa.policy",
}


def __getattr__(name: str) -> Any:
    if name not in _PARSERS:
        raise AttributeError(name)
    return getattr(import_module(_PARSERS[name]), name)
