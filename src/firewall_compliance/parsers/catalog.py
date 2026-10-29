"""Единый набор экспериментальных конфигурационных адаптеров CLI и desktop."""

from firewall_compliance.devices.network.hpe_aruba.policy import HpArubaParser
from firewall_compliance.devices.network.hpe_h3c.comware.policy import ComwareParser
from firewall_compliance.devices.ngfw.cisco.asa.policy import CiscoAsaParser
from firewall_compliance.parsers.ideco import IdecoParser
from firewall_compliance.parsers.registry import ParserRegistry
from firewall_compliance.parsers.usergate import UserGateParser


def create_default_registry() -> ParserRegistry:
    """Выбрать формат по содержимому, сохраняя диагностику неподдержанных условий."""
    return ParserRegistry(
        [CiscoAsaParser(), HpArubaParser(), ComwareParser(), UserGateParser(), IdecoParser()]
    )
