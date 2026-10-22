"""Единый набор экспериментальных конфигурационных адаптеров CLI и desktop."""

from firewall_compliance.parsers.cisco_asa import CiscoAsaParser
from firewall_compliance.parsers.comware import ComwareParser
from firewall_compliance.parsers.hp_aruba import HpArubaParser
from firewall_compliance.parsers.registry import ParserRegistry


def create_default_registry() -> ParserRegistry:
    """Выбрать формат по содержимому, сохраняя диагностику неподдержанных условий."""
    return ParserRegistry([CiscoAsaParser(), HpArubaParser(), ComwareParser()])
