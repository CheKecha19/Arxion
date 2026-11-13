"""Определение семейства конфигурации по синтаксису и независимым признакам."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SwitchPlatformDetection:
    """Основания выбора ОС; оценка не подтверждает подлинность документа."""

    platform: str | None
    family: str | None
    version: str | None
    confidence: float
    reasons: tuple[str, ...]
    candidates: tuple[str, ...] = ()

    @property
    def ambiguous(self) -> bool:
        """Вернуть наличие несовместимых сильных признаков ОС."""
        return len(self.candidates) > 1


def detect_switch_platform(text: str) -> SwitchPlatformDetection:
    """Распознать ОС без зависимости от ACL, имени устройства или файла.

    Точные платформенные заголовки и характерные конструкции учитываются
    отдельно. Общая строка version сама по себе не выбирает Comware.
    """
    text = text.lstrip("\ufeff")

    def match(pattern: str) -> re.Match[str] | None:
        return re.search(pattern, text, re.IGNORECASE | re.MULTILINE)

    signals: dict[str, tuple[float, tuple[str, ...], str | None]] = {}
    cx_header = match(
        r"^[ \t]*[!;#]?[ \t]*(?:version[ \t]+)?"
        r"(?:arubaos-cx|aos-cx|aruba os-cx)\b(?:[ \t]+([^\s!;#]+))?"
    )
    cx_acl = match(r"^[ \t]*access-list ip[ \t]+\S+")
    cx_binding = match(r"^[ \t]*apply access-list ip[ \t]+\S+")
    cx_vsf = match(r"^[ \t]*vsf member[ \t]+\d+")
    cx_routing = match(r"^[ \t]*no routing[ \t]*$")
    cx_ssh = match(r"^[ \t]*ssh server vrf[ \t]+\S+")
    if cx_header:
        signals["aos-cx"] = (
            0.98,
            ("Заголовок ArubaOS-CX/AOS-CX.",),
            cx_header[1],
        )
    elif (cx_acl and cx_binding) or (cx_vsf and (cx_routing or cx_ssh)):
        signals["aos-cx"] = (
            0.90,
            ("Сочетание характерных конструкций AOS-CX (ACL/apply либо VSF/VRF).",),
            None,
        )

    switch_header = match(
        r"^[ \t]*(?:[!;#][ \t]*[^\r\n]*\bconfiguration editor\b|"
        r"(?:hpStack|HP|HPE|Aruba)[ \t]+[^\r\n]*\bconfiguration editor\b|"
        r"[!;#]?[ \t]*arubaos-switch\b)"
    )
    manager = match(r"^[ \t]*ip authorized-managers[ \t]+\S+")
    if switch_header:
        release = match(r"\bcreated on release[ \t]+#?([^\s;]+)")
        signals["aos-switch"] = (
            0.96 if release else 0.88,
            ("Заголовок Configuration Editor/ArubaOS-Switch.",),
            release[1] if release else None,
        )
    elif manager:
        signals["aos-switch"] = (
            0.80,
            ("Характерная директива AOS-Switch ip authorized-managers; заголовок отсутствует.",),
            None,
        )

    comware_version = match(r"^[ \t]*version[ \t]+((?:5\.20|7\.1)\.[^\s,]+)")
    comware_banner = match(
        r"^[ \t]*[!;#]?[ \t]*(?:(?:HPE?|H3C)[ \t]+)?Comware\b"
    )
    comware_sysname = match(r"^[ \t]*sysname[ \t]+\S+")
    comware_acl = match(r"^[ \t]*acl (?:number|basic|advanced)\b")
    comware_interface = match(r"^[ \t]*interface (?:Vlan-interface|Bridge-Aggregation)\S+")
    comware_irf = match(r"^[ \t]*(?:irf-port[ \t]+\d+/\d+|irf member[ \t]+\d+)")
    comware_aaa = match(r"^[ \t]*radius scheme[ \t]+\S+")
    comware_shape = any((comware_sysname, comware_acl, comware_interface, comware_irf, comware_aaa))
    if (comware_version or comware_banner) and comware_shape:
        comware_reasons = ["Версия 5.20/7.1 либо заголовок Comware и характерный контекст конфигурации."]
        if comware_sysname:
            comware_reasons.append("Директива sysname.")
        if comware_irf:
            comware_reasons.append("Настройки IRF.")
        signals["comware"] = (
            0.96 if comware_version and comware_sysname else 0.90,
            tuple(comware_reasons),
            comware_version[1] if comware_version else None,
        )
        comware_generations = {
            value.split(".", 1)[0]
            for value in re.findall(
                r"^[ \t]*version[ \t]+((?:5\.20|7\.1)\.[^\s,]+)",
                text, re.IGNORECASE | re.MULTILINE,
            )
        }
        if len(comware_generations) > 1:
            signals["comware-version-conflict"] = (
                0.99,
                ("Одновременно присутствуют заголовки Comware 5 и Comware 7.",),
                None,
            )

    session_acl = match(r"^[ \t]*ip access-list session[ \t]+\S+")
    controller_role = match(r"^[ \t]*(?:user-role|wlan)[ \t]+\S+")
    controller_version = match(r"^[ \t]*[!]?[ \t]*(?:arubaos[ \t]+)?version[ \t]+(8\.\d+(?:\.\d+){0,3})[ \t]*$")
    controller_profile = match(r"^[ \t]*(?:controller-ip[ \t]+vlan|controller[ \t]+config|aaa derivation-rules user|crypto-local pki|ap-group)[ \t]+\S+")
    controller_objects = match(r"^[ \t]*(?:netdestination6?|netservice|aaa profile)[ \t]+\S+")
    if session_acl and controller_role or controller_version and (
        controller_profile or controller_role and controller_objects
    ):
        signals["arubaos-controller"] = (
            0.98 if controller_version else 0.95,
            ("Характерный синтаксис ArubaOS Controller; профиль AOS 8.x.",),
            controller_version[1] if controller_version else None,
        )
        controller_generations = {
            value for value in re.findall(
                r"^[ \t]*[!]?[ \t]*(?:arubaos[ \t]+)?version[ \t]+(8\.\d+)(?:\.\d+){0,3}[ \t]*$",
                text, re.IGNORECASE | re.MULTILINE,
            )
        }
        if len(controller_generations) > 1:
            signals["controller-version-conflict"] = (
                0.99, ("В одном документе заданы разные minor-версии ArubaOS Controller.",), None,
            )

    # Не допускаем выбора switch adapter по фрагменту смешанного документа.
    for platform, pattern in (
        ("cisco-asa", r"^[ \t]*ASA Version\b"),
        ("huawei-vrp", r"^[ \t]*[!;#]?[ \t]*(?:Huawei\b|VRP\b|[^\r\n]*\bVRP.*Software\b)"),
        ("juniper-junos", r"^[ \t]*set version[ \t]+\S+"),
    ):
        if match(pattern):
            signals[platform] = (0.99, (f"Заголовок/синтаксис другой платформы: {platform}.",), None)

    candidates = tuple(signals)
    if len(candidates) != 1:
        reasons = tuple(reason for _, evidence, _ in signals.values() for reason in evidence)
        if len(candidates) > 1:
            reasons = ("Конфликт признаков платформ: " + ", ".join(candidates) + ".", *reasons)
        return SwitchPlatformDetection(None, None, None, 0, reasons, candidates)
    platform = candidates[0]
    confidence, reasons, version = signals[platform]
    family = platform
    if platform == "comware" and version:
        family = "comware-5" if version.startswith("5.") else "comware-7"
    return SwitchPlatformDetection(
        platform, family, version, confidence,
        (*reasons, "Распознана ограниченная грамматика; подлинность и полнота экспорта не подтверждены."),
        candidates,
    )
