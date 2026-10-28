"""Optional, narrowly scoped reference mappings; internal policy remains the default."""

from dataclasses import dataclass

from firewall_compliance.domain.controls import (
    CheckControlMapping,
    ControlCatalogue,
    ControlDefinition,
)

REFERENCE_REVIEW_DATE = "2026-10-28"
MAPPING_VERSION = "1.0.0"
REFERENCE_CATALOGUE_IDS = ("nist-sp800-41-r1", "nist-sp800-53-r5-20201210", "cis-controls-v8.1")

_NIST41 = "https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-41r1.pdf"
_NIST53 = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"
_CIS = "https://cas.docs.cisecurity.org/en/latest/source/"
_EXPOSURE = ("FW-DANGEROUS-SERVICES", "FW-ADMIN-UNTRUSTED")
_LIMITS = (
    "Только явно выбранная техническая часть и нормализованные условия сохранённой ревизии.",
    "Не оценены исполнение на устройстве, first-match, NAT, маршруты и сквозная достижимость.",
    "Не подтверждает выполнение контроля целиком, организационных процедур или сертификацию.",
    "Применимость, область и параметры утверждаются отдельным профилем организации.",
)


@dataclass(frozen=True)
class _Reference:
    identifier: str
    title: str
    part: str
    link: str
    checks: tuple[str, ...] = ()
    limits: tuple[str, ...] = ()


def _catalogue(
    identifier: str, edition: str, references: tuple[_Reference, ...]
) -> ControlCatalogue:
    return ControlCatalogue(
        catalogue_id=identifier,
        version=MAPPING_VERSION,
        controls=tuple(
            ControlDefinition(
                control_id=f"{identifier}:{item.identifier}",
                title=f"{item.identifier}: {item.title}",
                statement=item.part,
                limitations=(
                    *_LIMITS,
                    *item.limits,
                    f"Reference: {edition}; {item.identifier}; {item.link}; "
                    f"reviewed {REFERENCE_REVIEW_DATE}.",
                )
                + (() if item.checks else ("Нет автоматического технического сопоставления.",)),
            )
            for item in references
        ),
        mappings=tuple(
            CheckControlMapping(
                mapping_id=f"{identifier}:{item.identifier}:{check}",
                control_id=f"{identifier}:{item.identifier}",
                check_id=check,
                check_versions=("1.0.0", "1.1.0"),
                source=item.link,
                edition=edition,
                source_control_id=item.identifier,
                rationale=(
                    f"{check} даёт свидетельство только для указанной части; "
                    "это сопоставление Arxion, не утверждённый авторами стандарта crosswalk."
                ),
                covered_part=item.part,
                limits=(*_LIMITS, *item.limits),
            )
            for item in references
            for check in item.checks
        ),
    )


def nist_sp80041_catalogue() -> ControlCatalogue:
    """Reference selected sections, without inventing normative control numbers."""
    return _catalogue(
        REFERENCE_CATALOGUE_IDS[0],
        "NIST SP 800-41 Rev. 1 (2009)",
        (
            _Reference(
                "4.1",
                "Условия IP и сервисов",
                "Сверить заданные разрешения с явным профилем запрещённых сервисов и admin-сетей.",
                _NIST41 + "#page=28",
                _EXPOSURE,
                ("Наличие broad ALLOW само по себе не доказывает нарушение deny-by-default.",),
            ),
            _Reference(
                "5.2.3",
                "Параметр журналирования",
                "Проверить флаг logging только в области, где организация требует его для правил.",
                _NIST41 + "#page=39",
                ("FW-LOGGING",),
                ("Не проверены записи, доставка, хранение, alerts и выбор типов событий.",),
            ),
            _Reference(
                "5.3",
                "Проверка исполнения",
                "Нужны отдельные испытания firewall; декларации не подтверждают результат runtime.",
                _NIST41 + "#page=40",
            ),
        ),
    )


def nist_sp80053_catalogue() -> ControlCatalogue:
    """Pin the reviewed 2020 edition rather than silently adopting later releases."""
    return _catalogue(
        REFERENCE_CATALOGUE_IDS[1],
        "NIST SP 800-53 Rev. 5, updates 2020-12-10",
        (
            _Reference(
                "AC-4",
                "Часть ограничений потоков",
                "Сверить заданные разрешения с явным профилем запрещённых сервисов и admin-сетей.",
                _NIST53 + "#page=55",
                _EXPOSURE,
            ),
            _Reference(
                "SC-7",
                "Часть граничных условий",
                "Сверить заданные разрешения с явным профилем запрещённых сервисов и admin-сетей.",
                _NIST53 + "#page=324",
                _EXPOSURE,
                ("Привязки к реальной границе системы и архитектурная сегментация не доказаны.",),
            ),
            _Reference(
                "CM-7",
                "Часть ограничений сервисов",
                "Проверить заданное разрешение сервиса, запрещённого явным профилем организации.",
                _NIST53 + "#page=131",
                ("FW-DANGEROUS-SERVICES",),
                ("Не проверены установленные приложения, открытые sockets и отключение демонов.",),
            ),
            _Reference(
                "AU-12",
                "Часть настройки logging",
                "Проверить флаг logging только в области, где организация требует его для правил.",
                _NIST53 + "#page=105",
                ("FW-LOGGING",),
                ("Не доказаны генерация записей, их состав, доставка, хранение и корреляция.",),
            ),
            _Reference(
                "AU-2",
                "Организационный выбор событий",
                "Требуются решения о событиях и процедурах; проверка ACL их не подтверждает.",
                _NIST53 + "#page=93",
            ),
            _Reference(
                "SC-7(5)",
                "Полнота запрета по умолчанию",
                "Нужно подтверждение применённой политики целиком, а не отдельного broad правила.",
                _NIST53 + "#page=326",
            ),
        ),
    )


def cis_controls81_catalogue() -> ControlCatalogue:
    """CIS Controls references, deliberately separate from product-specific Benchmarks."""
    return _catalogue(
        REFERENCE_CATALOGUE_IDS[2],
        "CIS Controls Assessment Specification v8.1",
        (
            _Reference(
                "12.2",
                "Часть сетевых ограничений",
                "Сверить заданные разрешения с явным профилем запрещённых сервисов и admin-сетей.",
                _CIS + "Controls12/",
                _EXPOSURE,
                ("Архитектура, доступность, все сегменты и принадлежность ресурсов не оценены.",),
            ),
            _Reference(
                "13.4",
                "Часть заданных условий фильтрации",
                "Сверить заданные разрешения с явным профилем запрещённых сервисов и admin-сетей.",
                _CIS + "Controls13/",
                _EXPOSURE,
                ("Применение фильтра между реальными сегментами и весь путь не подтверждены.",),
            ),
            _Reference(
                "4.8",
                "Сигнал о нежелательном сервисе",
                "Проверить заданное разрешение сервиса, запрещённого явным профилем организации.",
                _CIS + "Controls4/",
                ("FW-DANGEROUS-SERVICES",),
                ("Вход для пересмотра; установка, удаление и отключение сервиса не проверены.",),
            ),
            _Reference(
                "8.2",
                "Часть настройки logging",
                "Проверить флаг logging только в области, где организация требует его для правил.",
                _CIS + "Controls8/",
                ("FW-LOGGING",),
                ("Не доказаны фактический сбор журналов, весь инвентарь и процесс организации.",),
            ),
            _Reference(
                "4.4",
                "Развёртывание защиты сервера",
                "Потребуются данные о развёрнутой защите сервера; деклараций ACL недостаточно.",
                _CIS + "Controls4/",
            ),
            _Reference(
                "8.1",
                "Организационный процесс журналирования",
                "Требуются отдельные свидетельства процесса и его пересмотра.",
                _CIS + "Controls8/",
            ),
            _Reference(
                "12.3",
                "Свойства управления инфраструктурой",
                "Нужны свидетельства защищённых административных сессий и управления изменениями.",
                _CIS + "Controls12/",
            ),
        ),
    )


def reference_control_catalogue(identifier: str) -> ControlCatalogue:
    """Select an explicit optional catalogue; never fall back to another edition."""
    factories = {
        REFERENCE_CATALOGUE_IDS[0]: nist_sp80041_catalogue,
        REFERENCE_CATALOGUE_IDS[1]: nist_sp80053_catalogue,
        REFERENCE_CATALOGUE_IDS[2]: cis_controls81_catalogue,
    }
    try:
        factory = factories[identifier]
    except KeyError:
        raise ValueError("Unsupported reference catalogue or edition") from None
    return factory()
