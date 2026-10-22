"""Синтетические данные для макета; анализ конфигураций здесь не выполняется."""

from dataclasses import dataclass
from typing import Literal

SeverityLabel = Literal["Критическая", "Высокая", "Средняя", "Низкая", "Информационная"]
RuleRow = tuple[str, str, int, str, str, str, str, str, str]


@dataclass(frozen=True)
class FindingView:
    """Находка для списка и панели доказательств в демонстрационном интерфейсе."""

    id: str
    device: str
    revision: str
    severity: SeverityLabel
    title: str
    rule: str
    source: str
    destination: str
    service: str
    explanation: str
    evidence: str
    limitation: str
    recommendation: str


@dataclass(frozen=True)
class DeviceView:
    """Снимок устройства; имя может повторяться для разных ревизий."""

    name: str
    platform: str
    revision: str
    observed_at: str
    completeness: str


@dataclass(frozen=True)
class DemoWorkspace:
    """Неизменяемый набор данных, независимый от моделей анализатора."""

    devices: tuple[DeviceView, ...]
    findings: tuple[FindingView, ...]
    rules: tuple[RuleRow, ...]


def load_demo_workspace() -> DemoWorkspace:
    """Вернуть вымышленный стенд из двух устройств и двух ревизий каждого."""
    devices = (
        DeviceView("ASA-HQ", "Cisco ASA 9.16", "B", "10.10.2026 · 09:40", "Полная"),
        DeviceView("ASA-HQ", "Cisco ASA 9.16", "A", "09.10.2026 · 18:15", "Полная"),
        DeviceView("ASA-BRANCH", "Cisco ASA 9.16", "B", "10.10.2026 · 09:25", "Частичная"),
        DeviceView("ASA-BRANCH", "Cisco ASA 9.16", "A", "08.10.2026 · 16:30", "Полная"),
    )
    findings = (
        FindingView(
            "FW-ANY-ANY-01",
            "ASA-HQ",
            "B",
            "Высокая",
            "Разрешён доступ any → any",
            "#90 · temporary-access",
            "any",
            "any",
            "ALL",
            "Активное правило разрешает любой источник, назначение и сервис "
            "в области INSIDE_IN / inside inbound. "
            "Избыточный доступ требует проверки назначения правила.",
            "asa-hq-B.cfg · строки 90–92\n"
            "access-list INSIDE_IN remark temporary-access\n"
            "access-list INSIDE_IN extended permit ip any any log\n"
            "access-group INSIDE_IN in interface inside",
            "Вывод относится к области INSIDE_IN / inside inbound. "
            "Фактическое прохождение трафика зависит "
            "от маршрутизации, NAT и предыдущих правил.",
            "Уточнить владельца временного доступа, ограничить адреса и сервисы, согласовать срок.",
        ),
        FindingView(
            "FW-LOGGING-01",
            "ASA-HQ",
            "B",
            "Средняя",
            "Не включено логирование",
            "#20 · users-to-web",
            "10.10.20.0/24",
            "172.16.20.0/24 · WEB_SERVERS",
            "HTTPS · TCP/443",
            "В активном разрешающем правиле отключена запись событий. "
            "Это затрудняет аудит обращений к внутреннему веб-сервису.",
            "asa-hq-B.cfg · строки 18–21, 40–41\n"
            "object network WEB_SERVERS\n    subnet 172.16.20.0 255.255.255.0\n"
            "access-list INSIDE_IN remark users-to-web\n"
            "access-list INSIDE_IN extended permit tcp 10.10.20.0 255.255.255.0 "
            "object WEB_SERVERS eq 443 log disable",
            "Проверка использует демонстрационное требование логировать разрешающий доступ. "
            "Наличие журналов в других системах не оценивалось.",
            "Включить логирование с учётом объёма событий и принятой политики аудита.",
        ),
        FindingView(
            "FW-DUPLICATE-01",
            "ASA-HQ",
            "B",
            "Средняя",
            "Дублирующее правило",
            "#31 · dns-copy",
            "10.10.20.0/24",
            "10.10.1.53",
            "DNS · UDP/53",
            "Правила #30 и #31 имеют одинаковые условия, действие и настройку логирования "
            "в одной области. Второе правило повторяет первое.",
            "asa-hq-B.cfg · строки 44–47\n"
            "access-list INSIDE_IN remark users-dns\n"
            "access-list INSIDE_IN extended permit udp 10.10.20.0 255.255.255.0 "
            "host 10.10.1.53 eq 53 log\n"
            "access-list INSIDE_IN remark dns-copy\n"
            "access-list INSIDE_IN extended permit udp 10.10.20.0 255.255.255.0 "
            "host 10.10.1.53 eq 53 log",
            "Сопоставление выполнено для полностью разобранной области с порядком first-match. "
            "Число срабатываний правил не загружено.",
            "Сверить владельцев и назначение правил перед удалением дубликата.",
        ),
        FindingView(
            "FW-SHADOWED-01",
            "ASA-HQ",
            "B",
            "Средняя",
            "Правило затенено предыдущим",
            "#41 · app-admin",
            "10.10.20.15",
            "172.16.20.10",
            "SSH · TCP/22",
            "Условия правила #41 полностью входят в условия более раннего правила #40. "
            "При обработке first-match трафик завершает проверку на #40 с запретом.",
            "asa-hq-B.cfg · строки 50–53\n"
            "access-list INSIDE_IN remark deny-users-to-app\n"
            "access-list INSIDE_IN extended deny ip 10.10.20.0 255.255.255.0 "
            "object WEB_SERVERS log\n"
            "access-list INSIDE_IN remark app-admin\n"
            "access-list INSIDE_IN extended permit tcp host 10.10.20.15 "
            "host 172.16.20.10 eq 22 log",
            "Доказательство относится к области INSIDE_IN / inside inbound и текущей ревизии.",
            "Проверить необходимость исключения для администратора и согласовать порядок правил.",
        ),
        FindingView(
            "FW-COMMENTS-01",
            "ASA-BRANCH",
            "B",
            "Низкая",
            "Не описано назначение доступа",
            "#12 · branch-to-erp",
            "10.20.10.0/24",
            "172.16.30.10",
            "HTTPS · TCP/443",
            "Активное правило не содержит описания назначения. "
            "Из конфигурации нельзя определить владельца и основание доступа.",
            "asa-branch-B.cfg · строка 52\n"
            "access-list INSIDE_IN extended permit tcp 10.20.10.0 255.255.255.0 "
            "host 172.16.30.10 eq 443\nПеред правилом отсутствует remark.",
            "Демонстрация частичного разбора: некоторые строки экспорта не распознаны. "
            "Наличие описания во внешнем реестре не проверялось.",
            "Добавить назначение, владельца сервиса и ссылку на согласование доступа.",
        ),
        FindingView(
            "FW-DISABLED-01",
            "ASA-HQ",
            "B",
            "Низкая",
            "Отключённое правило требует ревизии",
            "#70 · legacy-backup",
            "10.10.40.12",
            "172.16.40.50",
            "TCP/9102",
            "В конфигурации сохранено отключённое правило старого резервного копирования. "
            "Это инвентаризационная находка; правило не создаёт текущий разрешённый доступ.",
            "asa-hq-B.cfg · строки 70–71\n"
            "access-list INSIDE_IN remark legacy-backup\n"
            "access-list INSIDE_IN extended permit tcp host 10.10.40.12 "
            "host 172.16.40.50 eq 9102 log inactive",
            "Дата отключения и владелец отсутствуют в экспорте. "
            "Низкая важность в макете соответствует информационной находке анализатора.",
            "Уточнить причину отключения и необходимость сохранения правила.",
        ),
        FindingView(
            "FW-MERGE-CANDIDATE-01",
            "ASA-HQ",
            "B",
            "Низкая",
            "Два правила можно объединить",
            "#50, #51 · monitoring",
            "10.10.50.10",
            "172.16.10.20, 172.16.10.21",
            "ICMP",
            "Соседние правила #50 и #51 имеют одинаковые источники, сервис, действие "
            "и логирование; отличаются только адресом назначения.",
            "asa-hq-B.cfg · строки 58–61\n"
            "access-list INSIDE_IN remark monitoring-web-01\n"
            "access-list INSIDE_IN extended permit icmp host 10.10.50.10 "
            "host 172.16.10.20 log\n"
            "access-list INSIDE_IN remark monitoring-web-02\n"
            "access-list INSIDE_IN extended permit icmp host 10.10.50.10 "
            "host 172.16.10.21 log",
            "Предложение не учитывает раздельных владельцев и требования к индивидуальному аудиту.",
            "Проверить бизнес-назначение и при согласовании объединить назначения в группу.",
        ),
        FindingView(
            "FW-ANY-ANY-02",
            "ASA-HQ",
            "A",
            "Высокая",
            "Разрешён доступ any → any",
            "#90 · temporary-access",
            "any",
            "any",
            "ALL",
            "В предыдущей ревизии также присутствовал широкий временный доступ "
            "INSIDE_IN / inside inbound.",
            "asa-hq-A.cfg · строки 88–90\n"
            "access-list INSIDE_IN remark temporary-access\n"
            "access-list INSIDE_IN extended permit ip any any log\n"
            "access-group INSIDE_IN in interface inside",
            "Историческая находка описывает сохранённый снимок, а не текущее состояние устройства.",
            "Сравнить с актуальной ревизией и проверить срок действия временного доступа.",
        ),
    )
    hq_rules: tuple[tuple[int, str, str, str, str, str, str], ...] = (
        (10, "admin-to-fw", "10.10.99.10", "10.10.1.1", "SSH", "Разрешить", "Включено"),
        (
            20,
            "users-to-web",
            "10.10.20.0/24",
            "172.16.20.0/24 · WEB_SERVERS",
            "HTTPS",
            "Разрешить",
            "Выключено",
        ),
        (30, "users-dns", "10.10.20.0/24", "10.10.1.53", "DNS", "Разрешить", "Включено"),
        (31, "dns-copy", "10.10.20.0/24", "10.10.1.53", "DNS", "Разрешить", "Включено"),
        (
            40,
            "deny-users-to-app",
            "10.10.20.0/24",
            "172.16.20.0/24",
            "ALL",
            "Запретить",
            "Включено",
        ),
        (41, "app-admin", "10.10.20.15", "172.16.20.10", "SSH", "Разрешить", "Включено"),
        (50, "monitoring-web-01", "10.10.50.10", "172.16.10.20", "ICMP", "Разрешить", "Включено"),
        (51, "monitoring-web-02", "10.10.50.10", "172.16.10.21", "ICMP", "Разрешить", "Включено"),
        (70, "legacy-backup", "10.10.40.12", "172.16.40.50", "TCP/9102", "Отключено", "Включено"),
        (90, "temporary-access", "any", "any", "ALL", "Разрешить", "Включено"),
        (100, "deny-all", "any", "any", "ALL", "Запретить", "Включено"),
    )
    branch_rules: tuple[tuple[int, str, str, str, str, str, str], ...] = (
        (5, "branch-dns", "10.20.10.0/24", "10.10.1.53", "DNS", "Разрешить", "Включено"),
        (12, "branch-to-erp", "10.20.10.0/24", "172.16.30.10", "HTTPS", "Разрешить", "Включено"),
        (20, "branch-monitoring", "10.10.50.10", "10.20.1.1", "ICMP", "Разрешить", "Включено"),
        (100, "deny-all", "any", "any", "ALL", "Запретить", "Включено"),
    )
    rules: tuple[RuleRow, ...] = tuple(
        (
            device.name,
            device.revision,
            row[0],
            row[1],
            row[2],
            "172.16.20.10/32 · WEB_SERVERS"
            if device.name == "ASA-HQ" and device.revision == "A" and row[0] in {20, 40}
            else row[3],
            row[4],
            row[5],
            row[6],
        )
        for device in devices
        for row in (hq_rules if device.name == "ASA-HQ" else branch_rules)
        if not (device.revision == "A" and row[0] == 31)
    )
    return DemoWorkspace(devices=devices, findings=findings, rules=rules)
