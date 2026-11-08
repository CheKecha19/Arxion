# Контракт логической карты ACL

Дополнение 08.11.2026: назначение новых switch-записей показывается отдельно
(transit/management/unbound/unknown). Карта сохраняет режим declared_rules;
новая карта настроенной структуры коммутаторов отделена от ACL-карты и не
является доказательством сквозной доступности. Требования — SWITCH_CONFIG_IMPORT.md.

Базовый контракт: 2026-10-11, ADR-020. Сверка: 31.10.2026.
Фильтры, SQLite, CLI и Qt описаны в [ACL_MAP_WORKFLOW.md](ACL_MAP_WORKFLOW.md).

## Назначение

Карта показывает условия, заданные разобранными правилами. Она не вычисляет
эффективные разрешения first-match ACL и не доказывает сквозную достижимость.
Первый проверяемый набор: HP/Aruba AOS-Switch, AOS-CX и Comware. Развитие Cisco
отложено; существующие adapters и регрессии сохраняются.

## API

```python
from datetime import UTC, datetime

from firewall_compliance.analysis.acl_map import build_acl_map, select_acl_relations
from firewall_compliance.application.acl_map import export_acl_map_dot, export_acl_map_json
from firewall_compliance.domain.acl_map import AclMap
from firewall_compliance.domain.enums import RuleAction

# revision — DeviceRevision из готовой AnalysisSession или сохранённого снимка.
graph = build_acl_map(revision, built_at=datetime.now(UTC))
denies = select_acl_relations(graph, action=RuleAction.DENY, enabled=True)
payload = export_acl_map_json(graph)
restored = AclMap.model_validate_json(payload)
dot = export_acl_map_dot(restored)
```

В desktop вход доступен как `AnalysisSession.revision`; повторное чтение исходника
не требуется. Построение следует выполнять в worker, не внутри обработки отрисовки.
Модули `domain`, `analysis` и `application` не импортируют Qt.

## Данные

- `schema_version=1.0.0`, `analyzer_version=0.1.0`, `mode=declared_rules`.
- `revision`: независимый глубокий неизменяемый нормализованный снимок с UUID,
  устройством, SHA-256 источников, parser version, diagnostics и coverage.
- `built_at`: время с часовым поясом, не раньше импорта.
- `nodes`: endpoint/service с полными значениями либо явный unknown placeholder.
- `relations`: одна связь на правило с полным `Rule`, наборами идентификаторов
  источников, назначений и сервисов, `condition_status` known/unknown/unsupported.
- `limitations`: обязательные ограничения, сериализуемые в JSON.

Rule хранит действие, enabled, policy_id/direction/semantics, sequence, зоны,
logging, описание и SourceLocation. Action и полнота условий независимы:
`allow` вместе с `unsupported` не становится подтверждённым разрешением.
Исходный порядок tuple правил сохраняется; карта не пытается исправить или
интерпретировать неподтверждённый порядок применения.

Вершины не объединяются по имени. Идентификаторы зависят от UUID ревизии,
policy/direction/zones и полного значения объекта. Это идентичность внутри карты,
не ключ для сравнения разных ревизий. Если policy_id неизвестен, объекты разных
правил не объединяются: общая область не доказана. Одно правило с несколькими наборами объектов
остаётся одной связью: не создаются все комбинации source × destination × service.
UI может отрисовывать правило как промежуточную вершину.

Неизвестный объект не подменяется `any`. Пустое поле получает отдельную unknown
вершину. Статусы исходных полей сохраняются в Rule; условие `known` определяется
общим строгим matcher, а не наличием непустой подписи.

## Чтение и экспорт

JSON содержит нормализованный снимок и ограниченные source excerpts, но не сырые
документы. Это чувствительные данные, к ним применяются правила хранения проекта.
При чтении повторно валидируется ревизия и заново вычисляется проекция: изменённые
связи, действия, вершины или ограничения без согласованного входа отвергаются.
Это проверка согласованности, не криптографическая подпись подлинности результата.

DOT показывает source/service → rule → destination, action, enabled и полноту
условий. Подписи экранируются; атрибуты URL, HTML и исполняемые вставки не берутся
из источника. Для получения текста DOT Graphviz не нужен. JSON хранит подробные
диагностику и provenance; DOT не заменяет полный отчёт.

Фильтр возвращает tuple связей и не изменяет исходную карту. Он не является новым
результатом с заявлением о полном охвате. В первоначальный backend-срез не входили
SQLite, CLI, Qt и HTML/PNG. Они реализованы следующим этапом вместе с сетевыми
фильтрами и пакетным запуском; актуальный workflow приведён по ссылке выше.
Наличие этих функций не подтверждает нагрузочную приёмку 80 файлов или вычисление
эффективных разрешений. Общие графовые операции NetworkX этим контрактом не обещаны.
