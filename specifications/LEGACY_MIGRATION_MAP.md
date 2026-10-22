# Карта миграции исходного прототипа

## Принцип

Миграция выполняется вертикальными срезами. Код не копируется целиком: переносится поведение, затем оно упрощается и защищается тестами в новой архитектуре.

Таблица задаёт границы ответственности, а не обязательное разбиение каждого компонента на отдельный каталог. После ADR-005 первым выбран Cisco ASA; затем подключены ограниченные HP/Aruba и Comware adapters. Уже реализованные контракты отражены в CURRENT_STATE и REQUIREMENT_STATUS.

Порядок завершения переноса уточнён 11.10.2026 в [MIGRATION_COMPLETION_PLAN.md](MIGRATION_COMPLETION_PLAN.md): сначала логическая карта ACL и сценарии HP/Aruba, Comware и ASA, затем оставшиеся рабочие возможности, включая UserGate, Juniper и Huawei. Этапы внутренние; итоговая поставка — один Windows-релиз. Таблица ниже сохраняет архитектурные границы первоначального переноса; актуальная последовательность задана новым планом.

| Компонент исходного прототипа | Целевое место | Стратегия |
|---|---|---|
| `src/models/*` | `domain/` | Перепроектировать как канонические модели, добавить source mapping и состояния неполных данных |
| `src/parsers/base_parser.py` | `parsers/contracts.py` | Реализован нейтральный контракт с `ParseOutcome`; не переносить legacy API |
| `src/parsers/json_parser.py` | Будущий `parsers/usergate/` | Последующий этап общего переноса; подтверждённый формат и отдельный ADR обязательны |
| `src/parsers/acl_parser.py` | `parsers/<vendor>/` | Разделить по производителям; не переносить как единый универсальный файл |
| `src/core/resolver.py` | `analysis/resolution/` | Перенести с отдельными тестами вложенных групп и циклов |
| `src/core/analyzer.py` | `application/` и `analysis/` | Разделить orchestration, graph building и topology integration |
| `src/core/security_auditor.py` | `analysis/policy_checks.py`, последующие модули `analysis/` | Независимые checks возвращают `CheckResult` с findings и полнотой |
| `src/core/compliance_auditor.py` | `compliance/` | Перенести как каталог controls поверх общей модели findings |
| `src/core/config_diff.py` | `analysis/diff/` | Сначала определить стабильное сравнение нормализованных правил |
| `src/core/reachability_checker.py` | `analysis/reachability/` | Отложить до формализации маршрутизации, NAT и источников данных |
| `src/core/topology_builder.py` | `analysis/topology/` | Отложить после базовой модели Device/Interface/Route |
| `src/graph/visualizer.py` | `infrastructure/exporters/` | Не переносить до стабильного DTO результата анализа |
| `src/cli.py`, `main.py` | `interfaces/cli/`, `bootstrap/` | Переписать после готовности application services; убрать auto-install |

## Очерёдность первого вертикального среза

1. Канонические модели Rule, Endpoint, Service, ParseResult, Finding и Evidence.
2. Базовый parser contract и минимальные contract tests.
3. Один выбранный парсер и его расширенные fixtures.
4. Нормализация и source mapping.
5. Один check, например `any-any`, с evidence.
6. JSON-результат первого сценария. После Фазы 7 это FirewallAssuranceResult; общий AnalysisResult остаётся Фазой 9.

## Что сохраняется как поведенческий ориентир

- Число правил на трёх исходных fixtures.
- Поддержка структуры UserGate JSON и базовых ACL-кейсов.
- Возможность строить граф доступа как вторичный результат.
- Идеи существующих security checks, diff, topology и compliance controls.

## Что не переносится напрямую

- Auto-install зависимостей в момент запуска.
- Глобальное подавление warnings.
- HTML-логику, встроенную в доменный/анализаторный слой.
- Непрозрачную обработку исключений.
- Маркетинговые заявления README как контракт поведения.
