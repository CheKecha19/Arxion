# TASK-005: Первый parser adapter Cisco ASA

Приоритет: P0
Статус: Готово
Дата завершения: 2026-10-09

## Результат

- Quality gate ADR-005 закрыт тремя специально созданными обезличенными Cisco ASA 9.16 fixtures и `manifest.json` с SHA-256.
- Реализован in-memory parser adapter `CiscoAsaParser` для ограниченного textual `show running-config`.
- Поддерживаются extended `access-list` с `permit` и `deny`, `access-group`, IPv4 network/service objects, одноуровневые network/service object groups и `log`.
- NAT не теряется: он отображается как `UnsupportedConstruct` и warning `UNSUPPORTED_NAT`.
- Для всех трёх сценариев добавлены parser, registry integration и full golden tests с фиксированным временем.

## Границы

Это не заявление commercial production-support Cisco ASA. Не поддерживаются NAT-семантика, IPv6, time-range, identity/user rules, FQDN, вложенные object groups и маршрутизация. Для каждого такого расширения требуется fixture, parser-contract, coverage diagnostics и golden result.

## Проверка

```powershell
uv run ruff format --check src tests scripts
uv run ruff check src tests scripts
uv run mypy src
uv run pytest
```
