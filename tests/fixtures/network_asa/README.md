# Синтетические сетевые входы Cisco ASA

Созданы для TASK-008, шага 8.0, 2026-10-10. Это собственные примеры проекта, не клиентские конфигурации и не скопированные транскрипты. Нет учётных данных, реальных устройств, серийных номеров или эксплуатационных наблюдений. Адреса вымышленные: private 10.0.0.0/8 и TEST-NET 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.

Формат: тела CLI-разделов/выдержок Cisco ASA 9.16 по документации. Конкретная сборка 9.16(x), устройство и эмулятор не проверялись. observed_at=null; дата создания не является временем состояния устройства.

Официальные источники, команды и ограничения приведены в [NETWORK_INPUTS](../../../specifications/NETWORK_INPUTS.md). Конфигурационный Null0 документирован; точное представление Null0 в RIB не установлено и не выдумано.

## Сценарии

| Каталог | Файлы | Назначение |
|---|---|---|
| connected_static_default | interfaces.cfg, static_routes.cfg, show_route.txt | Два интерфейса /24, строки C, static /24 и default; установка показана только выдержкой RIB, не конфигурацией |
| narrower_null0 | interfaces.cfg, static_routes.cfg | /24, более узкий /26 и Null0 /28; RIB отсутствует, установленный маршрут неизвестен |
| partial_unsupported | interfaces.cfg, static_routes.cfg, show_route.txt | Выбранный DHCP интерфейс, route track 6 без SLA/state, RIB оборвана после via; неизвестность не скрывается |

В narrower_null0 адреса 203.0.113.70, 203.0.113.100 и 203.0.113.10 демонстрируют попадание в /26, Null0 /28 и /24 соответственно. Это примеры настроенного намерения, не исполненные проверки установленной маршрутизации.

## Границы текста

Файлы cfg являются телами отдельных разделов, не полными конфигурациями и не сценариями развёртывания. txt - выдержки show route. Команды не запускались. Последняя строка partial_unsupported намеренно повреждена, а не является поддержанным синтаксисом.

manifest.json - метаданные проекта, не Cisco JSON export. Роль, команда, selection и extent не добавляются в payload. Во всех источниках complete=false, extent=excerpt либо truncated. Нет подтверждения общей полноты, синхронного получения, NAT, ACL или operational state.

## Контроль байтов

Восемь payloads имеют ASCII/UTF-8 без BOM, LF и завершающий LF. SHA-256 и byte_length в [manifest](manifest.json) относятся к точным байтам, без нормализации. README и manifest не являются входными payloads; manifest не хеширует сам себя.

```powershell
$root = (Resolve-Path 'tests/fixtures/network_asa').Path
$manifest = Get-Content -LiteralPath "$root/manifest.json" -Raw | ConvertFrom-Json
foreach ($scenario in $manifest.scenarios) {
    foreach ($source in $scenario.sources) {
        $path = Join-Path $root $source.path
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $source.sha256) {
            throw "Несовпадение SHA-256: $path"
        }
        if ((Get-Item -LiteralPath $path).Length -ne $source.byte_length) {
            throw "Несовпадение длины: $path"
        }
    }
}
```

Контроль целостности выполняется также автоматическим тестом. Во входном срезе 8.2 отдельный сетевой adapter проверяется на этих неизменных выдержках: результаты остаются неполными. Три новых golden results используют специально созданные synthetic документы из tests/network_import_fixtures.py, а не аппаратные экспорты. Коммерческая поддержка этими fixtures не подтверждается.
