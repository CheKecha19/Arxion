# Командная строка

Команды ниже предназначены для подготовленного окружения исходников. Используется префикс:

```powershell
uv run firewall-compliance
```

Не следует считать приведённый CLI отдельным готовым Windows-дистрибутивом. Входные конфигурации, профили и выходные отчёты храните в разных файлах.

## Версия и анализ

### version

Выводит версию приложения:

```powershell
uv run firewall-compliance version
```

### analyze PATH

Читает одну конфигурацию и выводит результат Firewall Assurance в JSON в стандартный вывод.

Опции:

* `--require-logging / --no-require-logging` — требование журналирования; по умолчанию включено;
* `--require-comments / --no-require-comments` — требование комментариев; по умолчанию включено;
* `--management-profile FILE`;
* `--policy-exposure-profile FILE`;
* `--policy-scope-profile FILE`;
* `--extended-policy-checks`;
* `--complete-config` — явное подтверждение полноты экспорта;
* `--configuration-view unknown|local|effective|effective_detail|pending`, по умолчанию unknown;
* `--node-path TEXT`.

```powershell
uv run firewall-compliance analyze "C:\ArxionDemo\device.cfg"
```

Профили exposure/scope автоматически включают расширенные проверки. Не указывайте --complete-config только ради получения определённого ответа: это утверждение оператора о входных данных.

### analyze-bundle PATH --output FILE

Создаёт общий AnalysisResult, пригодный для последующего экспорта и дополнительных оценок:

```powershell
uv run firewall-compliance analyze-bundle "C:\ArxionDemo\device.cfg" -o "C:\ArxionDemo\analysis.json"
```

Поддерживает --extended-policy-checks, три опции профилей, --complete-config, переключатели журналирования и комментариев. В отличие от analyze, у этой команды нет параметров --configuration-view и --node-path.

### analysis-export PATH --output FILE

Экспортирует сохранённый AnalysisResult. `--format json|csv|html`, по умолчанию HTML.

```powershell
uv run firewall-compliance analysis-export "C:\ArxionDemo\analysis.json" -o "C:\ArxionDemo\analysis.html" --format html
```

**JSON команды analyze и общий результат команды analyze-bundle — разные форматы.** Для analysis-export, controls assess и governance assess используйте общий результат.

## Сбор конфигураций

### usergate-collect HOST OUTPUT

Опции: `--family 6|7` (по умолчанию 7), `--transport tcp|https` (tcp), `--username` (Admin), `--ca-file FILE`.

Пароль запрашивается скрытым вводом. Выходной файл не должен существовать. Результат — собственный JSON-снимок Arxion для обычного импорта.

### ideco-collect HOST OUTPUT

Опции: --username (admin), --port (8443), --ca-file FILE. Порт — 1–65535. Пароль вводится по запросу; существующий выходной файл не перезаписывается. Команда ориентирована на Ideco v23 классического VCE в поддержанном срезе.

## Структура устройств

### switch-inspect PATH

Каталог коммутатора. Опции: `--output/-o FILE`, `--format json|csv|html` (json), `--complete-config`.

```powershell
uv run firewall-compliance switch-inspect "C:\ArxionDemo\switch.cfg" -o "C:\ArxionDemo\switch.html" --format html
```

### controller-inspect PATH

Каталог ArubaOS Controller. Опции: `--output/-o FILE`, `--format json|csv|html` (json), `--complete-config`, `--configuration-view unknown|local|effective|effective_detail|pending`, `--node-path`.

### controller-role PATH

Обязательные опции: --role, --source, --destination.

Дополнительные: --protocol (tcp), --port, --source-port, --at-time, --user-ip, --local-ip, --user-roles FILE, --ap-group, --complete-config, --configuration-view, --node-path, --output/-o FILE. Диапазон портов — 0–65535. Время --at-time должно содержать часовой пояс.

```powershell
uv run firewall-compliance controller-role "C:\ArxionDemo\controller.cfg" --role employee --source 192.0.2.10 --destination 198.51.100.20 --protocol tcp --port 443
```

Имя роли в примере необходимо заменить существующим в конфигурации. Без достаточного контекста допустим результат «неизвестно».

## Карты ACL

### acl-map build PATH --output FILE

Создаёт JSON-карту из конфигурации. --revision-json переключает вход на сохранённую DeviceRevision.

```powershell
uv run firewall-compliance acl-map build "C:\ArxionDemo\device.cfg" -o "C:\ArxionDemo\map.json"
```

### acl-map batch PATHS... --output FILE

Создаёт пакет независимых карт, сохраняя отказы отдельных входов. Поддерживает --revision-json. Максимум 1000 входов.

```powershell
uv run firewall-compliance acl-map batch "C:\ArxionDemo\a.cfg" "C:\ArxionDemo\b.cfg" -o "C:\ArxionDemo\maps.json"
```

Наличие ошибок отдельных файлов приводит к ненулевому коду завершения, даже если остальные карты сохранены.

### acl-map export PATH --output FILE

`--format json|dot|html` (html). Для HTML доступны:

* \--source CIDR;
* \--destination CIDR;
* \--protocol;
* \--port;
* \--include-unknown / --exclude-unknown (неизвестные включены).

```powershell
uv run firewall-compliance acl-map export "C:\ArxionDemo\map.json" -o "C:\ArxionDemo\map.html" --format html --protocol tcp --port 443
```

JSON и DOT сохраняют полный снимок; сетевые фильтры с этими форматами отклоняются. Команда ожидает отдельную карту, а не пакет batch.

### acl-map save PATH --database FILE --project ID

Сохраняет карту в существующем проекте SQLite. Дополнительные --run ID, --item ID связывают её с запуском и элементом; связи проверяются по снимку.

### acl-map load DATABASE --project ID --map-id ID --output FILE

Читает сохранённую карту проекта в JSON без исходной конфигурации.

### acl-map list DATABASE --project ID

Выводит каталог сохранённых карт проекта в JSON.

## Технические контроли

### controls catalogue --output FILE

Сохраняет ограниченный внутренний каталог технических контролей:

```powershell
uv run firewall-compliance controls catalogue -o "C:\ArxionDemo\controls.json"
```

Каталог не содержит автоматически подтверждённых внешних сопоставлений NIST/CIS.

### controls profile-template --output FILE

Обязательные параметры: --organization, --scope-reference, --profile-id, повторяемый --control, --justification.

Дополнительные: --version (1), --applicable/--not-applicable (applicable).

Выбирайте реальные ID из выгруженного каталога. Команда создаёт профиль, но не утверждает его от имени организации.

### controls assess PATH --profile FILE --output FILE

Оценивает сохранённый AnalysisResult. Дополнительные --catalogue FILE, --assessed-at ISO\_DATETIME.

```powershell
uv run firewall-compliance controls assess "C:\ArxionDemo\analysis.json" --profile "C:\ArxionDemo\control-profile.json" -o "C:\ArxionDemo\control-assessment.json"
```

### controls export PATH --output FILE

Экспортирует сохранённую оценку контролей. `--format json|csv|html` (html). Использует исторические свидетельства, а не текущие настройки.

## Governance

### governance assess PATH --component ID --profile FILE --output FILE

Создаёт новый общий результат по метаданным и статистике правил точного компонента сохранённого AnalysisResult.

Дополнительные параметры:

* \--inputs FILE — дополнительные свидетельства;
* \--assessed-at ISO\_DATETIME;
* \--max-operations INTEGER — от 1 до 10 000 000, по умолчанию 100 000.

Команда не изменяет исходный bundle или конфигурацию. ID компонента берите из сохранённого результата. Профиль и свидетельства должны соответствовать его ревизии.

## Ошибки CLI

При ошибке входа, профиля, формата, области проекта или экспорта большинство команд возвращает код 2. Команды API-сбора возвращают код 1 при обработанной ошибке сбора или записи.

Нулевой код завершения анализа не означает отсутствия находок. Изучайте содержимое результата и его полноту.

Если команда не может прочитать JSON, проверьте не только синтаксис, но и тип документа: DeviceRevision, отдельная карта, пакет карт, Firewall Assurance, AnalysisResult и оценка контролей не взаимозаменяемы.

## Связанные разделы

* [Форматы и профили](formats-and-profiles.md)
* [Поддерживаемые платформы](supported-platforms.md)
* [Общее оглавление](../)
