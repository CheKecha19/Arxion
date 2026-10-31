# CHECKS-010/011: явные метаданные и статистика правил

Этот документ описывает чистые domain/analysis контракты и локальный CLI workflow
сохранённой ревизии. Qt-ввод и коллекторы требуют отдельной интеграции.
Автоматического вывода владельца из комментария или использования
правила из отсутствующего счётчика нет. Данные и примеры только синтетические.

## Профиль и входы

`domain/policy_governance.py`:

- `PolicyGovernanceProfile`: schema `1.0.0`, `profile_id`, `version`.
- `PolicyGovernanceInputs`: schema `1.0.0`, `input_id`, точный `revision_id`,
  коллекции `metadata` и `statistics`.
- `RuleGovernanceMetadata`: явная запись владельца, основания и дат.
- `RuleObservationStatistics`: явная запись статистического наблюдения.

Профиль сохраняется через `model_dump(mode="json")`/`model_dump_json()`,
восстанавливается через `model_validate()`/`model_validate_json()`. Неизвестная
версия и дополнительные поля отвергаются. Boolean-поля и целые счётчики строгие:
строка `"true"` или boolean вместо числа не принимаются.

Каждая запись доказательств содержит `evidence_id`, `revision_id`, `rule_id`,
`observed_at`, непустой `reference` и `SourceLocation`. Все даты требуют timezone.
Input документ допускает максимум 4096 записей каждой коллекции, уникальные
evidence IDs и не более одной записи каждого типа на правило. Ссылки на другую
ревизию отвергаются моделью; другой `revision_id` относительно текущего контекста
даёт `GOVERNANCE_REVISION_MISMATCH`. Неизвестный rule ID даёт
`ORPHAN_RULE_EVIDENCE`, сопоставление по имени не выполняется.

Вход не меняет `Rule`, parser output или существующую SQLite схему. Сбор данных
остаётся обязанностью вызывающего приложения/оператора. `reference` и
`SourceLocation` описывают происхождение утверждений; проверка не подтверждает
их истинность обращением к устройству.

### Параметры профиля

| Поле | Смысл |
| --- | --- |
| `lifecycle_enabled` | Включение требований к жизненному циклу |
| `require_owner` | Обязателен явный владелец |
| `require_justification` | Обязательно явное основание |
| `require_temporary_expiry` | Временное разрешение требует срока действия |
| `require_review_date` | Обязательны дата пересмотра и контроль её наступления |
| `include_disabled_rules` | Включать disabled правила; по умолчанию false |
| `unused_enabled` | Включение поиска кандидатов по статистике |
| `unused_min_observation_seconds` | Минимальная длительность наблюдения, 1–315360000 |
| `unused_max_age_seconds` | Максимальный возраст конца наблюдения, 0–315360000 |

`None` означает неизвестное требование, не разрешение и не отключение.
`lifecycle_enabled=false` или `unused_enabled=false` даёт `not_applicable`.
Включённый lifecycle с четырьмя явно false требованиями также неприменим.
Неизвестный отдельный lifecycle параметр сохраняет partial результат: другие
завершённые проверки могут дать подтверждённую находку. Для статистики нужны
явно заданные minimum period и maximum age; универсальное число дней не встроено.

## Паспорт FW-RULE-GOVERNANCE, версия 1.0.0

1. **Утверждение.** Явные метаданные сохранённого правила нарушают заданное
   требование владельца/основания, срока временного разрешения или пересмотра.
   Это качество и жизненный цикл политики, не доказательство уязвимости.
2. **Платформы и полнота.** Чистая нормализованная `DeviceRevision`, точные
   ID правил и операторские/собранные метаданные. Парсер сам по себе не создаёт
   этих метаданных и не доказывает поддержку каждой версии оборудования.
   Неполный parse отражается как `INCOMPLETE_PARSE`; известные нарушения
   существующих правил могут сохраниться. Исчезновение правила не утверждается.
3. **Параметры.** Lifecycle поля профиля выше. По умолчанию область — active
   правила независимо от разрешающего/запрещающего действия. Disabled включаются
   только явным profile flag.
4. **Исходы.** Пустой `owner`/`justification` означает подтверждённое отсутствие,
   `None` означает неизвестность. Последняя даёт `RULE_METADATA_UNKNOWN`, а не
   finding об отсутствии. Поле `temporary` строго true/false/unknown.
   `expiry_status` и `review_status` имеют значения `known`, `absent`, `unknown`:
   `known` требует дату, остальные запрещают её. У временного правила known дата
   `expires_at <= context.analyzed_at` даёт `TEMPORARY_PERMISSION_EXPIRED`,
   absent — `MISSING_TEMPORARY_EXPIRY`. Для явно постоянного правила срок
   не требуется. `review_at <= analyzed_at` даёт `REVIEW_OVERDUE`, явное отсутствие
   требуемой даты — `MISSING_REVIEW_DATE`. Будущие metadata observations дают
   `FUTURE_EVIDENCE`. При неизвестных требованиях/входах результат partial;
   если ни одно требование нельзя оценить, добавляется `CHECK_NOT_EXECUTED`.
5. **Риск и рекомендация.** `medium`: организационные требования не выполнены.
   Проверить владельца, назначение и исключения, согласовать решение. Истёкший
   срок не является доказательством безопасности удаления правила.
6. **Доказательства.** Ревизия/конфигурация/device/rule, source locations правила
   и metadata record, исходное нормализованное правило, точная запись evidence,
   `evaluated_at`, список нарушения, profile/input/evidence IDs и SHA-256.
   Witness здесь — конкретное поле и дата записи на дату оценки, не сетевой поток.
7. **Тесты.** `tests/regression/test_policy_governance.py`: отсутствие против unknown,
   permanent/temporary, граница равенства дат, future evidence, выключение,
   исключение disabled, wrong revision/rule ID, частичные требования, JSON replay,
   source mapping, profile changes и независимый конечный oracle дат.
   IPv4/IPv6 не влияют на метаданные и не используются как основание вывода.
8. **Повторяемость и пределы.** Явный `context.analyzed_at`, глубокий snapshot
   профиля/входов, детерминированный finding UUID по ревизии/check/profile/record
   и нарушениям. Изменённый профиль не маскируется старой находкой. Бюджет
   `max_operations` по умолчанию 100000, допустимо 1–10000000. Исчерпание даёт
   `GOVERNANCE_LIMIT_REACHED`; ранее завершённые findings сохраняются.

## Паспорт FW-UNUSED-CANDIDATE, версия 1.0.0

1. **Утверждение.** Нулевой счётчик за квалифицированное наблюдение позволяет
   рекомендовать ручной пересмотр правила как кандидата в неиспользуемые.
   Неиспользование за всё время и ненужность правила не утверждаются.
2. **Платформы и полнота.** Нужна статистика, привязанная к точной ревизии/rule ID,
   подтверждённый стабильный policy window и охват. Поддержка парсинга ACL
   не означает наличие collector/runtime statistics. Схема vendor-neutral,
   конкретный коллектор и его версии здесь не реализованы.
3. **Параметры.** Явные min observation и max age из профиля. Нельзя ослабить
   требования zero resets/complete coverage посредством скрытого default.
4. **Исходы.** Finding требует одновременно `hits=0`, `count_kind=window_delta`,
   `coverage=complete`, `counter_resets=0`, `revision_stable=true`, известные
   `window_start/end`, достаточную длительность и допустимый возраст конца
   window. Все значения наблюдены не позже `analyzed_at`; observation не может
   предшествовать концу window. Ровно minimum duration и maximum age допустимы.
   Положительные hits с теми же доказательствами дают завершённый результат
   без кандидата. `cumulative_sample`, неизвестные hits/сбросы/stability,
   partial coverage, короткий/старый/неизвестный window дают partial, без finding.
   Коды: `UNPROVEN_WINDOW_COUNTER`, `INCOMPLETE_OBSERVATION`,
   `COUNTER_RESET_UNKNOWN_OR_PRESENT`, `UNSTABLE_POLICY_WINDOW`,
   `OBSERVATION_WINDOW_UNKNOWN`, `OBSERVATION_WINDOW_TOO_SHORT`,
   `OBSERVATION_TOO_OLD`. Один нулевой snapshot недостаточен.
5. **Риск.** `low`: кандидат для проверки качества/необходимости политики.
   Учитывать аварийные/редкие/резервные сценарии; автоматическое удаление
   и универсальная команда отключения запрещены рекомендацией результата.
6. **Доказательства.** Полный статистический record, его происхождение, window,
   счётчик и квалифицирующие признаки, точное правило, дата оценки, ссылки и
   fingerprints профиля/входа/record. Связь с сетевой достижимостью не выводится.
7. **Тесты.** Каждый обязательный статистический gate проверен отрицательным
   примером; положительный zero-hit кандидат, positive-hit допустимый случай,
   равенство порогов, wrong IDs, strict integers, сбросы, unknown, JSON replay,
   snapshots и бюджеты. Счётчики синтетические; оборудование не опрашивается.
8. **Повторяемость/пределы.** Те же snapshot и bounded execution, что lifecycle.
   Fingerprint относится к сохранённым фактам, а не к неподтверждённому значению
   из комментария. Пустой результат после лимита не становится complete.

## Application seams

```python
checks = (
    RuleGovernanceCheck(governance_profile, governance_inputs),
    UnusedRuleCandidatesCheck(governance_profile, governance_inputs),
)
report = analyze_firewall(revision, analyzed_at=explicit_time, checks=checks)
```

Обе проверки принимают существующий `PolicyCheckContext` и возвращают
существующий `CheckResult`. Они не выполняют файловый/сетевой I/O, не меняют
ревизию, не читают текущее время и не включаются сами в legacy seven.
Вызывающий слой должен сохранять именно profile + inputs + evaluation time
для replay, показывать ограничения и отдельно реализовать ввод/загрузку
доказательств. Отсутствующие collector данные нельзя заменять пустым полем
с подтверждённым отсутствием или нулевым счётчиком.

## Проверка сохранённого результата

`application/governance_workflow.py:assess_governance(source, component_id,
profile, inputs=None, *, assessed_at, max_operations=100000)` принимает готовый
`AnalysisResult` и явно выбранный policy component. Inputs обязаны ссылаться
именно на его revision UUID. Нельзя сначала создать evidence для одной ревизии,
а затем повторно разобрать исходный файл с новым случайным UUID и привязать
записи по похожему имени.

Функция создаёт новый analysis UUID и добавляет отдельный component
`governance:<UUID>` только с двумя governance checks. Первоначальные компоненты,
их check versions, findings, source snapshots и decisions с исходными датами
сохраняются. Существующие policy checks не запускаются повторно ради этого
этапа. Повторная governance-оценка добавляет ещё один отдельный этап: одинаковое
нарушение может снова присутствовать под другим component ID, сохраняя историю
оценок, а не подменяя предыдущую оценку.
Дата оценки должна иметь timezone и не предшествовать завершению исходного
bundle или сохранённым решениям. Интервал общего результата сохраняет исходное
начало и заканчивается датой нового этапа. Исходный объект не меняется.

```text
firewall-compliance analyze-bundle synthetic.cfg --output captured.json
firewall-compliance governance assess captured.json --component policy --profile governance.json --inputs evidence.json --assessed-at 2026-10-28T12:00:00+03:00 --output assessed.json
firewall-compliance analysis-export assessed.json --format html --output assessed.html
```

В `evidence.json` используются revision/rule IDs из `captured.json`; профиль
не выводится автоматически из найденных правил. Без `--inputs` новый этап
получает truthful partial/unknown, не использует evidence предыдущего этапа
скрыто и не сообщает «нарушений нет». `--assessed-at` можно опустить для
осознанной оценки на текущую дату; сохранённый результат фиксирует это время.
Все входные JSON ограничены 64 МиБ и UTF-8/UTF-8 BOM. Output должен отличаться
от bundle/profile/evidence, включая symlink/hardlink aliases. Ошибки чтения,
валидации, даты и записи дают безопасное сообщение без содержимого конфигурации.

`test_governance_workflow.py` проверяет сохранение смешанного policy/network
bundle и решений, новый этап без старых finding duplicates, неизменность
legacy options JSON, source-independent JSON/CSV/HTML, две неизменяемые записи
в ProjectStore, реальный CLI и защиту входных файлов/кодировок/размеров.

## Qt-проект

Во вкладке «Отчёты → Метаданные правил» выбирается сохранённый общий результат
и его policy-компонент. Профиль и документ метаданных/статистики загружаются явно
из JSON; UUID ревизии должен совпадать с выбранным снимком. Можно очистить
документ evidence: отсутствие данных даст unknown/ограничения, а не вымышленные
владельцы или нулевые счётчики. Профиль не выводится из комментариев правила.

Оценка сохраняет новый AnalysisResult с дополнительным governance-этапом.
Прежние проверки и даты решений не изменяются. Новый результат доступен в
общей истории проекта и после перезапуска; экспорты используют сохранённый
снимок. Длительные операции выполняются в worker с проектным контекстом,
отменой устаревшей доставки и shutdown при закрытии окна.

Историческая запись приёмки 28.10.2026: MainWindow wiring добавлялся после
промежуточной сборки, 18 отдельных Qt-тестов проходили, совместный teardown
диагностировался. Эта запись не характеризует текущую сборку. В текущих исходниках
вкладка подключена; актуальные результаты проверок следует смотреть в CI,
а сведения о поставке — в WINDOWS_DISTRIBUTION.md и harness/build-log.md.
