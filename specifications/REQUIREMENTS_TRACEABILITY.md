# Сопоставление архитектурных требований и требований безопасности

Область: текущий локальный Arxion, ветка release/v0.3 и подготовка v0.4.
Это карта требований и доказательств, а не сертификат соответствия.
Внешний обязательный документ заказчика в репозитории не представлен.
Его требования нельзя заменять предположениями или считать выполненными.
Пользователь 27.10.2026 явно выбрал внутренний baseline для текущего этапа.

## Архитектурный baseline

| ID | Требование | Спецификация | Проверяемая реализация / доказательство | Остаток |
|---|---|---|---|---|
| A-01 | Домен независим от адаптеров и UI | [ARCHITECTURE](ARCHITECTURE.md) | harness/project_graph.py architecture; domain/** | Статический граф не доказывает все динамические зависимости |
| A-02 | Анализ без файлового и сетевого I/O | [ARCHITECTURE](ARCHITECTURE.md), [DEVELOPMENT_RULES](DEVELOPMENT_RULES.md) | analysis/**, application orchestration, synthetic engine tests | Новые движки проверять отдельно |
| A-03 | Вендорские форматы преобразуются в общие контракты | [DOMAIN_MODEL](DOMAIN_MODEL.md), [SUPPORTED_PLATFORMS](SUPPORTED_PLATFORMS.md) | parsers/catalog.py, ParseResult, DeviceRevision | Ограничения каждого адаптера сохраняются; ArubaOS controller открыт |
| A-04 | Версионированные данные и чтение прежних результатов | [SCHEMA_MIGRATIONS](SCHEMA_MIGRATIONS.md) | domain snapshots, ProjectStore, additive registry; reopen/backup tests | Общий AnalysisResult и миграция организационного workspace ещё открыты |
| A-05 | Unknown и неполнота не становятся разрешением либо удалением | [SPECIFICATION_REVIEW](SPECIFICATION_REVIEW.md), [TASK-008](TASK-008_NETWORK_ASSURANCE.md) | domain data statuses; check limitations; synthetic VMware tests | SR-005 в работе; сквозная достижимость ещё не реализована |
| A-06 | Сведения источника сопровождают вывод | [DOMAIN_MODEL](DOMAIN_MODEL.md), [CLOUD_RU_VMWARE](CLOUD_RU_VMWARE.md) | Finding/Evidence, source_map, cloud_origin и JSON pointers | Общие отчёты и хранение всех видов анализа открыты |
| A-07 | UI выполняет длительные операции через worker и сохраняет проектный контекст | [DESKTOP_UI](DESKTOP_UI.md) | JobRunner, CloudPanel; project-switch/cancellation regressions | Нагрузочная и clean-OS матрицы не завершены |
| A-08 | Ручные сведения не подменяют факты импорта | [PRODUCT_BACKLOG](PRODUCT_BACKLOG.md), [DOMAIN_MODEL](DOMAIN_MODEL.md) | resource_registry observed/metadata; explicit link; audit; archive tests | Ручные подписи не доказывают топологию и физическое размещение провайдера |

## Временный baseline безопасности

Ниже используются требования [SECURITY_BASELINE](SECURITY_BASELINE.md).
Идентификаторы S-* служат этой матрице и не выданы за номера внешнего стандарта.

| ID | Требование | Реализация / проверка | Статус и ограничения |
|---|---|---|---|
| S-01 | Чувствительные конфигурации и ключи не попадают в Git, fixtures и логи | Synthetic-only tests; source/secret separation; config snapshots | Не является утверждением о проведённом полном secret scan |
| S-02 | Обработка локальна по умолчанию; сеть настраивается явно | FileSourceReader; CloudPanel explicit configured connection/scan | Внешние collectors/scheduler ещё не реализованы |
| S-03 | API-секрет отделён от инвентаря, истории и экспорта | Windows DPAPI; windows_secrets.py; packaged smoke | Перенос профиля требует повторного ввода ключа; управление ключами enterprise открыто |
| S-04 | TLS проверяется, перенаправления не обходят проверку адресата | Cloud clients transport validation and synthetic transport tests | Доверенные корпоративные CA задаются окружением; live-cloud acceptance не проведена |
| S-05 | Источник доказательства не разрешает произвольный путь или подменённый файл | source_preview/attach_source + captured snapshot/SHA-256 guard | Открытый пользователем фрагмент и экспорт остаются чувствительными данными |
| S-06 | Анализ не выполняет команды и не устанавливает зависимости | Pure engines and separated installation/build workflow | Отдельные интеграции должны проверяться при добавлении |
| S-07 | Неизвестные/ошибочные данные не дают ложного благополучия | partial/not_executed diagnostics; independent failed Edge handling | Ноль находок не доказывает безопасность |
| S-08 | Резервная копия целостна; ошибка не уничтожает исходник | organization_backup; SQLite integrity + hash; registry backup/restore regressions | Inspector v1 не включает новые registry tables в semantic digest; v2 migration открыта |
| S-09 | Права и аудит enterprise отделены от локального приложения | [BACKLOG](BACKLOG.md), [TECH_STACK](TECH_STACK.md) | RBAC/SSO/центральный audit пока не реализованы; локальный журнал правок не заменяет их |
| S-10 | Зависимости фиксированы и проходят проверку уязвимостей | uv.lock; harness build security | Последний dependency audit содержит findings; выпуск не объявляется полностью зелёным |
| S-11 | Релиз воспроизводим и сопровождается составом поставки | scripts/build_desktop.ps1; packaged --self-test; EXE/ZIP hashes | Windows CLI, SBOM и чистая Windows 11 ещё открыты |

Область статического security gate: Python-файлы приложения и qt_launcher.py;
исключения тестов, fixtures, зависимостей, кэшей и артефактов берутся из корневого
[SECURITY.md](../SECURITY.md). PowerShell, сторонние DLL и готовый образ этим
Bandit-прогоном не проверяются. Dependency audit является отдельной проверкой.

## Подключение обязательного внешнего документа

После его получения для каждого требования фиксируются точный исходный ID,
редакция документа, область применимости, связанные A-*/S-*/FR-*, затронутые
контракты и миграции, способ проверки и фактическое доказательство. Статусы:
«не оценено», «в работе», «проверено», «неприменимо с основанием».
Недостающие требования создают задачи в BACKLOG, а не исчезают из матрицы.

Текущая задача P0 выполнена для одобренного пользователем внутреннего baseline.
Поступление внешнего документа создаёт отдельное обновление этой матрицы.
Незавершённые механизмы и проверки из столбцов «Остаток» остаются открытыми.

## Проверка и выпуск v0.4

Перед выпуском нужны полный harness/build all с анализом каждого ненулевого
exit code, проверка миграций и старых проектов, самопроверка собранного EXE,
проверка целостности ZIP и совпадения вложенного EXE, версия 0.4, release notes
с возможностями и существенными ограничениями. Публикация разрешена пользователем
после завершения всего заказанного объёма; частично реализованный backlog не
считается готовностью выпуска.
