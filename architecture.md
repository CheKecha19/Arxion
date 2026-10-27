# Техническая карта Python-кода Firewall Compliance

Карта составлена по исходникам ветки `release/v0.3`, базовый коммит `1398f36`.
Она описывает эту версию репозитория, а не изменения, оставшиеся на локальном
компьютере. Для каждого файла указано назначение в одном-двух предложениях.

Здесь перечислены модули приложения, включая модели и вспомогательные функции:
большинство из них импортируются, а не запускаются как самостоятельные скрипты.
Исключены тесты, Harness, smoke/self-test и реализации проверок правил и настроек
(`analysis/policy_checks.py`, `analysis/management_checks.py`), как запрошено.
Оркестрация анализа, контракты результатов и их отображение включены, поскольку
они участвуют в обычной работе программы; каталог отдельных проверок не приводится.

## Как запускается и работает приложение

- CLI: `firewall-compliance` или `python -m firewall_compliance`.
- Основной GUI: `firewall-compliance-desktop` или
  `python -m firewall_compliance.interfaces.desktop` — оба запускают Qt.
- Windows-сборка использует `scripts/qt_launcher.py`.
- Основной путь данных: чтение конфигурации → выбор парсера → нормализованные
  модели и ревизия → анализ → сохранение в SQLite → таблицы, карты и отчёты.
- Облачные сборщики получают инвентарь и правила через API; получение правила
  не равнозначно его анализу или доказанной доступности сервиса.

Пути в таблицах указаны относительно корня проекта либо каталога в заголовке.
Ссылки ведут к исходникам. Наличие модуля не означает, что все его возможности
подключены к основному GUI: особенно это касается заготовок `organization_*`.

## Точки входа

| Файл | Назначение |
| --- | --- |
| [src/firewall_compliance/__main__.py](src/firewall_compliance/__main__.py) | Передаёт запуск `python -m firewall_compliance` командному интерфейсу. |
| [src/firewall_compliance/interfaces/cli/main.py](src/firewall_compliance/interfaces/cli/main.py) | Описывает команды Typer, включая вывод версии и анализ конфигураций. Принимает параметры пользователя и вызывает прикладные сценарии. |
| [src/firewall_compliance/interfaces/desktop/__main__.py](src/firewall_compliance/interfaces/desktop/__main__.py) | Запускает основной Qt-интерфейс при выполнении desktop-пакета через `python -m`. |
| [scripts/qt_launcher.py](scripts/qt_launcher.py) | Точка входа упакованного Windows-приложения, в обычном режиме запускающая Qt. Встроенный диагностический режим здесь не разбирается. |

## Доменная модель — `src/firewall_compliance/domain/`

Это общие контракты данных, которыми пользуются парсеры, анализатор, хранилище и UI.

| Файл | Назначение |
| --- | --- |
| [base.py](src/firewall_compliance/domain/base.py) | Задаёт базовый Pydantic-класс и общие настройки строгих доменных моделей. |
| [configuration.py](src/firewall_compliance/domain/configuration.py) | Описывает устройство, снимок конфигурации и нормализованное firewall-правило. Содержит поля условий, действия и метаданных правила. |
| [enums.py](src/firewall_compliance/domain/enums.py) | Собирает общие перечисления: действия, протоколы, критичность, достоверность данных и виды изменений. Позволяет разным слоям одинаково интерпретировать значения. |
| [network.py](src/firewall_compliance/domain/network.py) | Описывает адресные объекты, группы, диапазоны IP, сервисы и диапазоны портов. Это нормализованные условия правил, а не сетевой сканер. |
| [source.py](src/firewall_compliance/domain/source.py) | Хранит положение сущности в исходном документе, необходимое для перехода от результата к доказательству. |
| [parse_result.py](src/firewall_compliance/domain/parse_result.py) | Определяет результат парсинга, ошибки, предупреждения, неподдержанные конструкции и сведения о полноте разбора. |
| [revision.py](src/firewall_compliance/domain/revision.py) | Описывает неизменяемую ревизию устройства, интерфейсы, маршруты, сегменты и зафиксированные связи. Здесь же определены контракты сравнения ревизий и доказательства полноты сбора. |
| [observation.py](src/firewall_compliance/domain/observation.py) | Описывает подтверждённое время наблюдения и согласованный интервал для нескольких экспортов. Не подменяет время состояния временем импорта файла. |
| [snapshot.py](src/firewall_compliance/domain/snapshot.py) | Создаёт отделённые от входа глубокие снимки моделей и вложенных коллекций с защитой от обычных изменений. Используется для сохранения воспроизводимых результатов. |
| [finding.py](src/firewall_compliance/domain/finding.py) | Определяет находку и её доказательную базу: критичность, затронутые правила, происхождение и рекомендацию. |
| [assurance.py](src/firewall_compliance/domain/assurance.py) | Задаёт контракты результатов анализа правил и ограничений выполнения. Разделяет число находок и полноту выполненного анализа. |
| [management.py](src/firewall_compliance/domain/management.py) | Описывает извлечённые факты управления устройством и требования профиля организации. Нормализует адреса серверов без сетевых запросов и не сохраняет пароли или SNMP community в этих фактах. |
| [policy_matching.py](src/firewall_compliance/domain/policy_matching.py) | Реализует операции над адресными и сервисными условиями: объединение интервалов, покрытие и сопоставление потока. Неизвестные условия не расширяет автоматически до любого трафика. |
| [policy_decision.py](src/firewall_compliance/domain/policy_decision.py) | Описывает привязку ACL, трассу локального решения и административное состояние интерфейсов. Эти результаты не являются итогом прохождения пакета через сеть. |
| [reachability.py](src/firewall_compliance/domain/reachability.py) | Определяет запрос сетевого потока, причины неопределённости, кандидатов пути и результаты выбора маршрута. |
| [forwarding.py](src/firewall_compliance/domain/forwarding.py) | Описывает нейтральный контекст пересылки: интерфейсы, ACL, привязки, настройки и отдельные доказательства полноты их наборов. |
| [forwarding_policy.py](src/firewall_compliance/domain/forwarding_policy.py) | Хранит этапы и результат условной цепочки политик для заданных интерфейсов. Отделяет её от доказанной достижимости потока. |
| [forwarding_policy_evaluation.py](src/firewall_compliance/domain/forwarding_policy_evaluation.py) | Вычисляет условную цепочку политик по явно переданной паре интерфейсов. Не выбирает реальный выходной интерфейс из таблицы маршрутов. |
| [acl_map.py](src/firewall_compliance/domain/acl_map.py) | Определяет версионированные узлы и связи логической карты ACL и строит их каноническую проекцию. Сохраняет порядок правил и ограничения, не выдавая карту условий за физическую топологию. |

## Разбор конфигураций — `src/firewall_compliance/parsers/`

| Файл | Назначение |
| --- | --- |
| [contracts.py](src/firewall_compliance/parsers/contracts.py) | Задаёт общий интерфейс парсера, входной документ, запрос, метаданные и результат определения формата. Описывает отказ парсинга без создания фиктивной конфигурации. |
| [registry.py](src/firewall_compliance/parsers/registry.py) | Регистрирует адаптеры и выбирает наиболее подходящий по содержимому документа. Обрабатывает неоднозначность выбора и нарушение контрактов. |
| [catalog.py](src/firewall_compliance/parsers/catalog.py) | Собирает общий реестр ограниченных адаптеров Cisco ASA, HP/Aruba и Comware для CLI и desktop. |
| [cisco_asa.py](src/firewall_compliance/parsers/cisco_asa.py) | Преобразует поддержанную часть текстовых ACL и объектов Cisco ASA 9.16 в общую модель. Сохраняет диагностику неполного разбора. |
| [hp_aruba.py](src/firewall_compliance/parsers/hp_aruba.py) | Разбирает поддержанные IPv4 ACL AOS-Switch/AOS-CX, их назначения и комментарии. Разделяет управление устройством и транзитную фильтрацию с учётом ограничений адаптера. |
| [comware.py](src/firewall_compliance/parsers/comware.py) | Разбирает ограниченный набор IPv4 ACL HP/H3C Comware и их назначений. Сохраняет область управления, но не вычисляет транзитную достижимость. |
| [management.py](src/firewall_compliance/parsers/management.py) | Извлекает явно записанные настройки управления из поддержанного синтаксиса. Не предполагает значения по умолчанию и фактическое состояние служб. |
| [network_contracts.py](src/firewall_compliance/parsers/network_contracts.py) | Определяет роли и метаданные сетевых документов, привязки интерфейсов и контракт импорта сетевых фактов. |
| [cisco_asa_network.py](src/firewall_compliance/parsers/cisco_asa_network.py) | Координирует отдельный разбор сетевых документов ASA с явным назначением источников и сведениями о полноте. |
| [asa_network_common.py](src/firewall_compliance/parsers/asa_network_common.py) | Содержит общий промежуточный результат для узких текстовых грамматик сетевых фактов ASA. |
| [asa_network_interfaces.py](src/firewall_compliance/parsers/asa_network_interfaces.py) | Извлекает поддержанные настройки физических IPv4-интерфейсов ASA. Сохраняет неизвестные значения и неподдержанные строки. |
| [asa_network_routes.py](src/firewall_compliance/parsers/asa_network_routes.py) | Разбирает настроенные маршруты и IPv4 RIB ASA. Не считает наличие строки конфигурации доказательством установки маршрута. |
| [forwarding_contracts.py](src/firewall_compliance/parsers/forwarding_contracts.py) | Описывает отдельные входы и результаты разбора контекста пересылки ASA вне общего реестра ACL-парсеров. |
| [cisco_asa_forwarding.py](src/firewall_compliance/parsers/cisco_asa_forwarding.py) | Извлекает поддержанные forwarding-факты из конфигурации ASA 9.16 для последующего условного анализа цепочки политик. |

## Аналитические алгоритмы — `src/firewall_compliance/analysis/`

Реализации отдельных проверок намеренно опущены; ниже — остальные алгоритмы и оркестрация.

| Файл | Назначение |
| --- | --- |
| [firewall_assurance.py](src/firewall_compliance/analysis/firewall_assurance.py) | Запускает выбранный каталог анализа одной ревизии и собирает единый результат с версиями, профилем и ограничениями. Сам не читает файлы и не обращается к сети. |
| [policy_matching.py](src/firewall_compliance/analysis/policy_matching.py) | Сохраняет совместимый путь импорта операций сопоставления, реализованных в доменном модуле `policy_matching.py`. |
| [policy_decision.py](src/firewall_compliance/analysis/policy_decision.py) | Вычисляет локальное first-match решение для явно подтверждённой ACL и заданного потока. Не выполняет восстановление адресов после NAT. |
| [route_selection.py](src/firewall_compliance/analysis/route_selection.py) | Выбирает маршрут по наблюдаемой RIB и сохраняет причины неопределённости. Предварительный ответ о пути не подменяет ACL/NAT-анализ и фактическую достижимость. |
| [device_decision.py](src/firewall_compliance/analysis/device_decision.py) | Объединяет кандидата маршрута, административные настройки интерфейсов и локальное решение одной ACL. Явно сохраняет непроверенные этапы полной цепочки. |
| [forwarding_policy.py](src/firewall_compliance/analysis/forwarding_policy.py) | Предоставляет публичный API условного анализа цепочки политик для заданной пары физических интерфейсов. Возвращает самостоятельный снимок результата. |
| [revision_diff.py](src/firewall_compliance/analysis/revision_diff.py) | Сравнивает согласованные ревизии одного устройства и формирует изменения с доказательствами. Не выводит из различий влияние NAT или конечную достижимость. |
| [acl_map.py](src/firewall_compliance/analysis/acl_map.py) | Строит снимок логической карты ACL и фильтрует её связи для представления. Фильтрация не изменяет сведения о полноте исходного анализа. |

## Прикладные сценарии — `src/firewall_compliance/application/`

| Файл | Назначение |
| --- | --- |
| [firewall_assurance.py](src/firewall_compliance/application/firewall_assurance.py) | Проводит документ через реестр парсеров, создаёт ревизию и запускает анализ. Сетевые факты, не полученные из источника, оставляет неизвестными. |
| [network_import.py](src/firewall_compliance/application/network_import.py) | Обогащает новую ревизию отдельными сетевыми документами после согласования их происхождения. Не подменяет наблюдаемую RIB настроенными маршрутами. |
| [device_decision.py](src/firewall_compliance/application/device_decision.py) | Связывает импортированные обозначения интерфейсов с локальным анализом устройства. Подтверждает соответствие по документу, не превращая метку автоматически в зону. |
| [forwarding_binding.py](src/firewall_compliance/application/forwarding_binding.py) | Связывает контекст пересылки с импортированной ревизией ASA и отображением интерфейсов. Согласованная привязка сама по себе не означает полноту данных или разрешение доступа. |
| [acl_map.py](src/firewall_compliance/application/acl_map.py) | Экспортирует карту ACL в JSON и DOT вместе с ограничениями. Генерация DOT не требует запуска Graphviz. |

## Файлы, облачные API и секреты — `src/firewall_compliance/infrastructure/`

| Файл | Назначение |
| --- | --- |
| [source_reader.py](src/firewall_compliance/infrastructure/source_reader.py) | Читает локальные конфигурационные файлы в память и готовит вход для парсеров. |
| [cloud_vmware.py](src/firewall_compliance/infrastructure/cloud_vmware.py) | Реализует read-only сбор из Cloud.ru VMware Cloud Director: транспорт, авторизацию, согласование версии API и обработку ответов. Не изменяет облачную инфраструктуру. |
| [cloud_public.py](src/firewall_compliance/infrastructure/cloud_public.py) | Реализует read-only клиенты Cloud.ru Evolution Compute и Advanced ECS/VPC. Содержит конфигурации доступа, выбор ресурсов и подпись запросов Advanced. |
| [windows_secrets.py](src/firewall_compliance/infrastructure/windows_secrets.py) | Шифрует и расшифровывает локальные секреты через Windows DPAPI с привязкой к пользователю. Не предоставляет равноценное хранилище секретов для Linux. |

## Основной интерфейс и представления — `src/firewall_compliance/interfaces/desktop/`

| Файл | Назначение |
| --- | --- |
| [qt_app.py](src/firewall_compliance/interfaces/desktop/qt_app.py) | Собирает главное окно Qt, страницы, действия пользователя и связь виджетов с проектами и заданиями. Основное место интеграции таблиц, импорта, карт и отчётов. |
| [qt_models.py](src/firewall_compliance/interfaces/desktop/qt_models.py) | Предоставляет модель строк для таблиц Qt с сортировкой и поиском без отдельного виджета на каждую строку. |
| [qt_theme.py](src/firewall_compliance/interfaces/desktop/qt_theme.py) | Устанавливает общую тёмную тему, цветовые роли и оформление Qt-компонентов и диалогов. |
| [backend.py](src/firewall_compliance/interfaces/desktop/backend.py) | Объединяет ревизию и результат в сессию desktop-анализа. Выполняет файловый анализ, повторный запуск, сравнение и подготовку данных для UI/экспорта. |
| [jobs.py](src/firewall_compliance/interfaces/desktop/jobs.py) | Управляет фоновыми заданиями и событиями их выполнения. Интерфейс получает результаты через явный опрос, а не прямые обращения worker-потока к виджетам. |
| [workspace_models.py](src/firewall_compliance/interfaces/desktop/workspace_models.py) | Формирует представления операций и облачных ресурсов из сохранённых данных. Различает ресурсы разных подключений и не считает отсутствие в новом сборе удалением. |
| [workspace_navigation.py](src/firewall_compliance/interfaces/desktop/workspace_navigation.py) | Определяет разделы рабочего места и соответствие страниц разделам независимо от конкретных виджетов. |
| [workspace_history.py](src/firewall_compliance/interfaces/desktop/workspace_history.py) | Хранит историю переходов, фильтров и выделений в памяти. Не меняет результаты анализа. |
| [resource_details.py](src/firewall_compliance/interfaces/desktop/resource_details.py) | Готовит карточки ресурсов, историю наблюдений и переходы к доказательствам. Отбирает фрагменты источника, относящиеся к выбранному правилу или объекту. |
| [object_presentation.py](src/firewall_compliance/interfaces/desktop/object_presentation.py) | Преобразует канонические адреса, сервисы, объекты и условия правил в читаемые подписи и подробности. Не выдумывает отсутствующие значения. |
| [check_presentation.py](src/firewall_compliance/interfaces/desktop/check_presentation.py) | Переводит сохранённое состояние выполнения анализа в подписи и причины для UI. Это отображение результата, а не реализация проверок. |
| [result_presentation.py](src/firewall_compliance/interfaces/desktop/result_presentation.py) | Группирует одинаковые сообщения об ограничениях для Qt и HTML с сохранением исходных записей и области действия. Не переписывает результат backend. |
| [batch_reports.py](src/firewall_compliance/interfaces/desktop/batch_reports.py) | Создаёт общие отчёты запуска в JSON/HTML и сравнивает находки запусков. Пользовательские решения сохраняет отдельно от исходных результатов. |
| [management_settings.py](src/firewall_compliance/interfaces/desktop/management_settings.py) | Предоставляет редактирование организационного профиля управления устройствами. Полнота конкретного импорта не становится глобальным свойством профиля. |
| [cloud_panel.py](src/firewall_compliance/interfaces/desktop/cloud_panel.py) | Содержит панель настроек облачных подключений и запуска read-only сборов VMware. Это Tkinter-компонент, а не основной Qt-экран. |
| [cloud_public_form.py](src/firewall_compliance/interfaces/desktop/cloud_public_form.py) | Предоставляет формы проектных подключений Cloud.ru Advanced и Evolution с соответствующими типами ключей. |
| [cloud_rule_presentation.py](src/firewall_compliance/interfaces/desktop/cloud_rule_presentation.py) | Подготавливает колонки, строки и подробности собранных облачных правил. Не разрешает ссылки на объекты и не выдаёт показ правила за выполненный анализ. |

## Карты и сетевые формы — `src/firewall_compliance/interfaces/desktop/`

| Файл | Назначение |
| --- | --- |
| [project_map.py](src/firewall_compliance/interfaces/desktop/project_map.py) | Строит независимую от Qt карту ресурсов проекта и заявленных ACL-связей. Хранит сведения о правилах для перехода от связи к её основанию. |
| [qt_project_map.py](src/firewall_compliance/interfaces/desktop/qt_project_map.py) | Рисует общую карту проекта с иконками, вложенными областями, именованными зонами и связями. |
| [map_geometry.py](src/firewall_compliance/interfaces/desktop/map_geometry.py) | Вычисляет пересечения прямых рёбер и позиции визуальных мостиков, исключая общие конечные точки. |
| [qt_acl_map.py](src/firewall_compliance/interfaces/desktop/qt_acl_map.py) | Отображает логическую карту ACL конкретной ревизии через Qt-сцену, узлы и связи. Состояние представления строится по сохранённой ревизии. |
| [topology_map.py](src/firewall_compliance/interfaces/desktop/topology_map.py) | Проецирует записанные факты интерфейсов и префиксов, а также существующие трассы политик для показа топологии. Не выводит физические кабели или работоспособность связи из совпадения подсетей. |
| [qt_topology_map.py](src/firewall_compliance/interfaces/desktop/qt_topology_map.py) | Рисует Qt-карту зафиксированных топологических фактов с деталями происхождения и полноты. Не выполняет дополнительное сетевое исследование. |
| [map_network_facts.py](src/firewall_compliance/interfaces/desktop/map_network_facts.py) | Кодирует и декодирует версионированный снимок входных сетевых фактов карты. Сохраняет принадлежность снимка владельцу и ограничения формата. |
| [map_store.py](src/firewall_compliance/interfaces/desktop/map_store.py) | Читает и записывает архивы сетевых фактов по явному пути с ограничениями размера. Не перезаписывает существующий файл при сохранении. |
| [network_backend.py](src/firewall_compliance/interfaces/desktop/network_backend.py) | Организует импорт сетевых документов и выполнение локальных сетевых/forwarding-запросов для desktop. Не зависит от Tkinter. |
| [qt_network.py](src/firewall_compliance/interfaces/desktop/qt_network.py) | Предоставляет Qt-формы импорта сетевых документов и условного анализа ASA, включая редактор явных JSON-контрактов. Документы этого интерфейса остаются в памяти. |
| [network_panel.py](src/firewall_compliance/interfaces/desktop/network_panel.py) | Реализует сетевые формы прежнего Tkinter-интерфейса и состояние их документов/запросов. Разделяет роли источников, происхождение фактов и локальные решения. |

## Проекты и хранилище — `src/firewall_compliance/interfaces/desktop/`

| Файл | Назначение |
| --- | --- |
| [project_store.py](src/firewall_compliance/interfaces/desktop/project_store.py) | Управляет SQLite-хранилищем проектов, запусков, результатов, пользовательских отметок и облачных сборов. Вместо полного исходного документа сохраняет необходимые данные и выдержки доказательств. |
| [organization_models.py](src/firewall_compliance/interfaces/desktop/organization_models.py) | Определяет неизменяемые модели чтения прежних проектов, записей и результатов обследования базы. Используется при подготовке организационного рабочего пространства. |
| [organization_inspection.py](src/firewall_compliance/interfaces/desktop/organization_inspection.py) | Читает согласованный снимок поддержанной legacy-базы без её изменения и описывает формат, записи и обнаруженные ограничения. Это прикладное чтение хранилища, не тестовый скрипт. |
| [organization_workspace.py](src/firewall_compliance/interfaces/desktop/organization_workspace.py) | Даёт read-only фасад доступа ко всем исходным проектам legacy-базы, запускам и облачным сборам. Это совместимый слой до активации организационной модели, не завершённая миграция. |
| [organization_lock.py](src/firewall_compliance/interfaces/desktop/organization_lock.py) | Определяет канонический путь блокировки и lease рабочего пространства с блокировкой ОС. Позволяет ограничить конкурирующие операции над одной базой. |
| [organization_backup.py](src/firewall_compliance/interfaces/desktop/organization_backup.py) | Подготавливает резервную SQLite-копию, контролирует допустимость пути и целостность кандидата, рассчитывает хеш и завершает сохранение. Наличие этих примитивов не означает подключённый пользовательский сценарий миграции. |
| [organization_restore.py](src/firewall_compliance/interfaces/desktop/organization_restore.py) | Содержит низкоуровневые файловые операции для восстановления базы и сохранения forensic-копий. Полный сценарий восстановления этим модулем не реализован. |
| [organization_schema.py](src/firewall_compliance/interfaces/desktop/organization_schema.py) | Формирует добавочные SQL-описания организационных таблиц и ограничений. Это подготовительный модуль: он сам не применяет схему и не заполняет базу. |
| [organization_transactions.py](src/firewall_compliance/interfaces/desktop/organization_transactions.py) | Содержит заготовки ограниченного разрешения записи для SQLite-соединения и определения защитных триггеров legacy-таблиц. В исходнике явно отмечены неподтверждённость и отсутствие подключения к соединениям; полноценный менеджер транзакций здесь не реализован. |

## Прежний интерфейс и демонстрационные данные — `src/firewall_compliance/interfaces/desktop/`

Эти файлы не являются тестами, но не служат основной точкой запуска Qt-продукта.

| Файл | Назначение |
| --- | --- |
| [app.py](src/firewall_compliance/interfaces/desktop/app.py) | Реализует прежний Tkinter-макет рабочего места аналитика на демонстрационных данных. Не является основным Qt-приложением. |
| [live_app.py](src/firewall_compliance/interfaces/desktop/live_app.py) | Расширяет Tkinter-интерфейс реальным файловым анализом, фоновыми заданиями, экспортом и сетевыми формами. Разделяет демонстрационные и реальные сессии. |
| [demo.py](src/firewall_compliance/interfaces/desktop/demo.py) | Определяет простые модели представления и синтетический набор устройств, правил и находок для демонстрационного интерфейса. Конфигурации здесь не анализируются. |
| [gui_lifetime.py](src/firewall_compliance/interfaces/desktop/gui_lifetime.py) | Организует освобождение циклических Tk-объектов в потоке владельца GUI. Нужен для безопасного жизненного цикла прежнего интерфейса. |

## Служебные файлы пакетов — `__init__.py`

| Файл | Назначение |
| --- | --- |
| [src/firewall_compliance/__init__.py](src/firewall_compliance/__init__.py) | Объявляет пакет и текущую версию приложения. |
| [domain/__init__.py](src/firewall_compliance/domain/__init__.py) | Экспортирует общий публичный набор доменных моделей для остальных слоёв. |
| [parsers/__init__.py](src/firewall_compliance/parsers/__init__.py) | Экспортирует адаптеры, контракты и реестр парсеров. |
| [analysis/__init__.py](src/firewall_compliance/analysis/__init__.py) | Экспортирует основные функции локального анализа, выбора маршрута и сравнения ревизий. |
| [infrastructure/__init__.py](src/firewall_compliance/infrastructure/__init__.py) | Экспортирует файловый адаптер чтения источников. |
| [application/__init__.py](src/firewall_compliance/application/__init__.py) | Обозначает пакет прикладных сценариев; самостоятельной логики не содержит. |
| [bootstrap/__init__.py](src/firewall_compliance/bootstrap/__init__.py) | Обозначает место для сборки зависимостей; в этой версии содержит только описание пакета. |
| [compliance/__init__.py](src/firewall_compliance/compliance/__init__.py) | Обозначает пакет compliance-контролей; в этой версии содержит только описание, без реализованного движка соответствия стандартам. |
| [interfaces/__init__.py](src/firewall_compliance/interfaces/__init__.py) | Обозначает пакет пользовательских интерфейсов без самостоятельной логики. |
| [interfaces/cli/__init__.py](src/firewall_compliance/interfaces/cli/__init__.py) | Обозначает пакет CLI; команды находятся в `main.py`. |
| [interfaces/desktop/__init__.py](src/firewall_compliance/interfaces/desktop/__init__.py) | Обозначает desktop-пакет; создание Qt-приложения выполняется не здесь, а в `qt_app.py`. |

## Куда смотреть при изменениях

- Разбор конфигураций и комментариев: `parsers/`; общие поля правил — `domain/`.
- Поведение анализа и объяснение решения: `analysis/`, затем вызывающий сценарий `application/`.
- Таблицы и навигация: `qt_app.py`, `qt_models.py`, `workspace_*`, `*_presentation.py`.
- Карта проекта, карта ACL и топология: отдельные `project_map`, `acl_map`,
  `topology_map` и их Qt-компоненты; это разные представления, не взаимозаменяемые карты.
- История и данные проекта: `project_store.py`; подготовка новой организационной
  модели — `organization_*`, с учётом отмеченной незавершённости.
- Облачные подключения: `infrastructure/cloud_*.py`; формы и отображение — desktop-модули.
- Отчёты: `batch_reports.py`, `backend.py`; CLI-параметры — `interfaces/cli/main.py`.

При переименовании, добавлении или удалении Python-модулей карту следует обновлять.
Она дополняет `specifications/ARCHITECTURE.md`, но не заменяет контракты в коде
и не подтверждает готовность неподключённых функций.
