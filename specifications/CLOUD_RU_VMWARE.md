# Cloud.ru VMware: подключение и сканирования

Реализован сбор конфигурации VMware Cloud Director через API. В настройках
Cloud.ru есть отдельные подключения VMware, Advanced и Evolution.
Для Advanced и Evolution см. [руководство](CLOUD_RU_PUBLIC.md).
Для каждого локального проекта хранится одно подключение VMware.

## Что заполнить

| Поле | Где взять |
| --- | --- |
| Адрес площадки | Начало ссылки входа в Cloud Director, например `https://vcd01-01.cloud.ru`, без `/tenant/...` |
| Tenant | Имя из ссылки `https://<площадка>/tenant/<имя>/` |
| API Token | Cloud Director → меню пользователя → User preferences → Access Tokens → NEW |
| Версия API | По умолчанию `36.1`; поддерживаемую площадкой версию уточните в `https://<площадка>/docs/` |
| Таймаут | По умолчанию 30 секунд на запрос; допустимо 5–120 секунд |

Отдельные Key ID/Key Secret Evolution, project_id, пароль пользователя и прямой
доступ к vCenter или NSX Manager для этого способа подключения не требуются.
Токен наследует права его владельца. Нужны права чтения выбранных ресурсов и
сетевых сервисов. Генерация собственного API Token требует соответствующего
права в роли пользователя; настройка роли выполняется администратором tenant.

API Token обменивается на временный Access Token перед каждым сканированием и
проверкой подключения. Используется пользовательский API Token. Service Account
с ротацией refresh_token и процедура device_authorization в эту версию не входят.

Основание: [API Token Cloud.ru VMware](https://cloud.ru/docs/vdc/ug/topics/basic-info/basic-info__api-token)
и [отдельный механизм Service Account](https://cloud.ru/docs/vdc/ug/topics/api/api__service-tenant).

## Используемые API

`SITE` — настроенный адрес площадки. После авторизации передаётся заголовок
`Authorization: Bearer <access_token>`. В Accept передаётся выбранная версия API.

| Метод и путь относительно SITE | Назначение |
| --- | --- |
| `POST /oauth/tenant/{tenant}/token` | Обмен API Token: form-urlencoded `grant_type=refresh_token&refresh_token=<API Token>` |
| `GET /api/org/` | Проверка доступа к указанному tenant |
| `GET /api/query?type=vm&format=records&page=...&pageSize=128` | Инвентарь виртуальных машин |
| `GET /api/vApp/vm-{uuid}/networkConnectionSection` | Сетевые подключения, IP/MAC и параметры подключения ВМ |
| `GET /cloudapi/1.0.0/edgeGateways?page=...&pageSize=128` | Инвентарь Edge Gateway |
| `GET /cloudapi/1.0.0/orgVdcNetworks?page=...&pageSize=128` | Сети Org VDC и их параметры |
| `GET /cloudapi/{version}/edgeGateways/{urn}/firewall/rules` | Пользовательские и системные правила Firewall |
| `GET /cloudapi/{version}/edgeGateways/{urn}/nat/rules?page=...&pageSize=128` | Правила NAT |
| `GET /cloudapi/{version}/edgeGateways/{urn}/routing/staticRoutes?page=...&pageSize=128` | Настроенные статические маршруты |

Для сетевых сервисов Edge Gateway версия пути — `1.0.0` для API до 38.1 и
`2.0.0` начиная с 38.1. Сбор этих сервисов предназначен для NSX-T Edge Gateway.
При несовместимости API, отсутствии ресурса или прав результат содержит ошибку;
недоступные данные не подменяются пустым успешным результатом. NSX-V, DFW,
конфигурации гостевых NGFW, динамические маршруты, разрешение ссылок Firewall
Groups/Application Port Profiles и расчёт достижимости пока не поддержаны.

Справочники: [VM Query](https://github.com/vmware/go-vcloud-director/blob/main/types/v56/constants.go),
[операции vCloud API](https://developer.broadcom.com/xapis/vmware-cloud-director-api/latest/doc/landing-user_operations.html),
[Edge Gateway](https://developer.broadcom.com/xapis/vmware-cloud-director-openapi/latest/cloudapi/1.0.0/edgeGateways/get/),
[сети Org VDC](https://developer.broadcom.com/xapis/vmware-cloud-director-openapi/latest/cloudapi/1.0.0/orgVdcNetworks/get/),
[Firewall API](https://knowledge.broadcom.com/external/article/401636),
[NAT API](https://knowledge.broadcom.com/external/article/424616),
[Static Routes](https://developer.broadcom.com/xapis/vmware-cloud-director-openapi/latest/cloudapi/2.0.0/edgeGateways/gatewayId/routing/staticRoutes/get/).

## Как запустить

1. Выберите или создайте проект.
2. Откройте Настройки → Интеграции → Cloud.ru → VMware.
3. Заполните поля, сохраните подключение и нажмите «Проверить подключение».
4. Перейдите в Операции → Облачный сбор → Новый сбор и выберите Cloud.ru VMware.
5. Выберите ВМ, Edge Gateway и/или сети Org VDC. Инвентарь выбранных типов
   собирается всегда. Дополнительно можно включить сетевые подключения ВМ,
   Firewall, NAT и статические маршруты шлюзов.
6. Нажмите «Запустить сканирование». Сбор выполняется в фоне. Отмена действует
   после текущего API-запроса; частично собранные ресурсы сохраняются.

Собираются доступные токену ресурсы tenant, без фильтра по отдельному Org VDC.
История, ресурсы, ошибки, список запросов и JSON доступны в разделе сканирований.
Снимок можно экспортировать в JSON. Переключение локального проекта не меняет
проект назначения уже запущенного сканирования.

Статусы: завершено, частично, ошибка, отменено или прервано при закрытии окна.
Сбор данных пока не запускает проверки качества правил локального анализатора;
он не подтверждает безопасность или конечную достижимость сети.

## Хранение

API Token хранится в отдельной таблице SQLite, зашифрованный Windows DPAPI для
текущего пользователя. Он не копируется в настройки проверок, историю запусков,
результаты сканирования или экспорт JSON. Access Token существует только в памяти
клиента во время запроса. На другом компьютере/профиле Windows нужно ввести API
Token заново. Пустое поле при сохранении прежнего адреса и tenant сохраняет токен;
для нового адреса или tenant требуется повторный ввод.

Проверка TLS включена. Перенаправления не выполняются. Ошибки не содержат тела
ответа авторизации, токенов или заголовков. Снимки ресурсов содержат реальные
адреса и имена инфраструктуры и сохраняются в локальной базе проекта.

Автотесты используют синтетические ответы API. Проверка на реальной площадке
Cloud.ru требует заполненного подключения и доступного tenant.
