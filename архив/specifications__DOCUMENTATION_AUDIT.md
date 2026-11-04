# Аудит Markdown-документации — 31.10.2026

База: `c170560`, приложение 0.3.2. Охват: все 123 версионируемых Markdown-файлов проекта, включая skills, документацию synthetic fixtures и README ресурсов; дополнительно harness/context. Новый файл этого реестра добавлен отдельно.

Метод: чтение документов, сравнение исходников, импортов, workflow и истории Git. Автоматические локальные проверки, тесты, сборки и повторная верификация внешних API/URL не выполнялись. Большие исследовательские roadmap классифицированы по назначению; все их технические предложения не переаттестованы.

Копии в `.venv`, `dist`, `_temp_files`, `artifacts`, метаданные `.git` и сторонние пакеты не являются поддерживаемой документацией проекта. Их нельзя обновлять вместо оригиналов. Исторические ссылки на ignored artifacts могут быть недоступны в чистом checkout; отсутствие файла не подтверждает и не опровергает старый запуск.

## Решение по удалению

- Корневой `ROADMAP_V2_FULL.md`: точный дубль канонической версии; заменён указателем без удаления пути. Дальнейшее удаление указателя имеет смысл только после проверки входящих ссылок и отдельного разрешения.
- `architecture.md`: историческая карта коммита 1398f36, помечена. Возможен перенос в архив позже; уникальное описание не удалять автоматически.
- `WINDOWS_CLI_DISTRIBUTION.md`: историческая заменённая модель поставки; оставить указателем на WINDOWS_DISTRIBUTION.md.
- TASK, ADR, legacy, старые release notes и журналы: сохранять как историю. Дата сама по себе не основание удаления. Других доказанных кандидатов на удаление не найдено.

## Что обновлять дальше

- REQUIREMENT_STATUS и IMPLEMENTATION_TRACKER согласовывать с новыми функциями; не считать наличие кода доказательством закрытия широкого требования.
- CURRENT_STATE обновлять на релизах, CI-результаты всегда привязывать к SHA/запуску.
- Новые UserGate/Ideco пока вне devices; это факт текущей структуры, а не уже выполненный перенос.
- Не выдавать исследовательские планы точности/достижимости за функции продукта.

## Пофайловый реестр

| Файл | Категория / решение | Изменён в этой сверке |
| --- | --- | --- |
| [.agents/skills/arxion-change-impact/SKILL.md](../.agents/skills/arxion-change-impact/SKILL.md) | Процедура; согласована с AGENTS/CI | Да |
| [.agents/skills/arxion-golden-review/SKILL.md](../.agents/skills/arxion-golden-review/SKILL.md) | Процедура; согласована с AGENTS/CI | Да |
| [.agents/skills/arxion-quality/SKILL.md](../.agents/skills/arxion-quality/SKILL.md) | Процедура; согласована с AGENTS/CI | Да |
| [.agents/skills/arxion-security/SKILL.md](../.agents/skills/arxion-security/SKILL.md) | Процедура; согласована с AGENTS/CI | Да |
| [AGENTS.md](../AGENTS.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [GOALS.md](../GOALS.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [PLANS.md](../PLANS.md) | Накопленный журнал; датированные записи сохранять | Да |
| [README.md](../README.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [RELEASE_NOTES_v0.3.md](../RELEASE_NOTES_v0.3.md) | История 0.3.0; сохранить | Да |
| [ROADMAP_V2_FULL.md](../ROADMAP_V2_FULL.md) | Дубль заменён указателем | Да |
| [SECURITY.md](../SECURITY.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [architecture.md](../architecture.md) | Историческая карта; сохранить с пометкой | Да |
| [harness/build-log.md](../harness/build-log.md) | Накопленный журнал; датированные записи сохранять | Нет |
| [harness/project-map.md](../harness/project-map.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/ACL_MAP.md](ACL_MAP.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/ACL_MAP_WORKFLOW.md](ACL_MAP_WORKFLOW.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/ANALYSIS_RESULT.md](ANALYSIS_RESULT.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/ARCHITECTURE.md](ARCHITECTURE.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/BACKLOG.md](BACKLOG.md) | План/требования; сохранить, сверять с текущим статусом | Да |
| [specifications/CHECK_PASSPORTS.md](CHECK_PASSPORTS.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/CLOUD_RU_PUBLIC.md](CLOUD_RU_PUBLIC.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/CLOUD_RU_VMWARE.md](CLOUD_RU_VMWARE.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/CONTROL_ASSESSMENT.md](CONTROL_ASSESSMENT.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/CONTROL_REFERENCES.md](CONTROL_REFERENCES.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/CURRENT_STATE.md](CURRENT_STATE.md) | Текущая сводка 0.3.2 + явно отделённая история | Да |
| [specifications/DECISIONS.md](DECISIONS.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/DEPLOYMENT_TARGETS.md](DEPLOYMENT_TARGETS.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/DESKTOP_UI.md](DESKTOP_UI.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/DEVELOPMENT_RULES.md](DEVELOPMENT_RULES.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/DOMAIN_MODEL.md](DOMAIN_MODEL.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/FORWARDING_CONTEXT.md](FORWARDING_CONTEXT.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/FUNCTIONAL_REQUIREMENTS.md](FUNCTIONAL_REQUIREMENTS.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/GIT_RELEASE_POLICY.md](GIT_RELEASE_POLICY.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/GLOSSARY.md](GLOSSARY.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/IDECO.md](IDECO.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/IMPLEMENTATION_TRACKER.md](IMPLEMENTATION_TRACKER.md) | Исторический трекер с текущим пояснением; нужна поддержка по задачам | Да |
| [specifications/IMPROVEMENT_ROADMAP_2026-10.md](IMPROVEMENT_ROADMAP_2026-10.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/LEGACY_BASELINE.md](LEGACY_BASELINE.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/LEGACY_MIGRATION_MAP.md](LEGACY_MIGRATION_MAP.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/MANAGEMENT_ASSURANCE.md](MANAGEMENT_ASSURANCE.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/MIGRATION_COMPLETION_PLAN.md](MIGRATION_COMPLETION_PLAN.md) | План/требования; сохранить, сверять с текущим статусом | Да |
| [specifications/NETWORK_INPUTS.md](NETWORK_INPUTS.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/NETWORK_UI_GUIDE.md](NETWORK_UI_GUIDE.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/PLATFORM_EVALUATION.md](PLATFORM_EVALUATION.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/POLICY_EXPOSURE.md](POLICY_EXPOSURE.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/POLICY_GOVERNANCE.md](POLICY_GOVERNANCE.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/POLICY_SCOPE_CHECKS.md](POLICY_SCOPE_CHECKS.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/POLICY_UNION_SHADOWING.md](POLICY_UNION_SHADOWING.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/PRODUCT_BACKLOG.md](PRODUCT_BACKLOG.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/PRODUCT_VISION.md](PRODUCT_VISION.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/PROJECT_CONVENTIONS.md](PROJECT_CONVENTIONS.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/QUALITY_REQUIREMENTS.md](QUALITY_REQUIREMENTS.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/REFERENCE_ANALYSIS_NETOPIA.md](REFERENCE_ANALYSIS_NETOPIA.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/REQUIREMENT_STATUS.md](REQUIREMENT_STATUS.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/ROADMAP.md](ROADMAP.md) | План/требования; сохранить, сверять с текущим статусом | Да |
| [specifications/SCHEMA_MIGRATIONS.md](SCHEMA_MIGRATIONS.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/SECURITY_BASELINE.md](SECURITY_BASELINE.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/SOURCE_LAYOUT.md](SOURCE_LAYOUT.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/SPECIFICATION_INDEX.md](SPECIFICATION_INDEX.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/SPECIFICATION_REVIEW.md](SPECIFICATION_REVIEW.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/SR005_DIFF_CONTRACT.md](SR005_DIFF_CONTRACT.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/SUPPORTED_PLATFORMS.md](SUPPORTED_PLATFORMS.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/TASK-001_PROJECT_FOUNDATION.md](TASK-001_PROJECT_FOUNDATION.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-002_DOMAIN_MODEL.md](TASK-002_DOMAIN_MODEL.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-003_PARSER_TEST_CONTOUR.md](TASK-003_PARSER_TEST_CONTOUR.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-004_PLATFORM_SELECTION.md](TASK-004_PLATFORM_SELECTION.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-005_CISCO_ASA_PARSER.md](TASK-005_CISCO_ASA_PARSER.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-006_DEVICE_REVISIONS.md](TASK-006_DEVICE_REVISIONS.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-007_FIREWALL_ASSURANCE.md](TASK-007_FIREWALL_ASSURANCE.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-008_NETWORK_ASSURANCE.md](TASK-008_NETWORK_ASSURANCE.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-009_DESKTOP_INTEGRATION.md](TASK-009_DESKTOP_INTEGRATION.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-010_USER_DOCUMENTATION.md](TASK-010_USER_DOCUMENTATION.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-011_HP_ARUBA_PARSERS.md](TASK-011_HP_ARUBA_PARSERS.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-012_QT_DESKTOP.md](TASK-012_QT_DESKTOP.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-013_QT_NAVIGATION.md](TASK-013_QT_NAVIGATION.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-014_ARUBA_CHECK_COMPLETENESS.md](TASK-014_ARUBA_CHECK_COMPLETENESS.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-015_WORKSPACE_UI.md](TASK-015_WORKSPACE_UI.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-016_ROADMAP_R1.md](TASK-016_ROADMAP_R1.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK-017_ROADMAP_R2.md](TASK-017_ROADMAP_R2.md) | Исторические решения/этап; сохранить, не читать как текущий статус | Нет |
| [specifications/TASK_TEMPLATE.md](TASK_TEMPLATE.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/TECH_STACK.md](TECH_STACK.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/UI_BACKEND_INTEGRATION.md](UI_BACKEND_INTEGRATION.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/USERGATE.md](USERGATE.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/USER_GUIDE.md](USER_GUIDE.md) | Поддерживаемый контракт/руководство; сохранить | Да |
| [specifications/WINDOWS_CLI_DISTRIBUTION.md](WINDOWS_CLI_DISTRIBUTION.md) | Историческая поставка; указатель на единую Windows-сборку | Нет |
| [specifications/WINDOWS_DISTRIBUTION.md](WINDOWS_DISTRIBUTION.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [specifications/roadmap-v2/00_RESEARCH_SCOPE_AND_EXECUTION.md](roadmap-v2/00_RESEARCH_SCOPE_AND_EXECUTION.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/01_UX_AND_REPORTS.md](roadmap-v2/01_UX_AND_REPORTS.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/02_PLATFORMS_AND_PARSERS.md](roadmap-v2/02_PLATFORMS_AND_PARSERS.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/03_CHECKS_CATALOG.md](roadmap-v2/03_CHECKS_CATALOG.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/04_REACHABILITY_AND_MAP.md](roadmap-v2/04_REACHABILITY_AND_MAP.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/05_ACCURACY_AND_VERIFICATION.md](roadmap-v2/05_ACCURACY_AND_VERIFICATION.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/06_ORGANIZATION_DATA_AND_DELIVERY.md](roadmap-v2/06_ORGANIZATION_DATA_AND_DELIVERY.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/07_USER_JOURNEY_AND_ONBOARDING.md](roadmap-v2/07_USER_JOURNEY_AND_ONBOARDING.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/IMPLEMENTATION_STEPS.md](roadmap-v2/IMPLEMENTATION_STEPS.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/ROADMAP_V2_FULL.md](roadmap-v2/ROADMAP_V2_FULL.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/implementation-steps/COVERAGE.md](roadmap-v2/implementation-steps/COVERAGE.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/implementation-steps/R0.md](roadmap-v2/implementation-steps/R0.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/implementation-steps/R1.md](roadmap-v2/implementation-steps/R1.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/implementation-steps/R2.md](roadmap-v2/implementation-steps/R2.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/implementation-steps/R3.md](roadmap-v2/implementation-steps/R3.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/implementation-steps/R4.md](roadmap-v2/implementation-steps/R4.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/implementation-steps/R5.md](roadmap-v2/implementation-steps/R5.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/implementation-steps/R6.md](roadmap-v2/implementation-steps/R6.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/implementation-steps/R7.md](roadmap-v2/implementation-steps/R7.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [specifications/roadmap-v2/implementation-steps/R8.md](roadmap-v2/implementation-steps/R8.md) | План/требования; сохранить, сверять с текущим статусом | Нет |
| [src/firewall_compliance/interfaces/desktop/assets/map_icons/README.md](../src/firewall_compliance/interfaces/desktop/assets/map_icons/README.md) | Поддерживаемый контракт/руководство; сохранить | Нет |
| [tests/README.md](../tests/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Да |
| [tests/fixtures/assurance/README.md](../tests/fixtures/assurance/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Нет |
| [tests/fixtures/candidates/README.md](../tests/fixtures/candidates/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Да |
| [tests/fixtures/candidates/cisco-asa/README.md](../tests/fixtures/candidates/cisco-asa/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Да |
| [tests/fixtures/candidates/hp-aruba-aos-cx/README.md](../tests/fixtures/candidates/hp-aruba-aos-cx/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Да |
| [tests/fixtures/candidates/huawei-vrp/README.md](../tests/fixtures/candidates/huawei-vrp/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Да |
| [tests/fixtures/candidates/juniper-junos/README.md](../tests/fixtures/candidates/juniper-junos/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Да |
| [tests/fixtures/candidates/usergate-ngfw/README.md](../tests/fixtures/candidates/usergate-ngfw/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Да |
| [tests/fixtures/forwarding_asa/README.md](../tests/fixtures/forwarding_asa/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Нет |
| [tests/fixtures/hp_aruba/README.md](../tests/fixtures/hp_aruba/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Нет |
| [tests/fixtures/legacy/BASELINE.md](../tests/fixtures/legacy/BASELINE.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Нет |
| [tests/fixtures/network_asa/README.md](../tests/fixtures/network_asa/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Нет |
| [tests/fixtures/reachability/README.md](../tests/fixtures/reachability/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Нет |
| [tests/fixtures/revisions/README.md](../tests/fixtures/revisions/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Нет |
| [tests/golden/README.md](../tests/golden/README.md) | Документация synthetic данных/тестов; сохранить; старые инструменты помечены где встречаются | Да |
