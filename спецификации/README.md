# Спецификации проекта

Возвращены из архива 31.10.2026. Это требования, ограничения, контракты и решения, которые нужно учитывать при изменении кода. Читать относящиеся к задаче разделы, а не весь каталог перед каждой правкой.

Порядок работы и разрешения — [AGENTS.md](../AGENTS.md), разработка/релизы — [DEVELOPMENT.md](../DEVELOPMENT.md), безопасность — [SECURITY.md](../SECURITY.md). Эти правила имеют приоритет над историческими требованиями локальных запусков или автоматического создания тестов внутри старых описаний.

Фактический статус, roadmap и backlog остаются только в [PROJECT_STATUS.md](../PROJECT_STATUS.md); пользовательское описание — [DOCUMENTATION.md](../DOCUMENTATION.md). Целевое требование не является доказательством реализации. Исторические TASK, планы и исследования остались в архиве. Разделы миграций и ADR сохраняют исторические решения; применение к конкретной версии требует сверки кода.

## Требования и границы продукта

- [PRODUCT_VISION](PRODUCT_VISION.md)
- [FUNCTIONAL_REQUIREMENTS](FUNCTIONAL_REQUIREMENTS.md)
- [QUALITY_REQUIREMENTS](QUALITY_REQUIREMENTS.md)
- [SUPPORTED_PLATFORMS](SUPPORTED_PLATFORMS.md)
- [GLOSSARY](GLOSSARY.md)

## Архитектура и принятые решения

- [ARCHITECTURE](ARCHITECTURE.md)
- [DOMAIN_MODEL](DOMAIN_MODEL.md)
- [TECH_STACK](TECH_STACK.md)
- [DECISIONS](DECISIONS.md)
- [REQUIREMENTS_TRACEABILITY](REQUIREMENTS_TRACEABILITY.md)
- [UI_BACKEND_INTEGRATION](UI_BACKEND_INTEGRATION.md)

## Проверки и профили

- [CHECK_PASSPORTS](CHECK_PASSPORTS.md)
- [POLICY_EXPOSURE](POLICY_EXPOSURE.md)
- [POLICY_SCOPE_CHECKS](POLICY_SCOPE_CHECKS.md)
- [POLICY_UNION_SHADOWING](POLICY_UNION_SHADOWING.md)
- [POLICY_GOVERNANCE](POLICY_GOVERNANCE.md)
- [MANAGEMENT_ASSURANCE](MANAGEMENT_ASSURANCE.md)
- [CONTROL_ASSESSMENT](CONTROL_ASSESSMENT.md)
- [CONTROL_REFERENCES](CONTROL_REFERENCES.md)

## Контракты результатов и сетевой семантики

- [ANALYSIS_RESULT](ANALYSIS_RESULT.md)
- [SCHEMA_MIGRATIONS](SCHEMA_MIGRATIONS.md)
- [SR005_DIFF_CONTRACT](SR005_DIFF_CONTRACT.md)
- [NETWORK_INPUTS](NETWORK_INPUTS.md)
- [FORWARDING_CONTEXT](FORWARDING_CONTEXT.md)
- [ACL_MAP](ACL_MAP.md)
- [ACL_MAP_WORKFLOW](ACL_MAP_WORKFLOW.md)

## Контракты интеграций

- [USERGATE](USERGATE.md)
- [IDECO](IDECO.md)
- [CLOUD_RU_PUBLIC](CLOUD_RU_PUBLIC.md)
- [CLOUD_RU_VMWARE](CLOUD_RU_VMWARE.md)
