# Необязательные ссылки NIST/CIS

Модуль `application/control_reference_catalogues.py` создаёт три каталога через
`reference_control_catalogue(identifier)`; список `REFERENCE_CATALOGUE_IDS`
содержит точные IDs. Mapping version — `1.0.0`, дата проверки источников —
28.10.2026. Это авторские сопоставления Arxion, не crosswalk авторов стандартов.
Внутренний baseline остаётся значением по умолчанию. Автоматического принятия
внешних требований, изменения профиля либо повторного анализа нет.

## Проверенные первоисточники и область

- `nist-sp800-41-r1`: [NIST SP 800-41 Rev.1, September2009](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-41r1.pdf),
  §4.1 и §5.2.3. Сопоставлены профиль сервисов/admin-источников и настройка
  logging. Испытания §5.3 оставлены без автоматического сопоставления.
- `nist-sp800-53-r5-20201210`: [NIST SP800-53 Rev.5 с обновлениями10.12.2020](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final),
  [контроли и PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf).
  AC-4/SC-7/CM-7 связаны лишь с условиями, запрещёнными явным профилем;
  AU-12 — с флагом logging. AU-2 и SC-7(5) остаются без автоматического
  сопоставления. Более поздний release5.2.0 не подменяет эту закреплённую редакцию.
- `cis-controls-v8.1`: официальная CIS Controls Assessment Specification,
  [4.8 и4.4](https://cas.docs.cisecurity.org/en/latest/source/Controls4/),
  [8.2 и8.1](https://cas.docs.cisecurity.org/en/latest/source/Controls8/),
  [12.2 и12.3](https://cas.docs.cisecurity.org/en/latest/source/Controls12/),
  [13.4](https://cas.docs.cisecurity.org/en/latest/source/Controls13/).
  Технические условия и logging дают только вход для выбранной части;
  развёртывание, процедуры и свойства управления остаются без сопоставления.

Наличие разрешения не подтверждает применённую межсегментную фильтрацию,
запущенный сервис, сохранённый журнал или защищённую сессию. Broad ALLOW само
по себе не доказывает нарушение стандарта и не сопоставлен с таким вердиктом.
Организация задаёт применимость и точные параметры; вердикт относится только
к проверенной технической части. Остальные части прямо перечислены в limits.

В mapping сохранены источник, редакция, исходный ID, обоснование, covered_part,
версии check и границы. Одна проверка может поддерживать несколько частей.
ControlDefinition без mapping при применимом требовании даёт
`insufficient_evidence/NO_TECHNICAL_MAPPING`, а не положительный результат.
Никакой каталог не оценивает организацию целиком или не выдаёт сертификацию.

## CIS Benchmarks и применение

CIS Controls не переименовываются в продуктовый CIS Benchmark. Конкретные
benchmark/release/platform профили не встроены: нужны отдельно проверенные
редакция, область и права использования. Полные тексты и процедуры CIS не
копируются. [CIS публикует условия отдельно для продуктов и сервисов](https://www.cisecurity.org/terms-and-conditions-table-of-contents);
эта реализация не утверждает наличие лицензии на коммерческую перепубликацию.
PCI DSS и CSF2.0 не превращены в вымышленные ACL-профили.

Factory возвращает обычный immutable `ControlCatalogue`; его JSON можно явно
выбрать как `--catalogue` команды `controls assess` либо загрузить во вкладке
технических контролей. Профиль должен ссылаться на точные control IDs каталога.
Сохраняемый ControlAssessment содержит полный каталог/профиль/анализ, поэтому
новая версия ссылок не переписывает историю. CLI выбора готового factory и
встроенный selector каталога подключаются root отдельно.

Приёмка в `harness/tests/test_control_reference_catalogues.py`: точные редакции
и IDs, many-to-many, immutable/JSON snapshots, отсутствие fallback, missing и
неподдержанные процедуры, profile/finding evidence, сохранение internal default.
Данные только synthetic; EXE и реальные площадки этой задачей не проверяются.
