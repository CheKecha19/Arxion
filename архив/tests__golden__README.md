> Исторические команды генераторов/smoke ниже не являются действующими инструкциями: update_golden.py, build_golden_candidates.py и desktop_integration_smoke.py отсутствуют в текущем scripts. Автопроверки по умолчанию в CI; локальный запуск и новые тесты — только по запросу согласно корневому AGENTS.md.

# Golden-тесты

Golden-файлы содержат ожидаемое JSON-представление нормализованных результатов. Обычные тесты только читают их и никогда не перезаписывают.

Обновление эталона допускается только после проверки изменения и через явную команду:

```powershell
python scripts/update_golden.py <кандидат.json> <эталон.json> --confirm
```

Файл-кандидат должен быть получен отдельно из проверяемого результата. Команда не запускается из pytest и не включается в CI.

Cisco ASA golden-файлы используют фиксированное время импорта из теста и обновляются только после ручной проверки всех различий и явного `--confirm`.

Golden-файлы `device_revision_*.json` используют фиксированные UUID, время наблюдения и SHA-256. Они отдельно фиксируют полную ревизию и ревизию с `unknown`/`unsupported` сетевыми данными.

Кандидаты текущих эталонов создаются отдельно:

```powershell
uv run python -m scripts.build_golden_candidates .golden-candidates-phase7
```

Эта команда записывает только `*.candidate.json`. После проверки каждого отличия эталон обновляется через `scripts/update_golden.py ... --confirm`. `firewall_assurance*.json` фиксируют все семь проверок полного synthetic Cisco ASA export и поведение при неподдержанном условии ACL.

`forwarding_policy_*.json` фиксируют восемь условных сценариев: ingress/global allow,
ingress/outbound deny, same-security deny, inbound/empty outbound implicit deny и
неизвестный effective NAT. UUID, время и хеши источников фиксированы. Полные
доказательства создаются собственными доменными fixtures, а не повышением полноты
конфигурационных excerpts. Egress условно задан вызывающей стороной; верхний status
всегда unknown/not_enough_evidence. Это не аппаратные эталоны packet-processing.
