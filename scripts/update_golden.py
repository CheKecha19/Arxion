"""Явное обновление JSON golden-файла после ручной проверки различий."""

import argparse
import json
from pathlib import Path


def main() -> int:
    """Проверить JSON-кандидат и записать его в указанный golden-файл."""
    parser = argparse.ArgumentParser(description="Явно обновить JSON golden-файл.")
    parser.add_argument("candidate", type=Path, help="Проверенный JSON-кандидат.")
    parser.add_argument("destination", type=Path, help="Путь к обновляемому golden-файлу.")
    parser.add_argument("--confirm", action="store_true", help="Подтвердить перезапись эталона.")
    args = parser.parse_args()

    if not args.confirm:
        parser.error("для обновления golden-файла требуется --confirm")

    candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.destination.write_text(
        json.dumps(candidate, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
