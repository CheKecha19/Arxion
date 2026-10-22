"""Точка входа Windows-сборки."""

import sys
from pathlib import Path

if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--self-test":
        output_dir = Path(sys.argv[2])
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            from firewall_compliance.interfaces.desktop.packaged_smoke import run_packaged_smoke

            run_packaged_smoke(output_dir)
        except Exception:
            import traceback

            (output_dir / "self-test-error.txt").write_text(
                traceback.format_exc(), encoding="utf-8"
            )
            raise
    else:
        from firewall_compliance.interfaces.desktop.qt_app import main

        main()
