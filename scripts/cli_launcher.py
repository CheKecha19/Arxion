"""Console-only frozen entry point; importing it does not load any GUI runtime."""

import sys

from firewall_compliance.interfaces.cli.main import main

if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    main()
