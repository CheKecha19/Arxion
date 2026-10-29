"""Compatibility import for the relocated implementation."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("firewall_compliance.devices.network.hpe_h3c.comware.policy")
