"""Compatibility import for the relocated implementation."""

import sys
from importlib import import_module

sys.modules[__name__] = import_module("firewall_compliance.devices.ngfw.cisco.asa.common")
