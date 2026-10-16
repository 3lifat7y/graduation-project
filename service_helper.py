#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Windows Service Helper & Scoped UAC Elevation Manager
[Root Compatibility Shim]
Directly aliases `modules.monitoring.service_helper` to ensure 100% identical module
namespace, shared globals, and seamless unittest.mock patch support.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import modules.monitoring.service_helper as _impl

# Populate globals for static inspection
for _k, _v in _impl.__dict__.items():
    if not _k.startswith("__"):
        globals()[_k] = _v

# Bind sys.modules to the canonical implementation
sys.modules[__name__] = _impl

if __name__ == '__main__':
    st = _impl.get_service_status()
    print("Service Status:", st)
