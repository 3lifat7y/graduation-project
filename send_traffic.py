#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Traffic Simulation & Attack Generator
[Root Compatibility Shim]
Directly aliases `scripts.send_traffic` to ensure 100% backwards compatibility
with `simulate_attack.bat` and manual executions.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import scripts.send_traffic as _impl

for _k, _v in _impl.__dict__.items():
    if not _k.startswith("__"):
        globals()[_k] = _v

sys.modules[__name__] = _impl

if __name__ == '__main__':
    _impl.main()