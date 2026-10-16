#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Independent Local Network Discovery Engine
[Root Compatibility Shim]
Directly aliases `modules.network_discovery.discovery` to ensure 100% identical module
namespace, shared globals, and seamless unittest.mock patch support.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import modules.network_discovery.discovery as _impl

for _k, _v in _impl.__dict__.items():
    if not _k.startswith("__"):
        globals()[_k] = _v

sys.modules[__name__] = _impl

if __name__ == '__main__':
    if hasattr(_impl, 'main'):
        _impl.main()
    else:
        print("DDoS-Guard Network Discovery Module Loaded Successfully.")
