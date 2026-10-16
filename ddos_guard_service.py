#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Windows Service & Secure Local IPC Capture Engine
[Root Compatibility Shim]
Directly aliases `modules.monitoring.service` to ensure 100% identical module
namespace, shared globals, and seamless compatibility with Windows SCM Registry.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import modules.monitoring.service as _impl

for _k, _v in _impl.__dict__.items():
    if not _k.startswith("__"):
        globals()[_k] = _v

sys.modules[__name__] = _impl

if __name__ == '__main__':
    _impl.main()
