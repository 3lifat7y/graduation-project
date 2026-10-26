#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCOUT: Dedicated Live Network Traffic Generator
[Root Compatibility Shim]
Directly aliases `scripts.send_live_traffic` to ensure seamless execution
from root as well as scripts directory.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import scripts.send_live_traffic as _impl

for _k, _v in _impl.__dict__.items():
    if not _k.startswith("__"):
        globals()[_k] = _v

sys.modules[__name__] = _impl

if __name__ == '__main__':
    _impl.main()
