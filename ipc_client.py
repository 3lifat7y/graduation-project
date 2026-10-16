#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Secure Local IPC Client
[Root Compatibility Shim]
Directly aliases `modules.monitoring.ipc_client` to ensure 100% identical module
namespace, shared globals, and seamless unittest.mock patch support.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import modules.monitoring.ipc_client as _impl

for _k, _v in _impl.__dict__.items():
    if not _k.startswith("__"):
        globals()[_k] = _v

sys.modules[__name__] = _impl

if __name__ == '__main__':
    client = _impl.DDoSGuardIPCClient()
    print("IPC Service running:", client.is_service_running())
