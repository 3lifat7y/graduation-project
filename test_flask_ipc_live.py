#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Live Integration Test: Flask Endpoints + DDoS-Guard Windows Service
Tests Flask's /api/adapter-info, /api/scan, and /api/scan-status with the live IPC server.
"""

import sys
import time
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from api import app, ipc_client

def test_flask_endpoints():
    print("=" * 70)
    print(">> Testing Flask Endpoints with Live Windows Service via IPC")
    print("=" * 70)

    client = app.test_client()

    # 1. Test /api/adapter-info
    print("\n1. GET /api/adapter-info:")
    res = client.get('/api/adapter-info')
    print(f"   HTTP Status: {res.status_code}")
    data = res.get_json()
    svc_online = data.get("driver_status", {}).get("service_online", False)
    active_engine = data.get("driver_status", {}).get("active_engine")
    print(f"   Service Online : {svc_online}")
    print(f"   Active Engine  : {active_engine}")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert svc_online is True, "Expected Windows Service to be online"

    # 2. Test /api/scan (initiates scan via Windows Service IPC)
    print("\n2. POST /api/scan:")
    scan_req = client.post('/api/scan', json={"duration": 1.5, "min_packets": 1})
    print(f"   HTTP Status: {scan_req.status_code}")
    scan_data = scan_req.get_json()
    scan_id = scan_data.get("scan_id")
    status = scan_data.get("status")
    print(f"   Scan ID : {scan_id}")
    print(f"   Status  : {status}")
    print(f"   Message : {scan_data.get('message')}")
    assert scan_req.status_code == 200, f"Expected 200, got {scan_req.status_code}"
    assert status == "scanning", f"Expected scanning, got {status}"

    # 3. Poll /api/scan-status
    print("\n3. Polling /api/scan-status...")
    time.sleep(2.0)
    status_req = client.get('/api/scan-status')
    status_data = status_req.get_json()
    final_status = status_data.get("status")
    final_error = status_data.get("error")
    msg = status_data.get("message")
    print(f"   Final Status : {final_status}")
    print(f"   Error        : {final_error}")
    print(f"   Message      : {msg}")

    # Ensure NO "Unauthorized IPC request" error occurred!
    assert final_error != "Unauthorized IPC request.", f"FAILED: Unauthorized IPC request returned: {status_data}"
    assert "Unauthorized IPC request" not in str(msg), f"FAILED: Unauthorized IPC request in message: {msg}"
    print("\n   [SUCCESS] Valid request was NOT rejected! Authorization succeeded!")

    print("\n" + "=" * 70)
    print(">> All Flask IPC integration tests PASSED successfully!")
    print("=" * 70)

if __name__ == "__main__":
    test_flask_endpoints()
