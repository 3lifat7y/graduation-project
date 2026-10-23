"""
Test Suite for Live Monitoring Lifecycle Across Section Navigation
Verifies that packet capture runs continuously across Home, Port Scanning, Network Discovery,
and page reloads, reconnects seamlessly upon return, avoids duplicate workers, and only stops
on explicit user Stop action.
"""

import subprocess
import time
import json
import urllib.request
import socket
import base64
import os
import struct
import unittest

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
BASE_URL = "http://127.0.0.1:5000"


class ChromeCDPClient:
    def __init__(self, port=9226):
        self.port = port
        self.user_data = os.path.join(os.environ["TEMP"], f"chrome_lifecycle_test_{int(time.time()*1000)}")
        os.makedirs(self.user_data, exist_ok=True)
        self.proc = subprocess.Popen([
            CHROME_PATH,
            "--headless=new",
            f"--remote-debugging-port={self.port}",
            f"--user-data-dir={self.user_data}",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2.0)

        req = urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json")
        pages = json.loads(req.read().decode())
        page = [p for p in pages if p.get("type") == "page"][0]
        ws_url = page["webSocketDebuggerUrl"]

        host, port_num = "127.0.0.1", self.port
        path = ws_url.split(f"{host}:{port_num}")[1]

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port_num))

        key = base64.b64encode(os.urandom(16)).decode()
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port_num}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(handshake.encode())
        resp = self.sock.recv(4096)
        if b"101" not in resp:
            raise RuntimeError(f"WS handshake failed: {resp}")

        self.msg_id = 0

    def send_cdp(self, method, params=None):
        self.msg_id += 1
        msg = {"id": self.msg_id, "method": method, "params": params or {}}
        data = json.dumps(msg).encode()

        frame = bytearray()
        frame.append(0x81)
        length = len(data)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack(">H", length))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack(">Q", length))

        mask = os.urandom(4)
        frame.extend(mask)
        masked_data = bytearray(b ^ mask[i % 4] for i, b in enumerate(data))
        frame.extend(masked_data)

        self.sock.sendall(frame)

        while True:
            hdr = self.sock.recv(2)
            if not hdr:
                raise RuntimeError("Socket closed")
            plen = hdr[1] & 0x7F
            if plen == 126:
                ext = self.sock.recv(2)
                plen = struct.unpack(">H", ext)[0]
            elif plen == 127:
                ext = self.sock.recv(8)
                plen = struct.unpack(">Q", ext)[0]
            payload = bytearray()
            while len(payload) < plen:
                chunk = self.sock.recv(plen - len(payload))
                if not chunk:
                    break
                payload.extend(chunk)

            try:
                res = json.loads(payload.decode(errors="ignore"))
                if res.get("id") == self.msg_id:
                    return res.get("result", {})
            except Exception:
                pass

    def eval_js(self, expr):
        res = self.send_cdp("Runtime.evaluate", {
            "expression": expr,
            "returnByValue": True,
            "awaitPromise": True
        })
        val = res.get("result", {}).get("value")
        exc = res.get("exceptionDetails")
        if exc:
            raise RuntimeError(f"JS Exception: {exc}")
        return val

    def navigate(self, url):
        self.send_cdp("Page.navigate", {"url": url})
        time.sleep(1.8)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass
        self.proc.kill()


class TestCaptureLifecycleNavigation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure Flask server is up and responsive
        server_ready = False
        cls.server_proc = None
        try:
            req = urllib.request.urlopen(f"{BASE_URL}/api/service-status", timeout=1.0)
            if req.status == 200:
                server_ready = True
        except Exception:
            server_ready = False

        if not server_ready:
            cls.server_proc = subprocess.Popen([
                r".venv\Scripts\python.exe", "api.py"
            ], cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            for _ in range(15):
                time.sleep(1.0)
                try:
                    req = urllib.request.urlopen(f"{BASE_URL}/api/service-status", timeout=1.0)
                    if req.status == 200:
                        server_ready = True
                        break
                except Exception:
                    pass

        # Make sure previous capture session is stopped cleanly before testing
        try:
            req = urllib.request.Request(f"{BASE_URL}/api/scan-stop", data=b"{}", headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=2.0)
        except Exception:
            pass

        cls.cdp = ChromeCDPClient(port=9227)

    @classmethod
    def tearDownClass(cls):
        try:
            req = urllib.request.Request(f"{BASE_URL}/api/scan-stop", data=b"{}", headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=2.0)
        except Exception:
            pass
        cls.cdp.close()
        if cls.server_proc:
            cls.server_proc.kill()

    def get_backend_status(self):
        req = urllib.request.urlopen(f"{BASE_URL}/api/scan-status")
        return json.loads(req.read().decode())

    def test_01_start_monitoring_activates_capture(self):
        """Click Start Monitoring and verify active packet capture session in backend."""
        self.cdp.navigate(f"{BASE_URL}/?view=monitoring")
        time.sleep(1.5)

        # Click Start Monitoring
        click_res = self.cdp.eval_js("""
            (() => {
                const btn = document.getElementById('checkBtn');
                if (btn && !btn.disabled) {
                    btn.click();
                    return { clicked: true };
                }
                return { clicked: false, disabled: btn ? btn.disabled : true };
            })()
        """)
        self.assertTrue(click_res.get("clicked"), "Failed to click checkBtn")

        # Wait for backend session to become active
        active = False
        scan_id = None
        for _ in range(10):
            time.sleep(0.5)
            st = self.get_backend_status()
            if st.get("status") in ["scanning", "starting", "monitoring", "prediction_available", "no_traffic", "insufficient_traffic"]:
                active = True
                scan_id = st.get("scan_id")
                self.assertTrue(st.get("is_active"), "Backend is_active flag should be True")
                break

        self.assertTrue(active, f"Backend session did not become active: {st.get('status')}")
        self.assertIsNotNone(scan_id, "Scan ID was not generated")

    def test_02_in_page_navigation_preserves_capture(self):
        """Navigate to Home and Port Scanner inside the SPA; verify capture keeps running."""
        st_before = self.get_backend_status()
        initial_scan_id = st_before.get("scan_id")
        self.assertTrue(st_before.get("is_active"), "Expected active capture before in-page nav")

        # 1. Navigate to Home
        self.cdp.eval_js("""
            (() => {
                const homeItem = document.querySelector('.sidebar-nav-item[data-nav="home"]');
                if (homeItem) homeItem.click();
            })()
        """)
        time.sleep(1.0)
        st_home = self.get_backend_status()
        self.assertTrue(st_home.get("is_active"), "Capture stopped when navigating to Home!")
        self.assertEqual(st_home.get("scan_id"), initial_scan_id, "Scan ID changed on Home navigation")

        # 2. Navigate to Port Scanner
        self.cdp.eval_js("""
            (() => {
                const psItem = document.querySelector('.sidebar-nav-item[data-nav="port-scanner"]');
                if (psItem) psItem.click();
            })()
        """)
        time.sleep(1.0)
        st_ps = self.get_backend_status()
        self.assertTrue(st_ps.get("is_active"), "Capture stopped when navigating to Port Scanner!")
        self.assertEqual(st_ps.get("scan_id"), initial_scan_id, "Scan ID changed on Port Scanner navigation")

        # 3. Return to Live Monitoring
        self.cdp.eval_js("""
            (() => {
                const monItem = document.querySelector('.sidebar-nav-item[data-nav="monitoring"]');
                if (monItem) monItem.click();
            })()
        """)
        time.sleep(1.2)

        # Verify UI state re-attached cleanly
        ui_state = self.cdp.eval_js("""
            (() => {
                const badge = document.getElementById('stateBadge');
                const stopBtn = document.getElementById('stopBtn');
                const checkBtn = document.getElementById('checkBtn');
                return {
                    badgeText: badge ? badge.textContent.trim() : null,
                    stopVisible: stopBtn ? stopBtn.style.display !== 'none' : false,
                    checkDisabled: checkBtn ? checkBtn.disabled : false
                };
            })()
        """)
        self.assertTrue(ui_state["stopVisible"], "Stop button should remain visible on return to monitoring")
        self.assertTrue(ui_state["checkDisabled"], "Start button should remain disabled (active monitoring)")
        self.assertIn(ui_state["badgeText"], ["Monitoring", "Starting...", "No Traffic Detected", "Insufficient Data"],
                      "Badge text not in active monitoring states")

    def test_03_external_navigation_to_network_discovery_preserves_capture(self):
        """Navigate to /network-discovery; confirm capture continues (no beforeunload stop)."""
        st_before = self.get_backend_status()
        initial_scan_id = st_before.get("scan_id")
        self.assertTrue(st_before.get("is_active"), "Expected active capture before ND nav")

        # Navigate to full page /network-discovery
        self.cdp.navigate(f"{BASE_URL}/network-discovery")
        time.sleep(1.5)

        # Confirm backend capture continues uninterrupted
        st_nd = self.get_backend_status()
        self.assertTrue(st_nd.get("is_active"), "Capture stopped during navigation to /network-discovery!")
        self.assertEqual(st_nd.get("scan_id"), initial_scan_id, "Scan ID changed on /network-discovery")

        # Return to Live Monitoring
        self.cdp.navigate(f"{BASE_URL}/?view=monitoring")
        time.sleep(1.5)

        # Verify frontend automatically reconnected to the running session
        st_return = self.get_backend_status()
        self.assertTrue(st_return.get("is_active"), "Capture stopped upon returning to monitoring")
        self.assertEqual(st_return.get("scan_id"), initial_scan_id)

        ui_state = self.cdp.eval_js("""
            (() => {
                const badge = document.getElementById('stateBadge');
                const stopBtn = document.getElementById('stopBtn');
                const checkBtn = document.getElementById('checkBtn');
                return {
                    badgeText: badge ? badge.textContent.trim() : null,
                    stopVisible: stopBtn ? stopBtn.style.display !== 'none' : false,
                    checkDisabled: checkBtn ? checkBtn.disabled : false
                };
            })()
        """)
        self.assertTrue(ui_state["stopVisible"], "Stop button must be visible after reconnecting from full page reload")
        self.assertTrue(ui_state["checkDisabled"], "Check button must be disabled after reconnecting")

    def test_04_duplicate_start_handling(self):
        """Ensure calling start while already scanning reconnects safely without duplicate threads."""
        st_before = self.get_backend_status()
        active_id = st_before.get("scan_id")

        # Post /api/scan without force_restart
        req = urllib.request.Request(
            f"{BASE_URL}/api/scan",
            data=json.dumps({"continuous": True}).encode(),
            headers={"Content-Type": "application/json"}
        )
        res = json.loads(urllib.request.urlopen(req).read().decode())
        self.assertEqual(res.get("status"), "already_scanning")
        self.assertEqual(res.get("scan_id"), active_id, "Should preserve existing scan_id")
        self.assertTrue(res.get("is_active"))

    def test_05_explicit_user_stop_terminates_capture(self):
        """Verify that clicking the Stop button terminates capture and releases resources."""
        self.cdp.navigate(f"{BASE_URL}/?view=monitoring")
        time.sleep(1.2)

        stop_res = self.cdp.eval_js("""
            (() => {
                const btn = document.getElementById('stopBtn');
                if (btn && btn.style.display !== 'none' && !btn.disabled) {
                    btn.click();
                    return { clicked: true };
                }
                return { clicked: false, display: btn ? btn.style.display : null, disabled: btn ? btn.disabled : null };
            })()
        """)
        self.assertTrue(stop_res.get("clicked"), "Failed to click stopBtn")
        time.sleep(1.5)

        st_after = self.get_backend_status()
        self.assertEqual(st_after.get("status"), "stopped", "Session did not transition to stopped")
        self.assertFalse(st_after.get("is_active"), "is_active should be False after explicit stop")

        ui_state = self.cdp.eval_js("""
            (() => {
                const badge = document.getElementById('stateBadge');
                const stopBtn = document.getElementById('stopBtn');
                const checkBtn = document.getElementById('checkBtn');
                return {
                    badgeText: badge ? badge.textContent.trim() : null,
                    stopVisible: stopBtn ? stopBtn.style.display !== 'none' : false,
                    checkDisabled: checkBtn ? checkBtn.disabled : false
                };
            })()
        """)
        self.assertFalse(ui_state["stopVisible"], "Stop button should be hidden after stop")
        self.assertFalse(ui_state["checkDisabled"], "Start button should be enabled after stop")
        self.assertIn(ui_state["badgeText"], ["Stopped", "Ready"])


if __name__ == "__main__":
    unittest.main()
