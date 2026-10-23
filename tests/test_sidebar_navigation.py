"""
Test Suite for Cyber Dashboard Sidebar Navigation
Verifying all navigation transitions, DOM rendering, history management, and zero scan side effects.
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
    def __init__(self, port=9225):
        self.port = port
        self.user_data = os.path.join(os.environ["TEMP"], f"chrome_nav_test_{int(time.time()*1000)}")
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

        self.cmd_id = 0
        self.send("Page.enable")
        self.send("Runtime.enable")
        self.send("Console.enable")

    def send(self, method, params=None):
        self.cmd_id += 1
        cid = self.cmd_id
        msg = json.dumps({"id": cid, "method": method, "params": params or {}}).encode()
        mask = os.urandom(4)
        length = len(msg)
        if length < 126:
            header = struct.pack("!BB", 0x81, 0x80 | length)
        elif length < 65536:
            header = struct.pack("!BBH", 0x81, 0x80 | 126, length)
        else:
            header = struct.pack("!BBQ", 0x81, 0x80 | 127, length)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(msg))
        self.sock.sendall(header + mask + masked)
        return cid

    def recv_until(self, target_id, timeout=4.0):
        start = time.time()
        self.sock.settimeout(1.0)
        while time.time() - start < timeout:
            try:
                raw = self.sock.recv(65536)
                if not raw:
                    continue
                offset = 2
                b2 = raw[1]
                payload_len = b2 & 0x7F
                if payload_len == 126:
                    payload_len = struct.unpack("!H", raw[2:4])[0]
                    offset = 4
                elif payload_len == 127:
                    payload_len = struct.unpack("!Q", raw[2:10])[0]
                    offset = 10
                payload = raw[offset:offset+payload_len]
                parsed = json.loads(payload.decode('utf-8', errors='ignore'))
                if parsed.get("id") == target_id:
                    return parsed
            except Exception:
                continue
        return None

    def evaluate(self, script, timeout=4.0):
        cid = self.send("Runtime.evaluate", {"expression": script, "returnByValue": True})
        res = self.recv_until(cid, timeout=timeout)
        if res and "result" in res:
            return res["result"].get("result", {}).get("value")
        return None

    def navigate(self, url, wait_seconds=1.5):
        self.send("Page.navigate", {"url": url})
        time.sleep(wait_seconds)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass
        self.proc.terminate()
        self.proc.wait()


class TestSidebarNavigation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_proc = None
        server_ready = False
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

        cls.client = ChromeCDPClient(port=9225)
        cls.client.navigate(f"{BASE_URL}/")

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        if cls.server_proc:
            cls.server_proc.kill()

    def get_dom_view_state(self):
        script = """
        (function() {
            var monitorSec = document.getElementById('check-connection');
            var portSec = document.getElementById('port-scanner');
            var heroSec = document.getElementById('overview');
            var activeNav = document.querySelector('.sidebar-nav-item.active');
            
            return {
                bodyClasses: document.body.className,
                activeNav: activeNav ? activeNav.getAttribute('data-nav') : null,
                monitorVisible: monitorSec ? getComputedStyle(monitorSec).display !== 'none' : false,
                portVisible: portSec ? getComputedStyle(portSec).display !== 'none' : false,
                heroVisible: heroSec ? getComputedStyle(heroSec).display !== 'none' : false,
                url: window.location.href
            };
        })()
        """
        return self.client.evaluate(script)

    def test_01_initial_home_view(self):
        state = self.get_dom_view_state()
        self.assertTrue(state["heroVisible"], "Hero/Overview section must be visible on Home")
        self.assertFalse(state["monitorVisible"], "Live Monitoring section must be hidden on Home")
        self.assertFalse(state["portVisible"], "Port Scanner section must be hidden on Home")
        self.assertEqual(state["activeNav"], "home")

    def test_02_click_live_monitoring_renders_section(self):
        script = """
        (function() {
            var link = document.querySelector('.sidebar-nav-item[data-nav="monitoring"]');
            if (link) link.click();
        })()
        """
        self.client.evaluate(script)
        time.sleep(0.5)
        
        state = self.get_dom_view_state()
        self.assertTrue(state["monitorVisible"], "Live Monitoring section must be visible after click")
        self.assertFalse(state["heroVisible"], "Hero/Overview section must be hidden in dedicated Live Monitoring mode")
        self.assertFalse(state["portVisible"], "Port Scanner section must be hidden in dedicated Live Monitoring mode")
        self.assertEqual(state["activeNav"], "monitoring")
        self.assertIn("view=monitoring", state["url"])

    def test_03_click_port_scanner_renders_section(self):
        script = """
        (function() {
            var link = document.querySelector('.sidebar-nav-item[data-nav="port-scanner"]');
            if (link) link.click();
        })()
        """
        self.client.evaluate(script)
        time.sleep(0.5)
        
        state = self.get_dom_view_state()
        self.assertTrue(state["portVisible"], "Port Scanner section must be visible after click")
        self.assertFalse(state["monitorVisible"], "Live Monitoring section must be hidden in Port Scanner mode")
        self.assertFalse(state["heroVisible"], "Hero section must be hidden in Port Scanner mode")
        self.assertEqual(state["activeNav"], "port-scanner")
        self.assertIn("view=port-scanner", state["url"])

    def test_04_click_home_returns_to_overview(self):
        script = """
        (function() {
            var link = document.querySelector('.sidebar-nav-item[data-nav="home"]');
            if (link) link.click();
        })()
        """
        self.client.evaluate(script)
        time.sleep(0.5)
        
        state = self.get_dom_view_state()
        self.assertTrue(state["heroVisible"], "Hero section must be restored when returning Home")
        self.assertFalse(state["monitorVisible"], "Live Monitoring must be hidden on Home")
        self.assertFalse(state["portVisible"], "Port Scanner must be hidden on Home")
        self.assertEqual(state["activeNav"], "home")

    def test_05_repeated_switching_works_without_reload(self):
        for _ in range(3):
            # Click Live Monitoring
            self.client.evaluate("document.querySelector('.sidebar-nav-item[data-nav=\"monitoring\"]').click()")
            time.sleep(0.2)
            state_m = self.get_dom_view_state()
            self.assertTrue(state_m["monitorVisible"])
            self.assertFalse(state_m["heroVisible"])
            
            # Click Port Scanner
            self.client.evaluate("document.querySelector('.sidebar-nav-item[data-nav=\"port-scanner\"]').click()")
            time.sleep(0.2)
            state_p = self.get_dom_view_state()
            self.assertTrue(state_p["portVisible"])
            self.assertFalse(state_p["monitorVisible"])
            
            # Click Home
            self.client.evaluate("document.querySelector('.sidebar-nav-item[data-nav=\"home\"]').click()")
            time.sleep(0.2)
            state_h = self.get_dom_view_state()
            self.assertTrue(state_h["heroVisible"])
            self.assertFalse(state_h["monitorVisible"])

    def test_06_navigation_does_not_start_scan_automatically(self):
        # When navigating to Live Monitoring, scanning must remain standby/ready, not running
        self.client.evaluate("document.querySelector('.sidebar-nav-item[data-nav=\"monitoring\"]').click()")
        time.sleep(0.5)
        
        check_scan_script = """
        (function() {
            var checkBtn = document.getElementById('checkBtn');
            var stateBadge = document.getElementById('stateBadge');
            return {
                btnText: checkBtn ? checkBtn.innerText.trim() : null,
                badgeText: stateBadge ? stateBadge.innerText.trim() : null,
                badgeClass: stateBadge ? stateBadge.className : null
            };
        })()
        """
        scan_state = self.client.evaluate(check_scan_script)
        self.assertIn("Start Monitoring", scan_state["btnText"])
        self.assertIn("Ready", scan_state["badgeText"])

    def test_07_browser_popstate_navigation(self):
        # Navigate to port scanner, then use history.back()
        self.client.evaluate("document.querySelector('.sidebar-nav-item[data-nav=\"port-scanner\"]').click()")
        time.sleep(0.3)
        self.client.evaluate("window.history.back()")
        time.sleep(0.5)
        
        state = self.get_dom_view_state()
        self.assertTrue(state["monitorVisible"], "History back must restore previous Live Monitoring view")

    def test_08_direct_url_route_loading(self):
        # Direct URL loading of ?view=port-scanner
        self.client.navigate(f"{BASE_URL}/?view=port-scanner")
        time.sleep(0.5)
        state = self.get_dom_view_state()
        self.assertTrue(state["portVisible"], "Direct loading of ?view=port-scanner must display Port Scanner")
        self.assertFalse(state["heroVisible"], "Hero must be hidden when directly opening tool view")


if __name__ == "__main__":
    unittest.main()
