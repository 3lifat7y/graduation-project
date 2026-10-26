"""
Real Google Chrome E2E Browser Test for SCOUT Standalone Authentication Flows
Uses Chrome DevTools Protocol (CDP) directly via Python standard library.
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
    def __init__(self, port=9333):
        self.port = port
        self.user_data = os.path.join(os.environ["TEMP"], f"chrome_auth_e2e_{int(time.time()*1000)}")
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

            res = json.loads(payload.decode("utf-8", errors="ignore"))
            if res.get("id") == self.msg_id:
                return res.get("result", {})

    def eval_js(self, expression):
        res = self.send_cdp("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True
        })
        if "exceptionDetails" in res:
            raise RuntimeError(f"JS Exception: {res['exceptionDetails']}")
        return res.get("result", {}).get("value")

    def navigate(self, url, wait_seconds=1.5):
        self.send_cdp("Page.navigate", {"url": url})
        time.sleep(wait_seconds)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


class TestBrowserAuthFlows(unittest.TestCase):
    server_proc = None

    @classmethod
    def setUpClass(cls):
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

        cls.cdp = ChromeCDPClient(port=9333)

    @classmethod
    def tearDownClass(cls):
        cls.cdp.close()
        if cls.server_proc:
            cls.server_proc.terminate()
            try:
                cls.server_proc.wait(timeout=3)
            except Exception:
                cls.server_proc.kill()

    def test_01_homepage_to_login_flow(self):
        """1. Anonymous visitor opens Homepage, clicks Sign In, arrives at standalone /login."""
        self.cdp.navigate(f"{BASE_URL}/?public=1", wait_seconds=2.0)

        # Confirm floating modal does not exist
        modal_exists = self.cdp.eval_js("document.getElementById('authModal') !== null")
        self.assertFalse(modal_exists, "authModal overlay must not exist in homepage DOM")

        # Click Sign In button
        self.cdp.eval_js("document.getElementById('headerSignInBtn').click()")
        time.sleep(1.5)

        current_url = self.cdp.eval_js("window.location.href")
        self.assertTrue(current_url.endswith("/login"), f"Expected /login, got {current_url}")

    def test_02_login_page_theme_toggle_and_navigation(self):
        """2. Verify theme toggle changes data-theme and Home Page button returns to Homepage."""
        self.cdp.navigate(f"{BASE_URL}/login", wait_seconds=1.5)

        # Check navigation elements exist
        theme_btn_exists = self.cdp.eval_js("document.getElementById('themeToggleBtn') !== null")
        home_btn_exists = self.cdp.eval_js("document.getElementById('homePageBtn') !== null")
        self.assertTrue(theme_btn_exists, "themeToggleBtn must exist in top-left")
        self.assertTrue(home_btn_exists, "homePageBtn must exist in top-right")

        # Initial theme
        initial_theme = self.cdp.eval_js("document.documentElement.getAttribute('data-theme')")
        self.assertIn(initial_theme, ["light", "dark"])

        # Click theme toggle
        self.cdp.eval_js("document.getElementById('themeToggleBtn').click()")
        time.sleep(0.3)
        toggled_theme = self.cdp.eval_js("document.documentElement.getAttribute('data-theme')")
        expected_toggled = "dark" if initial_theme == "light" else "light"
        self.assertEqual(toggled_theme, expected_toggled)

        # Click Home Page button
        self.cdp.eval_js("document.getElementById('homePageBtn').click()")
        time.sleep(1.5)
        home_url = self.cdp.eval_js("window.location.href")
        self.assertTrue("?public=1" in home_url or home_url.endswith("/"), f"Expected homepage, got {home_url}")

    def test_03_login_validation_and_successful_admin_login(self):
        """3. Test empty submission feedback, password toggle, and successful admin login redirect."""
        self.cdp.navigate(f"{BASE_URL}/login", wait_seconds=1.5)

        # Empty submit validation
        self.cdp.eval_js("document.getElementById('loginSubmitBtn').click()")
        time.sleep(0.3)
        alert_visible = self.cdp.eval_js("document.getElementById('authAlert').style.display !== 'none'")
        alert_text = self.cdp.eval_js("document.getElementById('authAlertMessage').textContent")
        self.assertTrue(alert_visible)
        self.assertIn("Please enter", alert_text)

        # Enter credentials
        self.cdp.eval_js("document.getElementById('loginIdentifier').value = 'admin_scout'")
        self.cdp.eval_js("document.getElementById('loginPassword').value = 'AdminPass#2026'")

        # Test password toggle
        pwd_type_before = self.cdp.eval_js("document.getElementById('loginPassword').type")
        self.assertEqual(pwd_type_before, "password")
        self.cdp.eval_js("document.getElementById('togglePasswordBtn').click()")
        pwd_type_after = self.cdp.eval_js("document.getElementById('loginPassword').type")
        self.assertEqual(pwd_type_after, "text")
        self.cdp.eval_js("document.getElementById('togglePasswordBtn').click()")

        # Submit login
        self.cdp.eval_js("document.getElementById('loginSubmitBtn').click()")
        time.sleep(1.8)

        # Verify redirect to admin view
        final_url = self.cdp.eval_js("window.location.href")
        self.assertIn("view=admin", final_url)

    def test_04_register_page_guidance_and_submission(self):
        """4. Test /register: no username field, required Full Name/Email/Phone, complexity, and creation."""
        self.cdp.navigate(f"{BASE_URL}/register", wait_seconds=1.5)

        # Verify Username field is completely absent from DOM
        has_username = self.cdp.eval_js("document.getElementById('regUsername') !== null")
        self.assertFalse(has_username, "Visible/DOM Username field must not exist on register page")

        # Verify required fields exist with correct types
        has_full_name = self.cdp.eval_js("document.getElementById('regFullName') !== null")
        has_email = self.cdp.eval_js("document.getElementById('regEmail') !== null")
        phone_el = self.cdp.eval_js("(() => { const p = document.getElementById('regPhone'); return p ? { exists: true, type: p.type } : { exists: false }; })()")
        
        self.assertTrue(has_full_name, "regFullName must exist")
        self.assertTrue(has_email, "regEmail must exist")
        self.assertTrue(phone_el["exists"], "regPhone must exist")
        self.assertEqual(phone_el["type"], "tel", "regPhone type must be 'tel'")

        # Verify registration title
        reg_title = self.cdp.eval_js("document.querySelector('.auth-title').textContent")
        self.assertIn("Create", reg_title)

        # Type weak password
        self.cdp.eval_js("(() => { const p = document.getElementById('regPassword'); p.value = 'abc'; p.dispatchEvent(new Event('input')); })()")
        time.sleep(0.2)
        len_valid = self.cdp.eval_js("document.getElementById('pwdRuleLength').classList.contains('valid')")
        self.assertFalse(len_valid, "Weak password should not satisfy length rule")

        # Type complex password
        self.cdp.eval_js("(() => { const p = document.getElementById('regPassword'); p.value = 'CyberAnalyst#2026'; p.dispatchEvent(new Event('input')); })()")
        time.sleep(0.2)
        len_valid = self.cdp.eval_js("document.getElementById('pwdRuleLength').classList.contains('valid')")
        case_valid = self.cdp.eval_js("document.getElementById('pwdRuleCase').classList.contains('valid')")
        num_valid = self.cdp.eval_js("document.getElementById('pwdRuleNumSpecial').classList.contains('valid')")
        self.assertTrue(len_valid)
        self.assertTrue(case_valid)
        self.assertTrue(num_valid)

        # Fill mismatched confirm password and submit
        ts = int(time.time())
        full_name = f"Browser Analyst {ts}"
        email = f"analyst_{ts}@defense.corp"
        phone = f"+1 (555) {ts % 900 + 100}-9988"
        self.__class__.test_email = email
        self.__class__.test_phone = phone
        self.__class__.test_password = "CyberAnalyst#2026"

        self.cdp.eval_js(f"document.getElementById('regFullName').value = '{full_name}'")
        self.cdp.eval_js(f"document.getElementById('regEmail').value = '{email}'")
        self.cdp.eval_js(f"document.getElementById('regPhone').value = '{phone}'")
        self.cdp.eval_js("document.getElementById('regConfirmPassword').value = 'MismatchPass#999'")

        self.cdp.eval_js("document.getElementById('registerSubmitBtn').click()")
        time.sleep(0.3)
        alert_text = self.cdp.eval_js("document.getElementById('authAlertMessage').textContent")
        self.assertIn("match", alert_text.lower())

        # Correct confirm password and submit
        self.cdp.eval_js("document.getElementById('regConfirmPassword').value = 'CyberAnalyst#2026'")
        self.cdp.eval_js("document.getElementById('registerSubmitBtn').click()")
        time.sleep(2.0)

        # Successfully redirected to plans
        final_url = self.cdp.eval_js("window.location.href")
        self.assertIn("view=plans", final_url)

    def test_05_dual_login_email_and_phone(self):
        """5. Verify logging in with Email, logging out, and logging in with Phone authenticate same user."""
        email = getattr(self.__class__, "test_email", None)
        phone = getattr(self.__class__, "test_phone", None)
        password = getattr(self.__class__, "test_password", None)
        self.assertIsNotNone(email, "Must run after registration test")

        # 1. Log out first
        self.cdp.eval_js("fetch('/api/auth/logout', { method: 'POST' })")
        time.sleep(0.5)

        # 2. Log in using Email
        self.cdp.navigate(f"{BASE_URL}/login", wait_seconds=1.5)
        self.cdp.eval_js(f"document.getElementById('loginIdentifier').value = '{email}'")
        self.cdp.eval_js(f"document.getElementById('loginPassword').value = '{password}'")
        self.cdp.eval_js("document.getElementById('loginSubmitBtn').click()")
        time.sleep(1.8)

        # Check authenticated user ID
        user_via_email = self.cdp.eval_js("""
            (async () => {
                const res = await fetch('/api/auth/me');
                const data = await res.json();
                return data.user || {};
            })()
        """)
        self.assertEqual(user_via_email.get("email"), email.lower())
        user_id_email = user_via_email.get("id")

        # 3. Log out again
        self.cdp.eval_js("fetch('/api/auth/logout', { method: 'POST' })")
        time.sleep(0.5)

        # 4. Log in using Phone Number (with punctuation and country code)
        self.cdp.navigate(f"{BASE_URL}/login", wait_seconds=1.5)
        self.cdp.eval_js(f"document.getElementById('loginIdentifier').value = '{phone}'")
        self.cdp.eval_js(f"document.getElementById('loginPassword').value = '{password}'")
        self.cdp.eval_js("document.getElementById('loginSubmitBtn').click()")
        time.sleep(1.8)

        # Check authenticated user ID
        user_via_phone = self.cdp.eval_js("""
            (async () => {
                const res = await fetch('/api/auth/me');
                const data = await res.json();
                return data.user || {};
            })()
        """)
        user_id_phone = user_via_phone.get("id")

        self.assertEqual(user_id_email, user_id_phone, "Email and Phone login must authenticate the exact same user ID")
        self.assertEqual(user_via_phone.get("email"), email.lower())


if __name__ == "__main__":
    unittest.main()
