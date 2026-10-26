#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
End-to-End Headless Chrome Acceptance Test Suite:
SCOUT Admin — Persistent Active Sidebar State and Platform Overview Heading

Tests real browser DOM, scrolling, navigation, aliases, theme toggle, and heading isolation.
"""

import os
import sys
import time
import json
import base64
import socket
import urllib.request
import subprocess
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PORT = 5025
BASE_URL = f"http://127.0.0.1:{PORT}"


class ChromeCDPClient:
    def __init__(self, port=9244):
        self.port = port
        self.user_data = os.path.join(os.environ["TEMP"], f"chrome_admin_active_test_{int(time.time()*1000)}")
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

        self._msg_id = 0

    def send_cmd(self, method, params=None):
        self._msg_id += 1
        msg = {"id": self._msg_id, "method": method, "params": params or {}}
        payload = json.dumps(msg).encode("utf-8")

        # Encode WS frame
        frame = bytearray([0x81])
        length = len(payload)
        if length <= 125:
            frame.append(0x80 | length)
        elif length <= 65535:
            frame.append(0x80 | 126)
            frame.extend(length.to_bytes(2, "big"))
        else:
            frame.append(0x80 | 127)
            frame.extend(length.to_bytes(8, "big"))

        mask = os.urandom(4)
        frame.extend(mask)
        masked_payload = bytearray(b ^ mask[i % 4] for i, b in enumerate(payload))
        frame.extend(masked_payload)

        self.sock.sendall(frame)

        # Read response
        while True:
            resp_data = self.sock.recv(65536)
            if not resp_data:
                return None
            idx = 2
            mask_present = bool(resp_data[1] & 0x80)
            pay_len = resp_data[1] & 0x7F
            if pay_len == 126:
                idx += 2
            elif pay_len == 127:
                idx += 8
            if mask_present:
                idx += 4
            text = resp_data[idx:].decode("utf-8", errors="ignore")
            for line in text.split("\n"):
                if line.strip():
                    try:
                        parsed = json.loads(line)
                        if parsed.get("id") == self._msg_id:
                            return parsed.get("result")
                    except Exception:
                        pass

    def navigate(self, url):
        self.send_cmd("Page.navigate", {"url": url})
        time.sleep(2.0)

    def evaluate(self, expression):
        res = self.send_cmd("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True
        })
        if res and "result" in res and "value" in res["result"]:
            return res["result"]["value"]
        return None

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass
        if self.proc:
            self.proc.kill()


def run_acceptance_tests():
    print("=" * 70)
    print("SCOUT Admin Acceptance Verification: Persistent Sidebar & Heading")
    print("=" * 70)

    # 1. Start test server
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    server_proc = subprocess.Popen([
        sys.executable, "api.py", "--port", str(PORT)
    ], cwd=str(PROJECT_ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    client = None
    try:
        # Wait for server
        for _ in range(25):
            time.sleep(1.0)
            try:
                req = urllib.request.urlopen(f"{BASE_URL}/api/service-status", timeout=1.0)
                if req.status == 200:
                    break
            except Exception:
                pass
        else:
            raise RuntimeError("Server failed to start on port " + str(PORT))

        print(f"Server is listening on {BASE_URL}")

        # Ensure admin user exists in DB
        from modules.auth.db import get_session_factory
        from modules.auth.models import User
        SessionFactory = get_session_factory()
        with SessionFactory() as session:
            admin = session.query(User).filter_by(username="admin_e2e").first()
            if not admin:
                admin = User(username="admin_e2e", email="admin_e2e@scout.local", role="Admin", is_active=True)
                admin.set_password("AdminPass123!")
                session.add(admin)
                session.commit()

        # Connect headless Chrome
        client = ChromeCDPClient(port=9244)
        print("Headless Chrome connected via CDP.")

        # Navigate to home
        client.navigate(f"{BASE_URL}/")

        # Log in as Admin via Javascript fetch
        login_res = client.evaluate("""
        (async () => {
            const res = await fetch("/api/auth/login", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({username: "admin_e2e", password: "AdminPass123!"}),
                credentials: "same-origin"
            });
            const data = await res.json();
            return {status: res.status, data: data};
        })()
        """)
        print(f"Login result: {login_res['status']}, user role: {login_res.get('data', {}).get('user', {}).get('role')}")
        assert login_res["status"] == 200, "Admin login failed"

        # Test 1: Open Platform Overview (?view=admin)
        print("\n--- Test 1: Platform Overview Initial Load & Active Sidebar ---")
        client.navigate(f"{BASE_URL}/?view=admin")
        time.sleep(1.5)

        state = client.evaluate("""
        (() => {
            const activeNav = document.querySelector('.sidebar-nav-item.active');
            const overviewPanel = document.getElementById('adminPanelOverview');
            const heading = overviewPanel ? overviewPanel.querySelector('h2.admin-dashboard-title') : null;
            return {
                activeNav: activeNav ? activeNav.getAttribute('data-nav') : null,
                overviewDisplay: overviewPanel ? getComputedStyle(overviewPanel).display : null,
                headingText: heading ? heading.textContent : null,
                bodyClass: document.body.className
            };
        })()
        """)
        print(f"State: {state}")
        assert state["activeNav"] == "admin", f"Expected activeNav 'admin', got {state['activeNav']}"
        assert state["overviewDisplay"] == "block", "adminPanelOverview must be visible"
        assert state["headingText"] == "SCOUT Administrative Console", "Heading text mismatch"
        print("[PASS] Platform Overview is active and displays 'SCOUT Administrative Console'.")

        # Test 2: Scroll to the bottom of Platform Overview
        print("\n--- Test 2: Persistent Highlight During Scrolling on Platform Overview ---")
        client.evaluate("""
        (() => {
            window.scrollTo(0, 3000);
            window.dispatchEvent(new Event('scroll'));
        })()
        """)
        time.sleep(0.5)

        state_after_scroll = client.evaluate("""
        (() => {
            const activeNav = document.querySelector('.sidebar-nav-item.active');
            return {
                scrollY: window.scrollY,
                activeNav: activeNav ? activeNav.getAttribute('data-nav') : null
            };
        })()
        """)
        print(f"State after scroll: {state_after_scroll}")
        assert state_after_scroll["activeNav"] == "admin", f"Expected activeNav to remain 'admin' after scroll, got {state_after_scroll['activeNav']}"
        print("[PASS] Active highlight remained on 'Platform Overview' during scrolling!")

        # Test 3 & 4: Open Users, verify highlight and scroll immunity
        print("\n--- Test 3 & 4: Users Section Navigation, Scroll & Heading Isolation ---")
        client.evaluate("""
        (() => {
            const usersLink = document.querySelector('.sidebar-nav-item[data-nav="admin-users"]');
            if (usersLink) usersLink.click();
        })()
        """)
        time.sleep(1.0)

        users_state = client.evaluate("""
        (() => {
            const activeNav = document.querySelector('.sidebar-nav-item.active');
            const usersPanel = document.getElementById('adminPanelUsers');
            const overviewPanel = document.getElementById('adminPanelOverview');
            const usersTitle = usersPanel ? usersPanel.querySelector('h3') : null;
            return {
                activeNav: activeNav ? activeNav.getAttribute('data-nav') : null,
                usersDisplay: usersPanel ? getComputedStyle(usersPanel).display : null,
                overviewDisplay: overviewPanel ? getComputedStyle(overviewPanel).display : null,
                usersTitle: usersTitle ? usersTitle.textContent : null,
                url: window.location.href
            };
        })()
        """)
        print(f"Users section state: {users_state}")
        assert users_state["activeNav"] == "admin-users", f"Expected activeNav 'admin-users', got {users_state['activeNav']}"
        assert users_state["usersDisplay"] == "block", "Users panel must be visible"
        assert users_state["overviewDisplay"] == "none", "Overview panel MUST be hidden"
        assert users_state["usersTitle"] == "Operator Accounts", "Users section title mismatch"
        print("[PASS] Users section is active. Overview panel has display: none.")

        # Scroll on Users page
        client.evaluate("""
        (() => {
            window.scrollTo(0, 2500);
            window.dispatchEvent(new Event('scroll'));
        })()
        """)
        time.sleep(0.5)
        users_scroll_state = client.evaluate("document.querySelector('.sidebar-nav-item.active')?.getAttribute('data-nav')")
        assert users_scroll_state == "admin-users", f"Highlight disappeared on scroll: {users_scroll_state}"
        print("[PASS] Users sidebar item remains active after scrolling.")

        # Test 5: Verify all other sections (Subscription Plans, Subscriptions, Requests, Audit, Profile)
        sections = [
            ("admin-plans", "adminPanelPlans", "Subscription Plans Catalog"),
            ("admin-subs", "adminPanelSubscriptions", "Global Subscription Registry"),
            ("admin-requests", "adminPanelRequests", "Pending Subscription Requests"),
            ("admin-audit", "adminPanelAudit", "Subscription Security Audit Log"),
            ("admin-profile", "adminPanelProfile", "Admin Profile & Account Security")
        ]
        for nav_key, panel_id, expected_h3 in sections:
            print(f"\n--- Testing Section: {nav_key} ---")
            client.evaluate(f"""
            (() => {{
                const link = document.querySelector('.sidebar-nav-item[data-nav="{nav_key}"]');
                if (link) link.click();
            }})()
            """)
            time.sleep(0.8)

            sec_state = client.evaluate(f"""
            (() => {{
                const activeNav = document.querySelector('.sidebar-nav-item.active');
                const panel = document.getElementById('{panel_id}');
                const overviewPanel = document.getElementById('adminPanelOverview');
                const h3 = panel ? panel.querySelector('h3') : null;
                return {{
                    activeNav: activeNav ? activeNav.getAttribute('data-nav') : null,
                    panelDisplay: panel ? getComputedStyle(panel).display : null,
                    overviewDisplay: overviewPanel ? getComputedStyle(overviewPanel).display : null,
                    h3Text: h3 ? h3.textContent : null
                }};
            }})()
            """)
            print(f"Section {nav_key} state: {sec_state}")
            assert sec_state["activeNav"] == nav_key, f"Expected {nav_key}, got {sec_state['activeNav']}"
            assert sec_state["panelDisplay"] == "block", f"Panel {panel_id} must be visible"
            assert sec_state["overviewDisplay"] == "none", f"Overview must be hidden when on {nav_key}"
            assert sec_state["h3Text"] == expected_h3, f"Expected {expected_h3}, got {sec_state['h3Text']}"

            # Scroll test on this section
            client.evaluate("window.scrollTo(0, 1500); window.dispatchEvent(new Event('scroll'));")
            time.sleep(0.3)
            after_scroll_nav = client.evaluate("document.querySelector('.sidebar-nav-item.active')?.getAttribute('data-nav')")
            assert after_scroll_nav == nav_key, f"Expected {nav_key} after scroll, got {after_scroll_nav}"
            print(f"[PASS] Section {nav_key} persistent highlight verified during scrolling.")

        # Test 6: Route Aliases (?view=admin-operators and ?view=admin-subscriptions)
        print("\n--- Test 6: Route Aliases Normalization ---")
        client.navigate(f"{BASE_URL}/?view=admin-operators")
        time.sleep(1.0)
        alias_state = client.evaluate("""
        (() => {
            const activeNav = document.querySelector('.sidebar-nav-item.active');
            const usersPanel = document.getElementById('adminPanelUsers');
            return {
                activeNav: activeNav ? activeNav.getAttribute('data-nav') : null,
                usersDisplay: usersPanel ? getComputedStyle(usersPanel).display : null
            };
        })()
        """)
        assert alias_state["activeNav"] == "admin-users", f"admin-operators alias failed: {alias_state['activeNav']}"
        assert alias_state["usersDisplay"] == "block"
        print("[PASS] Route alias ?view=admin-operators correctly highlights 'admin-users'.")

        client.navigate(f"{BASE_URL}/?view=admin-subscriptions")
        time.sleep(1.0)
        sub_alias_state = client.evaluate("""
        (() => {
            const activeNav = document.querySelector('.sidebar-nav-item.active');
            const subsPanel = document.getElementById('adminPanelSubscriptions');
            return {
                activeNav: activeNav ? activeNav.getAttribute('data-nav') : null,
                subsDisplay: subsPanel ? getComputedStyle(subsPanel).display : null
            };
        })()
        """)
        assert sub_alias_state["activeNav"] == "admin-subs", f"admin-subscriptions alias failed: {sub_alias_state['activeNav']}"
        assert sub_alias_state["subsDisplay"] == "block"
        print("[PASS] Route alias ?view=admin-subscriptions correctly highlights 'admin-subs'.")

        # Test 7: Browser Back and Forward Navigation
        print("\n--- Test 7: Browser Back and Forward Navigation ---")
        client.evaluate("history.back();")
        time.sleep(1.0)
        back_state = client.evaluate("document.querySelector('.sidebar-nav-item.active')?.getAttribute('data-nav')")
        print(f"After history.back(): {back_state}")
        assert back_state == "admin-users", f"Expected admin-users after back, got {back_state}"

        client.evaluate("history.forward();")
        time.sleep(1.0)
        forward_state = client.evaluate("document.querySelector('.sidebar-nav-item.active')?.getAttribute('data-nav')")
        print(f"After history.forward(): {forward_state}")
        assert forward_state == "admin-subs", f"Expected admin-subs after forward, got {forward_state}"
        print("[PASS] Browser Back and Forward correctly updates active sidebar highlight!")

        # Test 8: Light Mode and Dark Mode Contrast
        print("\n--- Test 8: Light Mode and Dark Mode Contrast ---")
        # Light mode
        client.evaluate("document.documentElement.setAttribute('data-theme', 'light');")
        time.sleep(0.3)
        light_styles = client.evaluate("""
        (() => {
            const item = document.querySelector('.sidebar-nav-item.active');
            const icon = item ? item.querySelector('.nav-icon') : null;
            const computedItem = item ? getComputedStyle(item) : null;
            const computedIcon = icon ? getComputedStyle(icon) : null;
            return {
                bg: computedItem ? computedItem.backgroundColor : null,
                color: computedItem ? computedItem.color : null,
                iconColor: computedIcon ? computedIcon.color : null,
                boxShadow: computedItem ? computedItem.boxShadow : null
            };
        })()
        """)
        print(f"Light mode active styles: {light_styles}")
        # rgb(24, 24, 27) is #18181B
        assert "24, 24, 27" in light_styles["bg"], f"Expected #18181B bg in light mode, got {light_styles['bg']}"
        # icon should be rgb(163, 230, 53) -> #A3E635
        assert "163, 230, 53" in light_styles["iconColor"], f"Expected lime icon in light mode, got {light_styles['iconColor']}"
        print("[PASS] Light Mode active state verified (deep dark pill with vibrant lime icon and accent indicator).")

        # Dark mode
        client.evaluate("document.documentElement.setAttribute('data-theme', 'dark');")
        time.sleep(0.3)
        dark_styles = client.evaluate("""
        (() => {
            const item = document.querySelector('.sidebar-nav-item.active');
            const icon = item ? item.querySelector('.nav-icon') : null;
            const computedItem = item ? getComputedStyle(item) : null;
            const computedIcon = icon ? getComputedStyle(icon) : null;
            return {
                bg: computedItem ? computedItem.backgroundColor : null,
                color: computedItem ? computedItem.color : null,
                iconColor: computedIcon ? computedIcon.color : null
            };
        })()
        """)
        print(f"Dark mode active styles: {dark_styles}")
        # rgb(163, 230, 53) is #A3E635
        assert "163, 230, 53" in dark_styles["bg"], f"Expected lime bg in dark mode, got {dark_styles['bg']}"
        assert "9, 9, 11" in dark_styles["color"], f"Expected dark text in dark mode, got {dark_styles['color']}"
        print("[PASS] Dark Mode active state verified (vibrant lime pill with dark contrast text and icon).")

        # Test 9: Mouse Hover / Mouse Leave State Preservation
        print("\n--- Test 9: Mouse Hover and Leave Preservation ---")
        client.evaluate("""
        (() => {
            const otherItem = document.querySelector('.sidebar-nav-item[data-nav="admin-plans"]');
            if (otherItem) {
                otherItem.dispatchEvent(new MouseEvent('mouseenter'));
            }
        })()
        """)
        time.sleep(0.3)
        # Verify active item is still active
        hover_check = client.evaluate("document.querySelector('.sidebar-nav-item.active')?.getAttribute('data-nav')")
        assert hover_check == "admin-subs", f"Active item changed during hover: {hover_check}"

        client.evaluate("""
        (() => {
            const otherItem = document.querySelector('.sidebar-nav-item[data-nav="admin-plans"]');
            if (otherItem) {
                otherItem.dispatchEvent(new MouseEvent('mouseleave'));
            }
        })()
        """)
        time.sleep(0.3)
        leave_check = client.evaluate("document.querySelector('.sidebar-nav-item.active')?.getAttribute('data-nav')")
        assert leave_check == "admin-subs", f"Active item lost on mouseleave: {leave_check}"
        print("[PASS] Hovering other items and mouse leave does not remove or alter active item state.")

        # Test 10: Collapsing and Reopening Sidebar
        print("\n--- Test 10: Sidebar Collapse and Reopen ---")
        client.evaluate("document.body.classList.add('sidebar-collapsed');")
        time.sleep(0.3)
        collapse_check = client.evaluate("document.querySelector('.sidebar-nav-item.active')?.getAttribute('data-nav')")
        assert collapse_check == "admin-subs", "Active item lost on collapse"

        client.evaluate("document.body.classList.remove('sidebar-collapsed');")
        time.sleep(0.3)
        reopen_check = client.evaluate("document.querySelector('.sidebar-nav-item.active')?.getAttribute('data-nav')")
        assert reopen_check == "admin-subs", "Active item lost on reopen"
        print("[PASS] Active item preserved across sidebar collapse and reopen.")

        # Test 11: Refreshing Page Maintains Correct Item
        print("\n--- Test 11: Page Refresh Persistence ---")
        client.navigate(f"{BASE_URL}/?view=admin-audit")
        time.sleep(1.0)
        pre_refresh = client.evaluate("document.querySelector('.sidebar-nav-item.active')?.getAttribute('data-nav')")
        assert pre_refresh == "admin-audit"

        client.navigate(f"{BASE_URL}/?view=admin-audit")
        time.sleep(1.5)
        post_refresh = client.evaluate("document.querySelector('.sidebar-nav-item.active')?.getAttribute('data-nav')")
        assert post_refresh == "admin-audit", f"Expected admin-audit after refresh, got {post_refresh}"
        print("[PASS] Page refresh persistently maintains the active sidebar item!")

        print("\n" + "=" * 70)
        print("ALL 12 ACCEPTANCE TESTS PASSED SUCCESSFULLY!")
        print("=" * 70)

    finally:
        if client:
            client.close()
        if server_proc:
            server_proc.kill()


if __name__ == "__main__":
    run_acceptance_tests()
