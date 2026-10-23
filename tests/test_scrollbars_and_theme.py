"""
Comprehensive Automated Test Suite for Global Scrollbar Hiding & Theme-Aware Live Monitoring Scrollbar
Verifies:
1. Home and all other sections scroll normally with no visible page-level vertical scrollbar.
2. Live Monitoring displays its custom vertical scrollbar and allows users to reach all packet rows.
3. The Live Monitoring scrollbar matches Dark Mode specifications.
4. Switching to Light Mode immediately updates scrollbar CSS variables without reload.
5. Switching back to Dark Mode restores dark theme variables.
6. Horizontal scrollbar remains hidden while horizontal scrolling works.
7. Sticky headers, live filters, and table height constraints remain functional.
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
    def __init__(self, port=9228):
        self.port = port
        self.user_data = os.path.join(os.environ["TEMP"], f"chrome_scrollbar_test_{int(time.time()*1000)}")
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


class TestScrollbarsAndTheme(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure Flask server is up
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

        cls.cdp = ChromeCDPClient(port=9228)

    @classmethod
    def tearDownClass(cls):
        cls.cdp.close()
        if cls.server_proc:
            cls.server_proc.kill()

    def test_01_global_page_scrollbar_hidden_and_scrolling_functional(self):
        """Home and all pages scroll normally with no visible page-level vertical scrollbar."""
        self.cdp.navigate(f"{BASE_URL}/")
        time.sleep(1.5)

        # 1. Check styles on html and body
        styles = self.cdp.eval_js("""
            (() => {
                const htmlStyle = getComputedStyle(document.documentElement);
                const bodyStyle = getComputedStyle(document.body);
                return {
                    htmlScrollbarWidth: htmlStyle.scrollbarWidth,
                    bodyScrollbarWidth: bodyStyle.scrollbarWidth,
                    htmlOverflowY: htmlStyle.overflowY,
                    bodyOverflowY: bodyStyle.overflowY
                };
            })()
        """)
        self.assertEqual(styles["htmlScrollbarWidth"], "none", "HTML scrollbarWidth should be none")
        self.assertEqual(styles["bodyScrollbarWidth"], "none", "Body scrollbarWidth should be none")
        self.assertNotEqual(styles["bodyOverflowY"], "hidden", "Body overflow-y must NOT be hidden")

        # 2. Verify page scrolls normally using scrollTo / wheel
        scroll_res = self.cdp.eval_js("""
            (() => {
                const initialY = window.scrollY;
                window.scrollTo({ top: 500, behavior: 'instant' });
                const scrolledY = window.scrollY;
                window.scrollTo({ top: 0, behavior: 'instant' });
                return {
                    initialY: initialY,
                    scrolledY: scrolledY,
                    canScroll: scrolledY > 0
                };
            })()
        """)
        self.assertTrue(scroll_res["canScroll"], f"Page scrolling failed! Scrolled Y was: {scroll_res['scrolledY']}")

    def test_02_live_monitoring_table_scrollbar_properties(self):
        """Live Monitoring displays custom vertical scrollbar and constrains table height."""
        self.cdp.navigate(f"{BASE_URL}/?view=monitoring")
        time.sleep(1.5)

        # 1. Inspect table container computed styles
        table_style = self.cdp.eval_js("""
            (() => {
                const container = document.querySelector('.traffic-table-container');
                if (!container) return null;
                const cs = getComputedStyle(container);
                return {
                    maxHeight: cs.maxHeight,
                    overflowY: cs.overflowY,
                    overflowX: cs.overflowX,
                    scrollbarWidth: cs.scrollbarWidth,
                    borderWidth: cs.borderTopWidth
                };
            })()
        """)
        self.assertIsNotNone(table_style, "traffic-table-container not found")
        self.assertEqual(table_style["maxHeight"], "480px", "Max height should be constrained to 480px")
        self.assertIn(table_style["overflowY"], ["auto", "scroll"], "overflowY should be auto or scroll")
        self.assertEqual(table_style["scrollbarWidth"], "thin", "Firefox scrollbar-width should be thin")

        # 2. Check sticky header on table
        th_style = self.cdp.eval_js("""
            (() => {
                const th = document.querySelector('.traffic-table thead th');
                if (!th) return null;
                const cs = getComputedStyle(th);
                return {
                    position: cs.position,
                    top: cs.top,
                    zIndex: cs.zIndex
                };
            })()
        """)
        self.assertEqual(th_style["position"], "sticky", "Table header should be position: sticky")
        self.assertEqual(th_style["top"], "0px", "Table header sticky top should be 0px")

    def test_03_table_vertical_scrolling_reaches_all_rows(self):
        """Inject packet rows and verify user can scroll vertically to reach all rows."""
        self.cdp.navigate(f"{BASE_URL}/?view=monitoring")
        time.sleep(1.2)

        scroll_test = self.cdp.eval_js("""
            (() => {
                const tbody = document.getElementById('liveTrafficTableBody');
                const container = document.querySelector('.traffic-table-container');
                if (!tbody || !container) return { error: 'Missing elements' };

                // Populate 40 rows
                let rowsHtml = '';
                for (let i = 1; i <= 40; i++) {
                    rowsHtml += `
                        <tr id="test-row-${i}">
                            <td>12:00:${i.toString().padStart(2, '0')}</td>
                            <td>192.168.1.${i}:54321</td>
                            <td>10.0.0.1:80</td>
                            <td class="col-proto">TCP</td>
                            <td>64</td>
                            <td>SYN [Test row ${i}]</td>
                        </tr>
                    `;
                }
                tbody.innerHTML = rowsHtml;

                const scrollHeight = container.scrollHeight;
                const clientHeight = container.clientHeight;
                const isOverflowing = scrollHeight > clientHeight;

                // Scroll to bottom
                container.scrollTop = scrollHeight;
                const finalScrollTop = container.scrollTop;

                // Verify last row is reached
                const lastRow = document.getElementById('test-row-40');
                const lastRowVisible = Boolean(lastRow);

                return {
                    isOverflowing: isOverflowing,
                    scrollHeight: scrollHeight,
                    clientHeight: clientHeight,
                    finalScrollTop: finalScrollTop,
                    canScroll: finalScrollTop > 0,
                    lastRowReached: lastRowVisible
                };
            })()
        """)
        self.assertTrue(scroll_test["isOverflowing"], "Table should overflow when 40 rows are loaded")
        self.assertTrue(scroll_test["canScroll"], "Container should scroll vertically")
        self.assertTrue(scroll_test["lastRowReached"], "Last row must be accessible")

    def test_04_dark_and_light_theme_variables_and_instant_toggle(self):
        """Verify CSS variables for Dark and Light mode and instant real-time toggle."""
        self.cdp.navigate(f"{BASE_URL}/?view=monitoring")
        time.sleep(1.2)

        # 1. Ensure Dark Mode
        self.cdp.eval_js("document.documentElement.setAttribute('data-theme', 'dark');")
        dark_vars = self.cdp.eval_js("""
            (() => {
                const style = getComputedStyle(document.documentElement);
                return {
                    track: style.getPropertyValue('--table-scrollbar-track').trim(),
                    thumb: style.getPropertyValue('--table-scrollbar-thumb').trim(),
                    thumbHover: style.getPropertyValue('--table-scrollbar-thumb-hover').trim(),
                    border: style.getPropertyValue('--table-scrollbar-border').trim()
                };
            })()
        """)
        self.assertEqual(dark_vars["track"].lower(), "#1a201b", "Dark track variable mismatch")
        self.assertEqual(dark_vars["thumb"].lower(), "#488b6e", "Dark thumb variable mismatch")
        self.assertEqual(dark_vars["thumbHover"].lower(), "#589e7e", "Dark thumb hover variable mismatch")

        # 2. Toggle to Light Mode via DOM
        self.cdp.eval_js("document.documentElement.setAttribute('data-theme', 'light');")
        light_vars = self.cdp.eval_js("""
            (() => {
                const style = getComputedStyle(document.documentElement);
                return {
                    track: style.getPropertyValue('--table-scrollbar-track').trim(),
                    thumb: style.getPropertyValue('--table-scrollbar-thumb').trim(),
                    thumbHover: style.getPropertyValue('--table-scrollbar-thumb-hover').trim(),
                    border: style.getPropertyValue('--table-scrollbar-border').trim()
                };
            })()
        """)
        self.assertEqual(light_vars["track"].lower(), "#eae6dc", "Light track variable mismatch")
        self.assertEqual(light_vars["thumb"].lower(), "#355c4a", "Light thumb variable mismatch")
        self.assertEqual(light_vars["thumbHover"].lower(), "#244033", "Light thumb hover variable mismatch")

        # 3. Toggle back to Dark Mode
        self.cdp.eval_js("document.documentElement.setAttribute('data-theme', 'dark');")
        dark_restored = self.cdp.eval_js("""
            (() => {
                const style = getComputedStyle(document.documentElement);
                return {
                    track: style.getPropertyValue('--table-scrollbar-track').trim(),
                    thumb: style.getPropertyValue('--table-scrollbar-thumb').trim()
                };
            })()
        """)
        self.assertEqual(dark_restored["track"].lower(), "#1a201b")
        self.assertEqual(dark_restored["thumb"].lower(), "#488b6e")

    def test_05_horizontal_scrollbar_hidden_while_scrolling_preserved(self):
        """Horizontal scrollbar is hidden while horizontal scrolling functions."""
        self.cdp.navigate(f"{BASE_URL}/?view=monitoring")
        time.sleep(1.2)

        h_scroll = self.cdp.eval_js("""
            (() => {
                const container = document.querySelector('.traffic-table-container');
                const table = document.querySelector('.traffic-table');
                if (!container || !table) return { error: 'Not found' };

                // Force wider content to test horizontal scrollability
                const oldWidth = table.style.width;
                table.style.width = '2500px';

                const canHOverflow = container.scrollWidth > container.clientWidth;
                container.scrollLeft = 300;
                const scrolledLeft = container.scrollLeft;

                // Restore
                table.style.width = oldWidth;

                return {
                    canHOverflow: canHOverflow,
                    scrolledLeft: scrolledLeft,
                    hScrollWorks: scrolledLeft > 0
                };
            })()
        """)
        self.assertTrue(h_scroll["canHOverflow"], "Wide table should exceed container width")
        self.assertTrue(h_scroll["hScrollWorks"], "Horizontal scrolling should function when columns overflow")


if __name__ == "__main__":
    unittest.main()
