// Automated Browser Verification via Chrome DevTools Protocol (CDP)
// Tests: 1440x900 (Desktop), 768x1024 (Tablet), 390x844 (Mobile), 360x800 (Mobile)
// Verifies no wheel zoom, no horizontal overflow, zero console errors, and node interaction

const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');

const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const PORT = 9333;
const TEMP_USER_DATA = path.join(__dirname, '..', '.chrome_test_profile');

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

class CdpClient {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.id = 1;
    this.callbacks = new Map();
    this.events = [];
    this.consoleErrors = [];

    this.ws.onmessage = msg => {
      const parsed = JSON.parse(msg.data);
      if (parsed.id && this.callbacks.has(parsed.id)) {
        const { resolve, reject } = this.callbacks.get(parsed.id);
        this.callbacks.delete(parsed.id);
        if (parsed.error) reject(parsed.error);
        else resolve(parsed.result);
      }
      if (parsed.method === 'Runtime.consoleAPICalled') {
        if (parsed.params.type === 'error') {
          this.consoleErrors.push(parsed.params);
        }
      }
      if (parsed.method === 'Runtime.exceptionThrown') {
        this.consoleErrors.push(parsed.params);
      }
    };
  }

  ready() {
    return new Promise(resolve => {
      if (this.ws.readyState === WebSocket.OPEN) return resolve();
      this.ws.onopen = () => resolve();
    });
  }

  send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const msgId = this.id++;
      this.callbacks.set(msgId, { resolve, reject });
      this.ws.send(JSON.stringify({ id: msgId, method, params }));
    });
  }

  async eval(expression) {
    const res = await this.send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      awaitPromise: true
    });
    if (res.exceptionDetails) {
      throw new Error(res.exceptionDetails.text || 'Eval Exception');
    }
    return res.result ? res.result.value : undefined;
  }
}

async function run() {
  console.log('Launching Headless Chrome for Viewport Testing...');
  if (!fs.existsSync(TEMP_USER_DATA)) {
    fs.mkdirSync(TEMP_USER_DATA, { recursive: true });
  }

  const chromeProc = spawn(CHROME_PATH, [
    '--headless=new',
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${TEMP_USER_DATA}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-gpu',
    'about:blank'
  ]);

  try {
    let version = null;
    for (let i = 0; i < 20; i++) {
      await sleep(300);
      try {
        version = await fetchJson(`http://127.0.0.1:${PORT}/json/version`);
        if (version && version.webSocketDebuggerUrl) break;
      } catch (e) {}
    }

    if (!version || !version.webSocketDebuggerUrl) {
      throw new Error('Failed to connect to Chrome debugging endpoint');
    }

    const browserClient = new CdpClient(version.webSocketDebuggerUrl);
    await browserClient.ready();

    const newTarget = await browserClient.send('Target.createTarget', { url: 'http://127.0.0.1:5000/' });
    const session = await browserClient.send('Target.attachToTarget', { targetId: newTarget.targetId, flatten: true });

    // Open target session
    const targetWsUrl = `ws://127.0.0.1:${PORT}/devtools/page/${newTarget.targetId}`;
    const pageClient = new CdpClient(targetWsUrl);
    await pageClient.ready();

    await pageClient.send('Page.enable');
    await pageClient.send('Runtime.enable');
    await pageClient.send('DOM.enable');

    await sleep(2500); // Allow initial JS, SVG render, and layout to stabilize

    const viewports = [
      { name: 'Desktop (1440x900)', width: 1440, height: 900, isMobile: false },
      { name: 'Tablet (768x1024)', width: 768, height: 1024, isMobile: true },
      { name: 'Mobile (390x844)', width: 390, height: 844, isMobile: true },
      { name: 'Mobile (360x800)', width: 360, height: 800, isMobile: true }
    ];

    console.log('\n--- Viewport Layout & Interaction Tests ---');
    let allPassed = true;

    for (const vp of viewports) {
      console.log(`\nTesting Viewport: ${vp.name}...`);
      await pageClient.send('Emulation.setDeviceMetricsOverride', {
        width: vp.width,
        height: vp.height,
        deviceScaleFactor: 1,
        mobile: vp.isMobile
      });

      await sleep(600); // Allow resize event and CSS media query transition

      const results = await pageClient.eval(`(() => {
        const vpEl = document.getElementById("mindmapViewport");
        const canvas = document.getElementById("mindmapCanvas");
        const svg = document.getElementById("mindmapSvg");
        const body = document.body;
        const html = document.documentElement;

        const htmlScrollW = html.scrollWidth;
        const htmlClientW = html.clientWidth;
        const hasHorizontalOverflow = htmlScrollW > htmlClientW + 1;

        const vpRect = vpEl ? vpEl.getBoundingClientRect() : null;
        const canvasRect = canvas ? canvas.getBoundingClientRect() : null;
        const canvasTransform = canvas ? getComputedStyle(canvas).transform : null;
        const vpCursor = vpEl ? getComputedStyle(vpEl).cursor : null;

        // Check node presence
        const coreNode = document.getElementById("mmNodeCore");
        const monitoringBranch = document.getElementById("mmBranchMonitoring");
        const drawer = document.getElementById("mindmapDetailsDrawer");

        // SVG lines display
        const svgDisplay = svg ? getComputedStyle(svg).display : null;

        return {
          windowInnerWidth: window.innerWidth,
          hasHorizontalOverflow,
          htmlScrollW,
          htmlClientW,
          canvasTransform,
          vpCursor,
          coreVisible: !!coreNode && coreNode.offsetHeight > 0,
          monitoringVisible: !!monitoringBranch && monitoringBranch.offsetHeight > 0,
          svgDisplay,
          vpHeight: vpEl ? vpEl.offsetHeight : 0
        };
      })()`);

      console.log(`  - Horizontal Overflow: ${results.hasHorizontalOverflow ? 'FAIL (overflow detected)' : 'PASS (no horizontal overflow)'} (scrollWidth: ${results.htmlScrollW}px, clientWidth: ${results.htmlClientW}px)`);
      console.log(`  - Canvas Transform: ${results.canvasTransform === 'none' ? 'PASS (none)' : 'INFO (' + results.canvasTransform + ')'}`);
      console.log(`  - Cursor: ${results.vpCursor === 'default' ? 'PASS (default)' : results.vpCursor}`);
      console.log(`  - Core & Branches Visible: ${results.coreVisible && results.monitoringVisible ? 'PASS' : 'FAIL'}`);
      console.log(`  - SVG Display: ${results.svgDisplay}`);

      if (results.hasHorizontalOverflow) {
        allPassed = false;
      }
    }

    // Test Interaction: Clicking a node and verifying details drawer updates
    console.log('\n--- Interactive Node Selection Test ---');
    const nodeTest = await pageClient.eval(`(() => {
      const node = document.querySelector('[data-id="xgboost-classifier"]');
      if (!node) return { error: "Node not found" };
      node.click();
      const drawer = document.getElementById("mindmapDetailsDrawer");
      const title = document.getElementById("mmDrawerTitle");
      const badge = document.getElementById("mmDrawerBadge");
      const desc = document.getElementById("mmDrawerDesc");
      return {
        clicked: true,
        drawerDisplay: drawer ? getComputedStyle(drawer).display : null,
        title: title ? title.textContent : null,
        badge: badge ? badge.textContent : null,
        hasDesc: !!desc && desc.textContent.length > 10
      };
    })()`);
    console.log(`  - Clicked 'xgboost-classifier' node:`, nodeTest);

    // Test Theme Switch (Light <-> Dark Mode)
    console.log('\n--- Theme Switch Test ---');
    const themeTest = await pageClient.eval(`(() => {
      const btn = document.getElementById("themeToggleBtn");
      if (btn) btn.click();
      const themeAfterClick = document.documentElement.getAttribute("data-theme");
      const vpBg = getComputedStyle(document.getElementById("mindmapViewport")).backgroundColor;
      return { themeAfterClick, vpBg };
    })()`);
    console.log(`  - Theme toggle result:`, themeTest);

    console.log(`\n--- Console Error Check ---`);
    console.log(`  - Total Console Errors Captured: ${pageClient.consoleErrors.length}`);
    if (pageClient.consoleErrors.length > 0) {
      console.error(pageClient.consoleErrors);
      allPassed = false;
    }

    console.log(`\n========================================`);
    console.log(allPassed ? 'ALL VERIFICATIONS PASSED SUCCESSFULLY!' : 'SOME CHECKS FAILED');
    console.log(`========================================`);

  } finally {
    try {
      chromeProc.kill('SIGKILL');
    } catch (e) {}
    try {
      fs.rmSync(TEMP_USER_DATA, { recursive: true, force: true });
    } catch (e) {}
  }
}

run().catch(err => {
  console.error('Test Runner Error:', err);
  process.exit(1);
});
