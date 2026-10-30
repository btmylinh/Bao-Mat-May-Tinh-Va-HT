import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createApp } from '../src/app.js';
import { tamperBuffer } from '../src/crypto/cryptoService.js';
import { closeDatabase } from '../src/db/database.js';

const PORT = 3000;
const CDP_PORT = 9333;
const VIEWPORT_WIDTH = 1440;
const VIEWPORT_HEIGHT = 900;
const OUTPUT_DIR = path.resolve(process.cwd(), 'test-results');

const BROWSER_CANDIDATES = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
];

function findBrowserExecutable() {
  for (const candidate of BROWSER_CANDIDATES) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error('Could not find Chrome or Edge executable on this machine.');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForCdpTarget(cdpPort, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${cdpPort}/json/list`);
      if (res.ok) {
        const targets = await res.json();
        const pageTarget = targets.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
        if (pageTarget) {
          return pageTarget.webSocketDebuggerUrl;
        }
      }
    } catch {
      // Wait for browser to initialize CDP endpoint
    }
    await sleep(150);
  }
  throw new Error(`Timed out waiting for CDP target on port ${cdpPort}`);
}

class CdpSession {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  async connect() {
    this.ws = new WebSocket(this.wsUrl);
    await new Promise((resolve, reject) => {
      this.ws.addEventListener('open', () => resolve(), { once: true });
      this.ws.addEventListener('error', (err) => reject(err), { once: true });
    });

    this.ws.addEventListener('message', (event) => {
      try {
        const msg = JSON.parse(String(event.data));
        if (msg.id && this.pending.has(msg.id)) {
          const { resolve, reject } = this.pending.get(msg.id);
          this.pending.delete(msg.id);
          if (msg.error) {
            reject(new Error(`CDP error (${msg.error.code}): ${msg.error.message}`));
          } else {
            resolve(msg.result);
          }
        }
      } catch {
        // Ignore non-JSON messages
      }
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  async evaluate(expression) {
    const res = await this.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (res?.exceptionDetails) {
      throw new Error(
        `Runtime.evaluate exception: ${res.exceptionDetails.text || JSON.stringify(res.exceptionDetails)}`
      );
    }
    return res?.result?.value;
  }

  async capturePng(outputPath) {
    const { data } = await this.send('Page.captureScreenshot', {
      format: 'png',
      fromSurface: true,
      captureBeyondViewport: false,
    });
    fs.writeFileSync(outputPath, Buffer.from(data, 'base64'));
  }

  close() {
    try {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.close();
      }
    } catch {
      // Ignore close errors
    }
  }
}

async function waitForCondition(cdp, predicateExpr, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ok = await cdp.evaluate(predicateExpr);
    if (ok) return true;
    await sleep(100);
  }
  throw new Error(`Timed out waiting for condition: ${predicateExpr}`);
}

async function runUiCapture() {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  const tempStorageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zt-vault-ui-e2e-'));
  const tempUserDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zt-vault-chrome-'));

  let server = null;
  let browserProcess = null;
  let cdp = null;

  try {
    const app = createApp({
      dbPath: ':memory:',
      storageDir: tempStorageDir,
    });

    let activePort = PORT;
    await new Promise((resolve, reject) => {
      server = app.listen(0, '127.0.0.1', () => {
        activePort = server.address().port;
        resolve();
      });
      server.once('error', (err) => reject(err));
    });
    const baseUrl = `http://127.0.0.1:${activePort}`;
    console.log(`[UI-E2E] Express server listening on ${baseUrl}`);

    const browserExe = findBrowserExecutable();
    console.log(`[UI-E2E] Launching headless browser: ${browserExe}`);

    browserProcess = spawn(
      browserExe,
      [
        '--headless=new',
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-extensions',
        '--hide-scrollbars',
        `--window-size=${VIEWPORT_WIDTH},${VIEWPORT_HEIGHT}`,
        `--remote-debugging-port=${CDP_PORT}`,
        `--user-data-dir=${tempUserDataDir}`,
        'about:blank',
      ],
      { stdio: 'ignore' }
    );

    const wsUrl = await waitForCdpTarget(CDP_PORT);
    cdp = new CdpSession(wsUrl);
    await cdp.connect();

    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: VIEWPORT_WIDTH,
      height: VIEWPORT_HEIGHT,
      deviceScaleFactor: 1,
      mobile: false,
    });

    await cdp.send('Page.navigate', { url: baseUrl });

    // Wait for initial public lookup preview to be ready
    await waitForCondition(
      cdp,
      `Boolean(!document.getElementById('recipient-preview-card')?.classList.contains('hidden'))`
    );
    await sleep(350);
    await cdp.evaluate(`document.getElementById('toast-container')?.replaceChildren()`);

    // =========================================================================
    // 1) dack_01_login_uc01.png: Màn hình Đăng nhập hệ thống dành cho Người phát hành (UC01)
    // =========================================================================
    console.log('[UI-E2E] Scenario 1: Capturing Issuer Login Modal (dack_01_login_uc01.png)...');
    await cdp.evaluate(`document.getElementById('btn-open-issuer-login')?.click()`);
    await waitForCondition(
      cdp,
      `Boolean(!document.getElementById('login-modal')?.classList.contains('hidden'))`
    );
    await sleep(300);
    await cdp.evaluate(`document.getElementById('toast-container')?.replaceChildren()`);

    const shot1Path = path.join(OUTPUT_DIR, 'dack_01_login_uc01.png');
    await cdp.capturePng(shot1Path);
    console.log(`[UI-E2E] Saved screenshot 1 -> ${shot1Path}`);

    // =========================================================================
    // 2) dack_02_issuer_dashboard_uc03.png: Bảng điều khiển Quản lý danh mục kho văn bản (UC03)
    // =========================================================================
    console.log('[UI-E2E] Scenario 2: Submitting Login -> Issuer Catalog Dashboard (dack_02_issuer_dashboard_uc03.png)...');
    await cdp.evaluate(`document.getElementById('btn-submit-login')?.click()`);
    await waitForCondition(
      cdp,
      `Boolean(
        !document.getElementById('issuer-dashboard-view')?.classList.contains('hidden') &&
        document.querySelectorAll('#issuer-docs-tbody tr').length >= 1
      )`
    );
    await sleep(350);
    await cdp.evaluate(`document.getElementById('toast-container')?.replaceChildren()`);

    const activeDocId = await cdp.evaluate(
      `(Array.from(document.querySelectorAll('#issuer-docs-tbody tr')).find((tr) => tr.dataset.docCode === 'VB-2026-0001') || document.querySelector('#issuer-docs-tbody tr'))?.dataset?.docId || ''`
    );

    const shot2Path = path.join(OUTPUT_DIR, 'dack_02_issuer_dashboard_uc03.png');
    await cdp.capturePng(shot2Path);
    console.log(`[UI-E2E] Saved screenshot 2 -> ${shot2Path}`);

    // =========================================================================
    // 3) dack_03_upload_and_share_uc02_uc04.png: Hộp thoại Tải lên & Lưu trữ (UC02) + Tạo liên kết chia sẻ (UC04)
    // =========================================================================
    console.log('[UI-E2E] Scenario 3: Capturing Upload & Share Modal (dack_03_upload_and_share_uc02_uc04.png)...');
    await cdp.evaluate(`document.querySelector('.btn-row-share')?.click()`);
    await waitForCondition(
      cdp,
      `Boolean(
        !document.getElementById('upload-share-modal')?.classList.contains('hidden') &&
        document.getElementById('share-link-output')?.value?.includes('?share=')
      )`
    );
    await sleep(350);
    await cdp.evaluate(`document.getElementById('toast-container')?.replaceChildren()`);

    const shot3Path = path.join(OUTPUT_DIR, 'dack_03_upload_and_share_uc02_uc04.png');
    await cdp.capturePng(shot3Path);
    console.log(`[UI-E2E] Saved screenshot 3 -> ${shot3Path}`);

    await cdp.evaluate(`document.getElementById('btn-close-upload-modal')?.click()`);

    // =========================================================================
    // 4) dack_04_recipient_lookup_preview_uc05_uc06_uc07.png: Cổng Tra cứu & Tiếp nhận văn bản cho Khách (UC05, UC06, UC07)
    // =========================================================================
    console.log('[UI-E2E] Scenario 4: Logout to Public Recipient Portal -> Empty lookup input with placeholder + Online Preview + Download (dack_04_recipient_lookup_preview_uc05_uc06_uc07.png)...');
    await cdp.evaluate(`document.getElementById('btn-logout-issuer')?.click()`);
    await cdp.evaluate(`handleLookupDocument('VB-2026-0001', { populateInput: false })`);
    await cdp.evaluate(`document.getElementById('lookup-query-input').value = ''`);

    await waitForCondition(
      cdp,
      `Boolean(
        !document.getElementById('recipient-portal-view')?.classList.contains('hidden') &&
        !document.getElementById('recipient-preview-card')?.classList.contains('hidden') &&
        document.getElementById('preview-doc-code')?.textContent === 'VB-2026-0001'
      )`
    );
    await sleep(350);
    await cdp.evaluate(`document.getElementById('toast-container')?.replaceChildren()`);

    const shot4Path = path.join(
      OUTPUT_DIR,
      'dack_04_recipient_lookup_preview_uc05_uc06_uc07.png'
    );
    await cdp.capturePng(shot4Path);
    console.log(`[UI-E2E] Saved screenshot 4 -> ${shot4Path}`);

    // =========================================================================
    // 5) dack_05_error_blocked.png: Thông báo từ chối truy cập gọn gàng khi tệp hoặc liên kết không hợp lệ
    // =========================================================================
    console.log('[UI-E2E] Scenario 5: External tamper on storage file -> Lookup blocked with clean error notice (dack_05_error_blocked.png)...');
    const encFilePath = path.join(tempStorageDir, `${activeDocId}.enc`);
    const origBytes = fs.readFileSync(encFilePath);
    fs.writeFileSync(encFilePath, tamperBuffer(origBytes, 4));
    await cdp.evaluate(`document.getElementById('lookup-query-input').value = 'VB-2026-0001'`);
    await cdp.evaluate(`document.getElementById('btn-lookup-doc')?.click()`);

    await waitForCondition(
      cdp,
      `Boolean(
        !document.getElementById('portal-global-notice')?.classList.contains('hidden') &&
        document.getElementById('portal-notice-text')?.textContent?.includes('Không thể mở tệp')
      )`
    );
    await sleep(350);
    await cdp.evaluate(`document.getElementById('toast-container')?.replaceChildren()`);

    const shot5Path = path.join(OUTPUT_DIR, 'dack_05_error_blocked.png');
    await cdp.capturePng(shot5Path);
    console.log(`[UI-E2E] Saved screenshot 5 -> ${shot5Path}`);
  } finally {
    if (cdp) {
      cdp.close();
    }
    if (browserProcess) {
      try {
        browserProcess.kill('SIGKILL');
      } catch {
        // Ignore
      }
      if (process.platform === 'win32' && browserProcess.pid) {
        try {
          spawn('taskkill', ['/PID', String(browserProcess.pid), '/T', '/F'], {
            stdio: 'ignore',
          });
        } catch {
          // Ignore
        }
      }
    }
    if (server) {
      await new Promise((resolve) => server.close(() => resolve()));
    }
    closeDatabase();

    await sleep(400);
    for (const dir of [tempStorageDir, tempUserDataDir]) {
      try {
        if (dir && fs.existsSync(dir)) {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      } catch {
        // Ignore transient lock cleanup error
      }
    }
    console.log('[UI-E2E] Cleanup complete (Browser killed, Server closed, SQLite closed).');
  }
}

runUiCapture().catch((err) => {
  console.error('[UI-E2E] Fatal error:', err);
  process.exitCode = 1;
});
