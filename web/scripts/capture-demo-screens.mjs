import { spawn } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isWin = process.platform === 'win32';
const venvPython = path.resolve(__dirname, '../../.venv/Scripts/python.exe');
const pythonExe = fs.existsSync(venvPython) ? venvPython : (isWin ? 'python' : 'python3');
const backendDir = path.resolve(__dirname, '../../backend');
const screensDir = path.resolve(__dirname, '../../docs/QA/screens');

if (!fs.existsSync(screensDir)) {
  fs.mkdirSync(screensDir, { recursive: true });
}

console.log('[CAPTURE] Starting demo backend on http://127.0.0.1:8000...');
const server = spawn(
  pythonExe,
  ['-m', 'uvicorn', 'cyberq.api.app:app', '--host', '127.0.0.1', '--port', '8000'],
  {
    cwd: backendDir,
    env: {
      ...process.env,
      CYBERQ_ENV: 'demo',
      PYTHONPATH: path.resolve(backendDir, 'src'),
    },
    stdio: 'ignore',
  }
);

async function waitForBackend(maxTries = 30) {
  for (let i = 0; i < maxTries; i++) {
    try {
      const res = await fetch('http://127.0.0.1:8000/healthz');
      if (res.ok) {
        const json = await res.json();
        if (json.environment === 'demo') {
          console.log('[CAPTURE] Backend healthy in demo mode.');
          return true;
        }
      }
    } catch {
      // Retry
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('Backend failed to start in time');
}

async function run() {
  try {
    await waitForBackend();

    const browser = await chromium.launch({
      headless: true,
      args: ['--use-gl=angle', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'],
    });

    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

    // Initial load
    await page.goto('http://127.0.0.1:8000/?demo=1');
    await page.waitForLoadState('networkidle');

    const roleSelect = page.getByLabel('Viewing as role selection');
    await roleSelect.waitFor({ state: 'visible', timeout: 5000 });

    const switchRole = async (role) => {
      const respPromise = page.waitForResponse(
        (res) => res.url().includes('/auth/login') && res.status() === 200,
        { timeout: 5000 }
      ).catch(() => {});
      await roleSelect.selectOption(role);
      await respPromise;
      await page.waitForTimeout(600);
    };

    // 1. Analyst View
    console.log('[CAPTURE] 1. Switching to Analyst...');
    await switchRole('analyst');
    const triageTab = page.getByRole('button', { name: /Incident triage/i });
    if (await triageTab.isVisible()) await triageTab.click();
    await page.waitForTimeout(800);
    await page.screenshot({ path: path.join(screensDir, 'role_analyst.png') });

    // 2. CISO View (Command Center)
    console.log('[CAPTURE] 2. Switching to CISO...');
    await switchRole('ciso');
    if (await triageTab.isVisible()) await triageTab.click();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(screensDir, 'role_ciso.png') });

    // 3. CISO Decisions View
    console.log('[CAPTURE] 3. Navigating to /decisions as CISO...');
    const decisionsNav = page.locator("aside button[title*='Statutory Decision Ledger']");
    await decisionsNav.click();
    await page.waitForTimeout(1200);
    await page.screenshot({ path: path.join(screensDir, 'role_ciso_decisions.png') });

    // 4. Compliance Approver View
    console.log('[CAPTURE] 4. Switching to Compliance Approver...');
    const cmdNav = page.locator("aside button[title*='Command Center']");
    await cmdNav.click();
    await page.waitForTimeout(600);
    await switchRole('compliance_approver');
    if (await triageTab.isVisible()) await triageTab.click();
    await page.waitForTimeout(800);
    await page.screenshot({ path: path.join(screensDir, 'role_compliance.png') });

    // 5. Auditor View (/activity)
    console.log('[CAPTURE] 5. Switching to Auditor & navigating to /activity...');
    await switchRole('auditor');
    const activityNav = page.locator("aside button[title*='Activity & Audit Chain']");
    await activityNav.click();
    await page.waitForTimeout(1200);
    const verifyBtn = page.getByRole('button', { name: /Verify audit chain/i });
    if (await verifyBtn.isEnabled()) {
      await verifyBtn.click();
      await page.waitForTimeout(1200);
    }
    await page.screenshot({ path: path.join(screensDir, 'role_auditor.png') });

    // 6. Admin View (/admin)
    console.log('[CAPTURE] 6. Switching to Admin & navigating to /admin...');
    await switchRole('admin');
    const adminNav = page.locator("aside button[title*='System Administration & Telemetry']");
    await adminNav.click();
    await page.waitForTimeout(1200);
    await page.screenshot({ path: path.join(screensDir, 'role_admin.png') });

    await browser.close();
    console.log('[CAPTURE] All role screenshots captured successfully.');
  } finally {
    server.kill();
  }
}

run().catch((err) => {
  console.error('[CAPTURE] Error:', err);
  server.kill();
  process.exit(1);
});
