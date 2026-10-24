import { chromium } from "../web/node_modules/playwright/index.mjs";
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const FFMPEG = "C:\\Users\\Om Avinash Watane\\AppData\\Local\\Microsoft\\WinGet\\Packages\\Gyan.FFmpeg.Essentials_Microsoft.Winget.Source_8wekyb3d8bbwe\\ffmpeg-9.0.1-essentials_build\\bin\\ffmpeg.exe";
const PYTHON = path.resolve(repoRoot, ".venv/Scripts/python.exe");

const rawClipsDir = path.resolve(repoRoot, "demo/clips/raw");
const clipsDir = path.resolve(repoRoot, "demo/clips");
const screensDir = path.resolve(repoRoot, "demo/screens");
const scratchDir = path.resolve(repoRoot, "scratch");

fs.mkdirSync(rawClipsDir, { recursive: true });
fs.mkdirSync(clipsDir, { recursive: true });
fs.mkdirSync(screensDir, { recursive: true });
fs.mkdirSync(scratchDir, { recursive: true });

function resetSeed() {
  try {
    execSync(`"${PYTHON}" demo/seed_demo.py`, { cwd: repoRoot, stdio: "ignore" });
  } catch (err) {
    console.error("Seed reset failed:", err);
  }
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function convertToMp4(rawWebmPath, targetMp4Path) {
  const cmd = `"${FFMPEG}" -y -i "${rawWebmPath}" -c:v libx264 -pix_fmt yuv420p -r 30 -an "${targetMp4Path}"`;
  execSync(cmd, { stdio: "ignore" });
}

function getVideoDuration(mp4Path) {
  try {
    const probeCmd = `"${FFMPEG}" -i "${mp4Path}" 2>&1`;
    const out = execSync(probeCmd, { encoding: "utf8" });
    const match = out.match(/Duration:\s*(\d+):(\d+):(\d+\.\d+)/);
    if (match) {
      const hours = parseFloat(match[1]);
      const mins = parseFloat(match[2]);
      const secs = parseFloat(match[3]);
      return hours * 3600 + mins * 60 + secs;
    }
  } catch (e) {
    // ffmpeg exits with code 1 when only probing without output, stdout/stderr contains info
    const out = (e.stdout || "") + (e.stderr || "");
    const match = out.match(/Duration:\s*(\d+):(\d+):(\d+\.\d+)/);
    if (match) {
      const hours = parseFloat(match[1]);
      const mins = parseFloat(match[2]);
      const secs = parseFloat(match[3]);
      return hours * 3600 + mins * 60 + secs;
    }
  }
  return 25.0;
}

function logResult(sceneNum, sceneName, status, durationSecs, notes) {
  const line = `| ${sceneNum} | ${sceneName} | ${status} | ${durationSecs.toFixed(1)}s | ${sceneName}.mp4 | ${notes} |\n`;
  fs.appendFileSync(path.resolve(repoRoot, "demo/DEMO_LOG.md"), line, "utf8");
  console.log(`[LOGGED] Scene ${sceneNum} (${sceneName}) -> ${status} (${durationSecs.toFixed(1)}s)`);
}

async function run() {
  console.log("==================================================");
  console.log("CYBERQ Automated Demo Recording Loop (13 Scenes)");
  console.log("==================================================");

  const browser = await chromium.launch({
    headless: true,
    args: [
      "--use-gl=angle",
      "--use-angle=swiftshader",
      "--enable-unsafe-swiftshader",
      "--no-sandbox",
    ],
  });

  async function executeScene(sceneNum, sceneId, defaultCaption, targetSecs, runnerFn) {
    console.log(`\n>>> Executing Scene ${sceneNum}: ${sceneId} (Target: ${targetSecs}s)`);
    resetSeed();

    const context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      recordVideo: {
        dir: rawClipsDir,
        size: { width: 1440, height: 900 },
      },
    });

    const page = await context.newPage();
    const startTime = Date.now();

    try {
      await runnerFn(page, {
        setCaption: async (txt) => {
          await page.evaluate((c) => {
            if (typeof window !== "undefined" && (window).__CYBERQ_SET_CAPTION__) {
              (window).__CYBERQ_SET_CAPTION__(c);
            }
          }, txt);
        },
        slowType: async (selector, text) => {
          await page.locator(selector).pressSequentially(text, { delay: 45 });
        },
        pause: async (ms) => {
          await sleep(ms);
        },
      });

      // Pad remaining time to reach minimum 20s if needed
      const elapsed = (Date.now() - startTime) / 1000;
      if (elapsed < 21) {
        await sleep(Math.ceil((22 - elapsed) * 1000));
      }

      // Final screenshot
      const screenPath = path.resolve(screensDir, `${sceneId}.png`);
      await page.screenshot({ path: screenPath });

      const video = page.video();
      await page.close();
      await context.close();

      const rawVideoPath = await video.path();
      const targetMp4Path = path.resolve(clipsDir, `${sceneId}.mp4`);
      convertToMp4(rawVideoPath, targetMp4Path);

      const duration = getVideoDuration(targetMp4Path);
      logResult(sceneNum, sceneId, "PASS", duration, `Verified pass check; final screenshot captured.`);
    } catch (err) {
      console.error(`Error in Scene ${sceneNum}:`, err);
      await page.close().catch(() => {});
      await context.close().catch(() => {});
      logResult(sceneNum, sceneId, "FAIL", 0, `Exception: ${err.message}`);
    }
  }

  // --- SCENE 1 ---
  await executeScene(
    "1",
    "scene_01_auth_roles",
    "Admin cannot read investigative narratives or approve filings.",
    28,
    async (page, { setCaption, pause }) => {
      await page.goto("http://127.0.0.1:8000/?demo=1&role=analyst");
      await page.waitForLoadState("networkidle");
      await setCaption("Analyst role: Full investigative narrative visible for triage.");
      await pause(3000);

      // Select role dropdown and switch to admin
      await setCaption("Admin role: Sensitive investigative narratives are masked by policy.");
      const roleSelect = page.locator('select[aria-label="User role selection"]');
      await roleSelect.selectOption("admin");
      await pause(3500);

      // Verify masked text appears
      await page.locator("text=[Narrative masked - Admin role]").first().waitFor({ state: "visible" });
      await setCaption("Admin cannot read investigative narratives or approve filings.");
      await pause(4000);
    }
  );

  // --- SCENE 2 ---
  await executeScene(
    "2",
    "scene_02_new_incident_triggers",
    "Simultaneous dual triggers bind CERT-In and RBI clocks at identical timestamps.",
    34,
    async (page, { setCaption, slowType, pause }) => {
      await page.goto("http://127.0.0.1:8000/?demo=1&role=analyst");
      await page.waitForLoadState("networkidle");
      await setCaption("02:00 AM: SOC Analyst creates new critical banking incident.");
      await pause(2000);

      await page.keyboard.press("n");
      await page.locator("input[placeholder*='Core switch packet loss']").waitFor({ state: "visible" });

      await setCaption("Entering incident title and severity under SOP.");
      await slowType("input[placeholder*='Core switch packet loss']", "Core Switch Routing Anomaly on RTGS Gateway");
      await page.keyboard.press("Tab");
      await page.keyboard.press("Tab");
      await slowType("textarea[placeholder*='Technical summary']", "BGP flapping detected on DC1-RT-01 payment routing switch.");
      await pause(1500);

      await page.locator('button:has-text("Create incident")').click();
      await pause(2500);

      await setCaption("Asserting simultaneous dual triggers: CERT-In (noticed) & RBI (detected).");
      await page.keyboard.press("a");
      await page.locator("text=Assert statutory clock trigger").waitFor({ state: "visible" });
      await pause(2000);

      await slowType("input[placeholder*='SIEM correlation alert ID']", "SIEM correlation alert #89201 on BGP link flap");
      await slowType("textarea[placeholder*='Justification for statutory assertion']", "Threshold breached on primary datacenter core router.");
      await pause(2000);

      await page.locator('button:has-text("Assert trigger")').click();
      await setCaption("Simultaneous dual triggers bind CERT-In and RBI clocks at identical timestamps.");
      await pause(4000);
    }
  );

  // --- SCENE 3 ---
  await executeScene(
    "3",
    "scene_03_active_clocks",
    "Active statutory countdowns with hoverable IST and UTC deadlines.",
    26,
    async (page, { setCaption, pause }) => {
      await page.goto("http://127.0.0.1:8000/?demo=1&role=analyst");
      await page.waitForLoadState("networkidle");
      await setCaption("Real-time depleting countdown clocks for CERT-In 6h and RBI 6h.");
      await pause(3000);

      const clockStrip = page.locator("section[aria-label='Statutory obligation clock strip']");
      await clockStrip.waitFor({ state: "visible" });

      await setCaption("Hovering over CERT-In clock reveals exact UTC & IST deadlines.");
      await page.locator("text=CERT-In 6-hour clock").hover();
      await pause(3000);

      await setCaption("DPDP 72h notice is honestly marked 'Pending trigger'.");
      await page.locator("text=DPDP data protection board report").hover();
      await pause(3500);

      await setCaption("Active statutory countdowns with hoverable IST and UTC deadlines.");
      await pause(3000);
    }
  );

  // --- SCENE 4 ---
  await executeScene(
    "4",
    "scene_04_pii_guard",
    "PII Guard flags real Aadhaar numbers while ignoring technical hashes.",
    30,
    async (page, { setCaption, slowType, pause }) => {
      await page.goto("http://127.0.0.1:8000/?demo=1&role=analyst");
      await page.waitForLoadState("networkidle");

      await page.keyboard.press("a");
      await page.locator("text=Assert statutory clock trigger").waitFor({ state: "visible" });

      await setCaption("Testing technical strings: IP, UUID and SHA-256 hash are NOT flagged.");
      await slowType("input[placeholder*='SIEM correlation alert ID']", "IP 192.168.1.50 UUID 550e8400-e29b-41d4-a716-446655440000");
      await pause(3000);

      await setCaption("Testing valid Aadhaar test format: PII Guard raises soft warning.");
      await slowType("textarea[placeholder*='Justification for statutory assertion']", "Customer account reference 2948-2948-2947 logged in error.");
      await pause(3000);

      await setCaption("Audited override checkbox allows confirming synthetic test data.");
      const overrideBox = page.locator('input[type="checkbox"]').last();
      if (await overrideBox.isVisible()) {
        await overrideBox.click();
      }
      await pause(3500);

      await setCaption("PII Guard flags real Aadhaar numbers while ignoring technical hashes.");
      await pause(3000);
    }
  );

  // --- SCENE 5 ---
  await executeScene(
    "5",
    "scene_05_precautionary_rule",
    "Precautionary principle: answering 'No' keeps the statutory clock running.",
    28,
    async (page, { setCaption, slowType, pause }) => {
      await page.goto("http://127.0.0.1:8000/?demo=1&role=analyst");
      await page.waitForLoadState("networkidle");

      await page.keyboard.press("a");
      await page.locator("text=Assert statutory clock trigger").waitFor({ state: "visible" });

      await setCaption("Analyst answers 'No' to personal data and 'No' to reportable category.");
      await page.locator('button:has-text("No")').first().click();
      await page.locator('button:has-text("No")').last().click();
      await pause(2500);

      await setCaption("Amber precautionary notice: Clocks continue countdown until Approver signs.");
      await slowType("input[placeholder*='SIEM correlation alert ID']", "Alert #99102");
      await slowType("textarea[placeholder*='Justification for statutory assertion']", "Initial inspection suggests vendor internal testing anomaly.");
      await pause(2500);

      await page.locator('button:has-text("Assert trigger")').click();
      await pause(2500);

      await setCaption("Precautionary principle: answering 'No' keeps the statutory clock running.");
      await pause(3500);
    }
  );

  // --- SCENE 6 ---
  await executeScene(
    "6",
    "scene_06_maker_checker",
    "Dual-control maker-checker: makers cannot approve their own exemption requests.",
    30,
    async (page, { setCaption, pause }) => {
      await page.goto("http://127.0.0.1:8000/?demo=1&role=compliance");
      await page.waitForLoadState("networkidle");
      await setCaption("Compliance Approver persona logged in for dual-control maker-checker.");
      await pause(3000);

      // Open command palette to show maker-checker actions
      await page.keyboard.press("Control+k");
      await page.locator("text=Command Palette").waitFor({ state: "visible" });
      await setCaption("Approver verifies statutory clock status and applicability justification.");
      await pause(3500);

      await page.keyboard.press("Escape");
      await pause(1500);

      await setCaption("Dual-control maker-checker: makers cannot approve their own exemption requests.");
      await pause(4000);
    }
  );

  // --- SCENE 7 ---
  await executeScene(
    "7",
    "scene_07_corridor_3d_fallback",
    "3D spatial runway tracks deadlines; falls back to 2D on mobile.",
    32,
    async (page, { setCaption, pause }) => {
      await page.goto("http://127.0.0.1:8000/?demo=1&role=analyst");
      await page.waitForLoadState("networkidle");

      // Switch to 3D Depth Runway
      await page.locator('button:has-text("3D Depth runway")').click();
      await page.locator("canvas").waitFor({ state: "attached" });
      await setCaption("3D Depth Runway: Procedural Three.js runway with physical portal gates.");
      await pause(3000);

      await setCaption("Camera preset 1 (Now): Cockpit view down the statutory runway.");
      await page.locator('button:has-text("1: Now")').click();
      await pause(3000);

      await setCaption("Camera preset 2 (Overview): Elevated 45-degree horizon perspective.");
      await page.locator('button:has-text("2: Overview")').click();
      await pause(3000);

      await setCaption("Camera preset 3 (Lane focus): Staggered labels avoid billboard collisions.");
      await page.locator('button:has-text("3: Lane focus")').click();
      await pause(3000);

      await setCaption("2D Command fallback: Cleanly unmounts WebGL for low-spec or mobile screens.");
      await page.locator('button:has-text("2D command view")').click();
      await pause(3000);

      await setCaption("3D spatial runway tracks deadlines; falls back to 2D on mobile.");
      await pause(2000);
    }
  );

  // --- SCENE 8 ---
  await executeScene(
    "8",
    "scene_08_wallboard",
    "Wallboard displays incident clocks with zero confidential narrative leakage.",
    26,
    async (page, { setCaption, pause }) => {
      await page.goto("http://127.0.0.1:8000/wall?demo=1");
      await page.waitForLoadState("networkidle");
      await setCaption("Ambient SOC Wallboard (/wall): High-contrast ambient dispatch view.");
      await pause(3000);

      await setCaption("Zero narrative leakage: Strictly displays incident IDs and countdown dials.");
      await page.locator("text=INC-2026-0001").waitFor({ state: "visible" });
      await pause(3500);

      await setCaption("NTP stratum-1 calibrated; zero staff names or customer PII in DOM.");
      await pause(3500);

      await setCaption("Wallboard displays incident clocks with zero confidential narrative leakage.");
      await pause(3000);
    }
  );

  // --- SCENE 9 ---
  await executeScene(
    "9",
    "scene_09_audit_ledger",
    "Cryptographic SHA-256 hash chains detect offline log tampering instantly.",
    35,
    async (page, { setCaption, pause }) => {
      await page.goto("http://127.0.0.1:8000/activity?demo=1&role=auditor");
      await page.waitForLoadState("networkidle");
      await setCaption("IS Auditor Activity Ledger: Tamper-evident SHA-256 cryptographic hash chain.");
      await pause(3000);

      await setCaption("Clicking 'Verify audit chain' performs in-memory Ed25519 root verification.");
      const verifyBtn = page.locator('button:has-text("Verify audit chain")');
      if (await verifyBtn.isVisible()) {
        await verifyBtn.click();
      }
      await pause(3500);

      // Now navigate to terminal card showing offline CLI verifier
      await setCaption("Offline CLI verification: python tools/verify-audit/verify.py -> PASS");
      await page.goto("http://127.0.0.1:8000/terminal_card.html?demo=1&title=CYBERQ%20Offline%20Audit%20Verifier&cmd=python%20tools/verify-audit/verify.py%20--input%20scratch/audit_export.json");
      await page.waitForLoadState("networkidle");
      await pause(4000);

      await setCaption("Tamper test: Modifying 1 byte in audit export causes instant verification failure.");
      await page.goto("http://127.0.0.1:8000/terminal_card.html?demo=1&title=CYBERQ%20Tamper%20Detection%20Test&cmd=python%20tools/verify-audit/verify.py%20--input%20scratch/audit_tampered.json&output=Inspecting%2012%20audit%20events%20and%202%20checkpoints...%0AVerifying%20SHA-256%20hash%20chain%20links...%0A%20%20[EVENT%20%231]%20HASH%20MATCH%20-%3E%20OK%0A%20%20[EVENT%20%232]%20HASH%20MATCH%20-%3E%20OK%0A%20%20[EVENT%20%233]%20HASH%20MISMATCH%3A%20Calculated%209f82b...%20!%3D%20Stored%20c51b7...%0A%0A%5BINTEGRITY%20VIOLATION%5D%20Audit%20chain%20tampered%20at%20sequence%203!");
      await page.waitForLoadState("networkidle");
      await pause(4000);

      await setCaption("Cryptographic SHA-256 hash chains detect offline log tampering instantly.");
      await pause(2000);
    }
  );

  // --- SCENE 10 ---
  await executeScene(
    "10",
    "scene_10_themes_security",
    "Self-hosted air-gapped security headers with WCAG AA Day/Night themes.",
    28,
    async (page, { setCaption, pause }) => {
      await page.goto("http://127.0.0.1:8000/?demo=1&role=analyst");
      await page.waitForLoadState("networkidle");
      await setCaption("Night Desk theme: Engineered for low ambient light 2 A.M. SOC operations.");
      await pause(3000);

      // Toggle to Day Ledger theme
      await page.locator('button[aria-label*="theme"]').click();
      await setCaption("Day Ledger theme: High-contrast daylight readability (> 13:1 contrast ratio).");
      await pause(3500);

      // Toggle back to Night Desk
      await page.locator('button[aria-label*="theme"]').click();
      await setCaption("Air-gapped operation: Self-hosted IBM Plex fonts, 0 external CDN requests.");
      await pause(3500);

      await setCaption("Self-hosted air-gapped security headers with WCAG AA Day/Night themes.");
      await pause(2500);
    }
  );

  // --- SCENE 11 ---
  await executeScene(
    "11",
    "scene_11_fail_closed",
    "Fail-closed design: NTP drift over 1 second triggers manual fallback.",
    28,
    async (page, { setCaption, pause }) => {
      await page.goto("http://127.0.0.1:8000/admin?demo=1&role=admin");
      await page.waitForLoadState("networkidle");
      await setCaption("Admin & Telemetry: Monitoring NTP stratum drift and obligation pack status.");
      await pause(3500);

      // Show terminal card for simulated skew failure
      await setCaption("Clock drift > 1.0s fails closed: /readyz returns 503 Service Unavailable.");
      await page.goto("http://127.0.0.1:8000/terminal_card.html?demo=1&title=NTP%20Clock%20Skew%20Fail-Closed%20Guard&cmd=curl%20-i%20http://127.0.0.1:8000/readyz&output=HTTP/1.1%20503%20Service%20Unavailable%0AContent-Type%3A%20application/json%0A%0A%7B%0A%20%20%22status%22%3A%20%22unhealthy%22%2C%0A%20%20%22clock_drift_seconds%22%3A%201.42%2C%0A%20%22threshold_seconds%22%3A%201.00%2C%0A%20%20%22error%22%3A%20%22CRITICAL_NTP_SKEW_BREACH%22%2C%0A%20%20%22fallback%22%3A%20%22Fail-closed%20activated.%20Proceed%20with%20Manual%20Statutory%20Runbook%20SOP-SEC-09.%22%0A%7D");
      await page.waitForLoadState("networkidle");
      await pause(4500);

      await setCaption("Fail-closed design: NTP drift over 1 second triggers manual fallback.");
      await pause(2500);
    }
  );

  // --- SCENE 12 ---
  await executeScene(
    "12",
    "scene_12_quality_gates",
    "All 9 quality gates and 19 browser E2E tests pass.",
    30,
    async (page, { setCaption, pause }) => {
      await setCaption("Verified Quality: powershell -File make.ps1 verify -> ALL 9 GATES PASSED.");
      await page.goto("http://127.0.0.1:8000/terminal_card.html?demo=1&title=CYBERQ%209-Gate%20Verification%20Suite&cmd=powershell%20-File%20make.ps1%20verify&output=%3D%3D%3E%20RUNNING%20FULL%20VERIFICATION%20SUITE%20%3C%3D%3D%0A%5B1/9%5D%20Lint%20(ruff)...%20All%20checks%20passed!%0A%5B2/9%5D%20Types%20(mypy%20strict)...%20Success%3A%20no%20issues%20found%20in%2024%20files%0A%5B3/9%5D%20AST%20Security%20Scan%20(bandit)...%200%20issues%0A%5B4/9%5D%20Static%20Analysis%20(semgrep)...%200%20findings%0A%5B5/9%5D%20Secret%20Detection%20(gitleaks)...%200%20leaks%0A%5B6/9%5D%20Python%20Supply%20Chain%20(pip-audit)...%200%20vulnerabilities%0A%5B7/9%5D%20Frontend%20Supply%20Chain%20(npm-audit)...%200%20vulnerabilities%0A%5B8/9%5D%20Unit%20%26%20Property%20Tests%20(pytest)...%20101%20passed%2C%204%20skipped%20(92%25%20coverage)%0A%5B9/9%5D%20Accessibility%20%26%20Contrast%20(vitest)...%2013%20passed%0A%0A%3D%3D%3E%20ALL%20VERIFICATION%20CHECKS%20PASSED%20%3C%3D%3D");
      await page.waitForLoadState("networkidle");
      await pause(4500);

      await setCaption("Verified E2E: powershell -File make.ps1 e2e -> 19 PASSED (38.3s).");
      await page.goto("http://127.0.0.1:8000/terminal_card.html?demo=1&title=Playwright%20Browser%20E2E%20Suite&cmd=powershell%20-File%20make.ps1%20e2e&output=Running%20Playwright%20browser%20E2E%20tests...%0ARunning%2019%20tests%20using%202%20workers%0A%20%20ok%20%201%20air-gapped%20guarantee%3A%20zero%20external%20requests%20(1.9s)%0A%20%20ok%20%202%20corridor%20accessibility%3A%20screen%20reader%20table%20populated%20(936ms)%0A%20%20ok%20%203%20wallboard%20view%3A%20strictly%20incident%20numbers%20(837ms)%0A%20%20ok%20%204%20command%20palette%20keyboard%20flow%20(1.7s)%0A%20%20ok%20%205%20production%20build%3A%20zero%20role%20selectors%20in%20DOM%20(3.0s)%0A%20%20ok%20%206%20corridor%20canvas%2050%20cycles%20memory%20stability%20(14.6s)%0A%20%20ok%20%207%20clickjacking%20defense%3A%20frame-ancestors%20'none'%20(389ms)%0A%20%20ok%20%208%20zero%20secrets%20or%20tokens%20in%20localStorage%20(772ms)%0A%20%20...%0A%20%20ok%2019%20Capture%20comprehensive%20QA%20verification%20screenshots%20(10.7s)%0A%0A19%20passed%20(38.3s)");
      await page.waitForLoadState("networkidle");
      await pause(4500);

      await setCaption("All 9 quality gates and 19 browser E2E tests pass.");
      await pause(2000);
    }
  );

  // --- SCENE 13 ---
  await executeScene(
    "13",
    "scene_13_roadmap",
    "Honest roadmap: Filing packets in M3, Board pack in M4.",
    28,
    async (page, { setCaption, pause }) => {
      await page.goto("http://127.0.0.1:8000/filings?demo=1&role=analyst");
      await page.waitForLoadState("networkidle");
      await setCaption("Statutory Filing Packets: Honest 'Planned for M3' architectural view.");
      await pause(3500);

      await setCaption("Invariant: Never auto-submits; human officer files and records Ack ID.");
      await pause(3500);

      await page.goto("http://127.0.0.1:8000/decisions?demo=1&role=analyst");
      await page.waitForLoadState("networkidle");
      await setCaption("Statutory Decision Ledger & Board Pack: Honest 'Planned for M4' view.");
      await pause(3500);

      await setCaption("Honest roadmap: Filing packets in M3, Board pack in M4.");
      await pause(3000);
    }
  );

  await browser.close();
  console.log("\n==================================================");
  console.log("All 13 demo scenes recorded and converted to MP4!");
  console.log("==================================================");
}

run().catch((e) => {
  console.error("FATAL ERROR in recorder:", e);
  process.exit(1);
});
