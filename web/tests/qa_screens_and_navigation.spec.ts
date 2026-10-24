import { test, expect } from "@playwright/test";
import path from "path";
import { fileURLToPath } from "url";

test.describe("CYBERQ Full System QA & Navigation Verification", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const screensDir = path.resolve(currentDir, "../../docs/QA/screens");

  test("Part 1: Four sidebar tabs navigate cleanly to real/honest pages with aria-current", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // 1. Initial State: Command Center is active
    const cmdBtn = page.locator("aside button[title*='Command Center']");
    await expect(cmdBtn).toHaveAttribute("aria-current", "page");

    // 2. Click Activity & Audit Chain (/activity)
    const activityBtn = page.locator("button[title*='Activity & Audit Chain']");
    await activityBtn.click();
    await page.waitForTimeout(500);
    expect(page.url()).toContain("/activity");
    await expect(activityBtn).toHaveAttribute("aria-current", "page");
    await expect(page.getByText("Tamper-evident activity ledger")).toBeVisible();

    // Verify audit chain button is visible and properly disabled for analyst per separation of duties
    const verifyBtn = page.getByRole("button", { name: /Verify audit chain/i });
    await expect(verifyBtn).toBeVisible();
    await expect(verifyBtn).toBeDisabled();

    // 3. Click Statutory Decision Ledger (/decisions)
    const decisionsBtn = page.locator("button[title*='Statutory Decision Ledger']");
    await decisionsBtn.click();
    await page.waitForTimeout(500);
    expect(page.url()).toContain("/decisions");
    await expect(decisionsBtn).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("heading", { name: "Statutory decision ledger", exact: true })).toBeVisible();
    await expect(page.getByText("Planned for M4").first()).toBeVisible();

    // 4. Click Regulatory Filing Packets (/filings)
    const filingsBtn = page.locator("button[title*='Regulatory Filing Packets']");
    await filingsBtn.click();
    await page.waitForTimeout(500);
    expect(page.url()).toContain("/filings");
    await expect(filingsBtn).toHaveAttribute("aria-current", "page");
    await expect(page.getByText("Regulatory filing packets")).toBeVisible();
    await expect(page.getByText("Planned for M3").first()).toBeVisible();

    // 5. Click System Administration & Telemetry (/admin)
    const adminBtn = page.locator("button[title*='System Administration & Telemetry']");
    await adminBtn.click();
    await page.waitForTimeout(500);
    expect(page.url()).toContain("/admin");
    await expect(adminBtn).toHaveAttribute("aria-current", "page");
    await expect(page.getByText("System administration & telemetry")).toBeVisible();
    await expect(page.getByText("certin-directions-2022")).toBeVisible();
    await expect(page.getByText("rbi-cybersecurity-directions-2026")).toBeVisible();

    // 6. Return to Command Center
    await cmdBtn.click();
    await page.waitForTimeout(500);
    await expect(cmdBtn).toHaveAttribute("aria-current", "page");
    await expect(page.getByText("CYBERQ")).toBeVisible();
  });

  test("Keyboard sequences (g a, g d, g f, g m, g i) navigate seamlessly", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Press 'g' then 'a' -> /activity
    await page.keyboard.press("g");
    await page.keyboard.press("a");
    await page.waitForTimeout(500);
    expect(page.url()).toContain("/activity");

    // Press 'g' then 'd' -> /decisions
    await page.keyboard.press("g");
    await page.keyboard.press("d");
    await page.waitForTimeout(500);
    expect(page.url()).toContain("/decisions");

    // Press 'g' then 'f' -> /filings
    await page.keyboard.press("g");
    await page.keyboard.press("f");
    await page.waitForTimeout(500);
    expect(page.url()).toContain("/filings");

    // Press 'g' then 'm' -> /admin
    await page.keyboard.press("g");
    await page.keyboard.press("m");
    await page.waitForTimeout(500);
    expect(page.url()).toContain("/admin");

    // Press 'g' then 'i' -> / (command)
    await page.keyboard.press("g");
    await page.keyboard.press("i");
    await page.waitForTimeout(500);
    await expect(page.locator("aside button[title*='Command Center']")).toHaveAttribute("aria-current", "page");
  });

  test("Deep linking & browser back/forward history support", async ({ page }) => {
    await page.goto("/admin");
    await page.waitForLoadState("networkidle");
    await expect(page.getByText("System administration & telemetry")).toBeVisible();

    await page.goto("/decisions");
    await page.waitForLoadState("networkidle");
    await expect(page.getByRole("heading", { name: "Statutory decision ledger", exact: true })).toBeVisible();

    await page.goBack();
    await page.waitForTimeout(400);
    expect(page.url()).toContain("/admin");
    await expect(page.getByText("System administration & telemetry")).toBeVisible();

    await page.goForward();
    await page.waitForTimeout(400);
    expect(page.url()).toContain("/decisions");
    await expect(page.getByRole("heading", { name: "Statutory decision ledger", exact: true })).toBeVisible();
  });

  test("Part 2: 3D Runway visual state never shows false breached on pending/unenforced", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Switch to 3D Runway
    const runwayTab = page.getByRole("button", { name: /3D Depth runway/i });
    await runwayTab.click();
    await page.waitForTimeout(1000);

    // Verify DPDP label says "Not in force" and NEVER contains "(breached)"
    const runwayContainer = page.locator("div.relative.w-full.h-\\[460px\\]");
    await expect(runwayContainer).toBeVisible();

    const dpdpLabel = runwayContainer.getByText("Not in force");
    await expect(dpdpLabel).toBeVisible();

    const breachedCount = await runwayContainer.getByText(/00:00:00 \(breached\)/i).count();
    expect(breachedCount).toBe(0);
  });

  test("Capture comprehensive QA verification screenshots into docs/QA/screens/", async ({ page }) => {
    test.setTimeout(60000);
    await page.setViewportSize({ width: 1440, height: 900 });

    // 1. Command Center Night Desk
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(600);
    await page.screenshot({ path: path.join(screensDir, "01-command-center-night.png") });

    // 2. 3D Corridor Runway with Gate Geometry
    const runwayTab = page.getByRole("button", { name: /3D Depth runway/i });
    await runwayTab.click();
    await page.waitForTimeout(1200);
    await page.screenshot({ path: path.join(screensDir, "02-corridor-gate-geometry.png") });

    // 3. Command Center Day Ledger Theme
    const themeBtn = page.getByRole("button", { name: "Toggle theme" });
    await themeBtn.click();
    await page.waitForTimeout(600);
    await page.screenshot({ path: path.join(screensDir, "03-command-center-day.png") });

    // Switch back to dark theme
    await themeBtn.click();
    await page.waitForTimeout(400);

    // 4. Ambient Wallboard
    await page.goto("/wall");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(800);
    await page.screenshot({ path: path.join(screensDir, "04-wallboard-soc.png") });

    // 5. Activity Ledger & Audit Chain
    await page.goto("/activity");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(600);
    const verifyBtn = page.getByRole("button", { name: /Verify audit chain/i });
    if (await verifyBtn.isVisible() && await verifyBtn.isEnabled()) {
      await verifyBtn.click();
      await page.waitForTimeout(800);
    }
    await page.screenshot({ path: path.join(screensDir, "05-activity-ledger.png") });

    // 6. Statutory Decisions View
    await page.goto("/decisions");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(600);
    await page.screenshot({ path: path.join(screensDir, "06-decisions-m4-planned.png") });

    // 7. Regulatory Filings View
    await page.goto("/filings");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(600);
    await page.screenshot({ path: path.join(screensDir, "07-filings-m3-planned.png") });

    // 8. Admin Telemetry & Packs View
    await page.goto("/admin");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(800);
    await page.screenshot({ path: path.join(screensDir, "08-admin-telemetry-packs.png") });
  });
});
