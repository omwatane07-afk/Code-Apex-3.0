import { test } from "@playwright/test";
import path from "path";
import { fileURLToPath } from "url";

test.describe("CYBERQ Role Access Screenshots Capture", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const screensDir = path.resolve(currentDir, "../../docs/QA/screens");

  test("Capture screenshots for all 5 roles across views", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });

    // 1. Role: Analyst (Command Center with incident triage)
    await page.goto("/?role=analyst&demo=1");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1000);
    // Switch tab to detail
    const triageTab = page.getByRole("button", { name: /Incident triage/i });
    if (await triageTab.isVisible()) {
      await triageTab.click();
      await page.waitForTimeout(500);
    }
    await page.screenshot({ path: path.join(screensDir, "role_analyst.png") });

    // 2. Role: CISO (Command Center with CISO Executive Overview and controls)
    await page.goto("/?role=ciso&demo=1");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1000);
    if (await triageTab.isVisible()) {
      await triageTab.click();
      await page.waitForTimeout(500);
    }
    await page.screenshot({ path: path.join(screensDir, "role_ciso.png") });

    // 3. Role: CISO on /decisions (Risk Decision Ledger)
    await page.goto("/decisions?role=ciso&demo=1");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(screensDir, "role_ciso_decisions.png") });

    // 4. Role: Compliance Approver (Command Center with maker-checker obligations)
    await page.goto("/?role=compliance_approver&demo=1");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1000);
    if (await triageTab.isVisible()) {
      await triageTab.click();
      await page.waitForTimeout(500);
    }
    await page.screenshot({ path: path.join(screensDir, "role_compliance.png") });

    // 5. Role: Auditor on /activity (Audit chain with verification & masked narratives)
    await page.goto("/activity?role=auditor&demo=1");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1200);
    // Click verify audit chain button if active
    const verifyBtn = page.getByRole("button", { name: /Verify audit chain/i });
    if (await verifyBtn.isEnabled()) {
      await verifyBtn.click();
      await page.waitForTimeout(1000);
    }
    await page.screenshot({ path: path.join(screensDir, "role_auditor.png") });

    // 6. Role: Admin on /admin (System Administration & Telemetry)
    await page.goto("/admin?role=admin&demo=1");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(screensDir, "role_admin.png") });
  });
});
