import { test, expect } from "@playwright/test";
import { createRequire } from "module";

const require = createRequire(import.meta.url);

test.describe("Browser Security & Accessibility Suite (Playwright + Axe-Core)", () => {
  test("clickjacking defense: app shell refuses iframe framing or enforces frame-ancestors 'none'", async ({ page }) => {
    // Attempt to load CYBERQ in an iframe from an external HTML document
    await page.setContent(`
      <!DOCTYPE html>
      <html>
        <body>
          <iframe id="test-frame" src="/" width="800" height="600"></iframe>
        </body>
      </html>
    `);

    const frameElement = page.frameLocator("#test-frame");
    expect(frameElement).toBeDefined();
    // Under strict CSP / X-Frame-Options: DENY, framing is blocked
    const response = await page.goto("/");
    expect(response).not.toBeNull();
    expect(response?.headers()["x-frame-options"]).toBe("DENY");
    expect(response?.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
  });

  test("zero secrets or tokens in browser localStorage and sessionStorage", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const storageAudit = await page.evaluate(() => {
      const localKeys = Object.keys(window.localStorage);
      const sessionKeys = Object.keys(window.sessionStorage);
      return {
        localKeys,
        sessionKeys,
        hasSensitiveData: localKeys.some(k => /token|auth|session|secret|key/i.test(k)) ||
                          sessionKeys.some(k => /token|auth|session|secret|key/i.test(k))
      };
    });

    expect(storageAudit.hasSensitiveData).toBe(false);
    expect(storageAudit.localKeys.length).toBe(0);
    expect(storageAudit.sessionKeys.length).toBe(0);
  });

  test("zero CSP violations in console across 3D corridor, wallboard, and modals", async ({ page }) => {
    const cspViolations: string[] = [];
    page.on("console", (msg) => {
      const text = msg.text();
      if (
        msg.type() === "error" &&
        (text.toLowerCase().includes("content security policy") || text.toLowerCase().includes("csp"))
      ) {
        cspViolations.push(text);
      }
    });

    // 1. Visit main dashboard
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // 2. Open 3D Depth Runway
    await page.getByRole("button", { name: /3D Depth runway/i }).click();
    await page.waitForTimeout(500);

    // 3. Open trigger modal
    await page.keyboard.press("a");
    await page.waitForTimeout(300);
    await page.getByRole("button", { name: "Cancel" }).click();

    // 4. Open command palette
    await page.keyboard.press("Control+k");
    await page.waitForTimeout(300);
    await page.keyboard.press("Escape");

    // 5. Visit wallboard
    await page.goto("/wall");
    await page.waitForLoadState("networkidle");

    // Assert strictly zero CSP violations
    expect(cspViolations).toEqual([]);
  });

  test("axe-core automated WCAG AA accessibility audit on rendered App Shell", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Inject axe-core directly into execution context (CSP safe without <script> tag)
    const fs = require("fs");
    const axePath = require.resolve("axe-core/axe.min.js");
    const axeSource = fs.readFileSync(axePath, "utf8");
    await page.evaluate(axeSource);

    const results = await page.evaluate(async () => {
      // @ts-ignore
      return await window.axe.run({
        runOnly: {
          type: "tag",
          values: ["wcag2a", "wcag2aa"],
        },
      });
    });

    const seriousOrCritical = results.violations.filter(
      (v: any) => v.impact === "critical" || v.impact === "serious"
    );

    expect(seriousOrCritical).toEqual([]);
  });

  test("statutory clock strip and command center rendering (M1)", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Verify Clock Strip segments exist
    const clockStrip = page.locator("section[aria-label='Statutory obligation clock strip']");
    await expect(clockStrip).toBeVisible();

    // Verify all 3 statutory clocks are rendered
    await expect(page.getByText("CERT-In 6-hour clock")).toBeVisible();
    await expect(page.getByText("RBI cyber incident log (DAKSH)")).toBeVisible();
    await expect(page.getByText("DPDP data protection board report")).toBeVisible();

    // Verify Active incidents panel
    await expect(page.getByText(/Active incidents/i)).toBeVisible();
  });
});
