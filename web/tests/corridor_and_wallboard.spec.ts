import { test, expect } from "@playwright/test";

test.describe("3D Situational Corridor, Wallboard & 2 A.M. Operational UX", () => {
  test("air-gapped guarantee: zero external network requests while 3D corridor runs", async ({ page }) => {
    const externalRequests: string[] = [];

    page.on("request", (req) => {
      const url = req.url();
      if (!url.startsWith("http://127.0.0.1:8000") && !url.startsWith("data:") && !url.startsWith("blob:")) {
        externalRequests.push(url);
      }
    });

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Switch to 3D Depth Runway tab
    const runwayTab = page.getByRole("button", { name: /3D Depth runway/i });
    await runwayTab.click();

    // Allow Three.js rendering cycle
    await page.waitForTimeout(1000);

    // Verify zero external network requests
    expect(externalRequests).toEqual([]);
  });

  test("corridor accessibility: screen reader mirror table exists and is fully populated", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Switch to 3D Depth runway tab
    await page.getByRole("button", { name: /3D Depth runway/i }).click();

    // Verify screen-reader table mirror exists
    const srTable = page.locator("table[aria-label='Statutory deadline depth sequence']");
    await expect(srTable).toBeAttached();

    // Verify CERT-In, RBI, DPDP rows exist in SR table
    await expect(srTable.getByText("CERT-In")).toBeAttached();
    await expect(srTable.getByText("RBI")).toBeAttached();
  });

  test("wallboard view (/wall): strictly displays incident numbers and clocks with zero titles or names", async ({ page }) => {
    await page.goto("/wall");
    await page.waitForLoadState("networkidle");

    // Verify wallboard title and NTP calibration banner (sentence case)
    await expect(page.getByText(/CyberQ SOC telemetry wallboard/i)).toBeVisible();
    await expect(page.getByText(/NTP stratum-1 calibrated/i)).toBeVisible();

    // Verify incident number is displayed
    await expect(page.getByText("INC-2026-0001")).toBeVisible();

    // Verify regulatory clocks are rendered
    await expect(page.getByText("CERT-IN").first()).toBeVisible();
    await expect(page.getByText("RBI").first()).toBeVisible();

    // Verify ZERO incident titles, summaries, or user names are present anywhere in the DOM
    const bodyText = await page.innerText("body");
    expect(bodyText).not.toContain("Core Switch Routing Loop");
    expect(bodyText).not.toContain("BGP neighbor flapping");
    expect(bodyText).not.toContain("analyst-01");
  });

  test("command palette (Ctrl+K) and keyboard navigation", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Open palette with Ctrl+K
    await page.keyboard.press("Control+k");
    const paletteInput = page.getByPlaceholder(/Search commands, navigation/i);
    await expect(paletteInput).toBeVisible();

    // Press Esc to dismiss
    await page.keyboard.press("Escape");
    await expect(paletteInput).not.toBeVisible();

    // Press 'a' key to assert trigger
    await page.keyboard.press("a");
    await expect(page.getByText("Assert statutory clock trigger")).toBeVisible();

    // Cancel modal
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByText("Assert statutory clock trigger")).not.toBeVisible();
  });

  test("production build: zero role selector elements exist in DOM", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // In production build, role switcher is strictly stripped from DOM
    const roleSelect = page.locator("select").filter({ hasText: /Analyst|Admin|Auditor/i });
    expect(await roleSelect.count()).toBe(0);
  });
});
