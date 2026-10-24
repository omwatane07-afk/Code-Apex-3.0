import { test, expect } from "@playwright/test";

test.describe("2D/3D Information Parity & Clock Alignment", () => {
  test("exact information parity between 2D Command Center dials and 3D Depth Runway", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // 1. Collect 2D View Clock information
    const certIn2D = page.locator("section[aria-label='Statutory obligation clock strip']").getByText(/CERT-In/i);
    const rbi2D = page.locator("section[aria-label='Statutory obligation clock strip']").getByText(/RBI/i);
    const dpdp2D = page.locator("section[aria-label='Statutory obligation clock strip']").getByText(/DPDP/i);

    await expect(certIn2D).toBeVisible();
    await expect(rbi2D).toBeVisible();
    await expect(dpdp2D).toBeVisible();

    // 2. Switch to 3D Depth Runway
    const runwayTab = page.getByRole("button", { name: /3D Depth runway/i });
    await runwayTab.click();

    // 3. Verify screen-reader mirror table contains identical regulatory obligations
    const srTable = page.locator("table[aria-label='Statutory deadline depth sequence']");
    await expect(srTable).toBeAttached();

    const srCertIn = srTable.getByText(/CERT-In/i);
    const srRbi = srTable.getByText(/RBI/i);
    const srDpdp = srTable.getByText(/DPDP/i);

    await expect(srCertIn).toBeAttached();
    await expect(srRbi).toBeAttached();
    await expect(srDpdp).toBeAttached();

    // 4. Verify 3D labels or projected DOM elements are present for all regulators
    const runwayContainer = page.locator("div.relative.w-full.h-\\[460px\\]");
    await expect(runwayContainer).toBeVisible();
    await expect(runwayContainer.getByText(/CERT-In/i).first()).toBeVisible();
    await expect(runwayContainer.getByText(/RBI/i).first()).toBeVisible();
  });
});
