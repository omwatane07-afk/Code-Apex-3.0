import { test, expect } from "@playwright/test";

test.describe("DPDP 'aware' Trigger & 72-Hour Statutory Clock (Analyst Maker)", () => {
  test("analyst-only trigger: visible to analyst, hidden from CISO, activates 72h countdown", async ({ page }) => {
    // 1. Visit as Analyst
    await page.goto("/?role=analyst&demo=1");
    await page.waitForLoadState("networkidle");

    // Click Incident triage tab to display IncidentDetail
    await page.getByRole("button", { name: /Incident triage/i }).click();

    // Verify "Trigger DPDP (Aware)" button is visible for Analyst role
    const triggerDpdpBtn = page.getByRole("button", { name: /Trigger DPDP \(Aware\)/i });
    await expect(triggerDpdpBtn).toBeVisible();

    // 2. Switch role to CISO via URL parameter
    await page.goto("/?role=ciso&demo=1");
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: /Incident triage/i }).click();

    // Verify "Trigger DPDP (Aware)" button is NOT visible to CISO role
    const cisoTriggerBtn = page.getByRole("button", { name: /Trigger DPDP \(Aware\)/i });
    await expect(cisoTriggerBtn).toHaveCount(0);

    // 3. Return to Analyst role
    await page.goto("/?role=analyst&demo=1");
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: /Incident triage/i }).click();

    // 4. Click "Trigger DPDP (Aware)" button
    await page.getByRole("button", { name: /Trigger DPDP \(Aware\)/i }).click();

    // 5. Verify Modal appears with DPDP statutory context
    const modalHeading = page.getByRole("heading", { name: /Assert Statutory DPDP "Aware" Trigger/i });
    await expect(modalHeading).toBeVisible();
    await expect(page.getByText(/strict 72-hour reporting clock to the Data Protection Board/i)).toBeVisible();

    // 6. Submit the trigger assertion
    const submitBtn = page.getByRole("button", { name: /Assert 'aware' \(Start 72h clock\)/i });
    await expect(submitBtn).toBeVisible();
    await submitBtn.click();

    // 7. Verify modal closes and "Trigger DPDP (Aware)" button disappears (clock is now running)
    await expect(modalHeading).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Trigger DPDP \(Aware\)/i })).toHaveCount(0);

    // 8. Verify DPDP obligation is now active and displays running status in incident detail
    const dpdpSection = page.locator("div").filter({ hasText: /^DPDPdpdp-rules-2025/i }).first();
    await expect(dpdpSection).toBeVisible();
    await expect(dpdpSection.getByText(/running/i)).toBeVisible();

    // 9. Switch to 3D Depth Runway tab and verify DPDP clock is rendered and active
    const runwayTab = page.getByRole("button", { name: /3D Depth runway/i });
    await runwayTab.click();
    await page.waitForTimeout(1000);

    const runwayContainer = page.locator("div.relative.w-full.h-\\[460px\\]");
    await expect(runwayContainer).toBeVisible();
    await expect(runwayContainer.getByText("DPDP")).toBeVisible();
  });
});
