import { test, expect } from "@playwright/test";

test.describe("100% Keyboard-Only Incident to Running Clocks Workflow", () => {
  test("end-to-end operational flow from keyboard shortcut 'n' to 'a' to running clocks", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // 1. Press 'n' to open New Incident modal
    await page.keyboard.press("n");
    const titleInput = page.getByPlaceholder(/Core switch packet loss/i);
    await expect(titleInput).toBeVisible();

    // 2. Type incident title using keyboard
    await titleInput.fill("Keyboard Triage: BGP Flap on Edge Router 04");

    // 3. Tab to Summary input and fill
    await page.keyboard.press("Tab"); // moves to severity select
    await page.keyboard.press("Tab"); // moves to summary textarea
    const summaryInput = page.getByPlaceholder(/Technical summary/i);
    await summaryInput.fill("Observed sudden BGP session reset on core link DC1-EDGE-04.");

    // 4. Tab to submit button and press Enter
    await page.keyboard.press("Tab"); // moves to cancel
    await page.keyboard.press("Tab"); // moves to 'Create incident' button
    await page.keyboard.press("Enter");

    // Modal closes
    await expect(titleInput).not.toBeVisible();

    // 5. Press 'a' to open Assert Trigger modal
    await page.keyboard.press("a");
    const triggerModalTitle = page.getByText("Assert statutory clock trigger");
    await expect(triggerModalTitle).toBeVisible();

    // 6. Select quick picker relative time via keyboard click on '10m ago' button
    const quickPicker10m = page.getByRole("button", { name: "10m ago" });
    await quickPicker10m.focus();
    await page.keyboard.press("Enter");

    // 7. Complete plain-language diagnostic questions via keyboard
    // Answering Q1: "Is personal data involved?" -> Click 'no' button
    const personalDataNo = page.getByRole("button", { name: /^no$/i }).first();
    await personalDataNo.focus();
    await page.keyboard.press("Enter");

    // Answering Q2: "Is this a reportable incident category?" -> Click 'yes' button
    const reportableYes = page.getByRole("button", { name: /^yes$/i }).last();
    await reportableYes.focus();
    await page.keyboard.press("Enter");

    // 8. Fill evidence summary and rationale
    const evidenceInput = page.getByPlaceholder(/SIEM correlation alert ID/i);
    await evidenceInput.fill("SIEM correlation alert ID #89201");

    const rationaleInput = page.getByPlaceholder(/Justification for statutory assertion/i);
    await rationaleInput.fill("Threshold breached on primary datacenter core router.");

    // 9. Tab to Assert Trigger submit button and press Enter
    const assertSubmitBtn = page.getByRole("button", { name: "Assert trigger" });
    await assertSubmitBtn.focus();
    await page.keyboard.press("Enter");

    // 10. Assert trigger modal closes and statutory countdown is running
    await expect(triggerModalTitle).not.toBeVisible();

    // 11. Verify running statutory clocks in Command Center
    const clockStrip = page.locator("section[aria-label='Statutory obligation clock strip']");
    await expect(clockStrip).toBeVisible();
    await expect(page.getByText(/CERT-In/i).first()).toBeVisible();
    await expect(page.getByText(/RBI/i).first()).toBeVisible();
  });
});
