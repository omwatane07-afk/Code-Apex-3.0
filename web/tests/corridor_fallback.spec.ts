import { test, expect } from "@playwright/test";

test.describe("Corridor Canvas WebGL Unavailable Graceful Fallback", () => {
  test("gracefully falls back to 2D view when WebGL context cannot be created", async ({ page }) => {
    // Inject script simulating WebGL disabled or unavailable
    await page.addInitScript(() => {
      const origGetContext = (HTMLCanvasElement.prototype as any).getContext;
      (HTMLCanvasElement.prototype as any).getContext = function (type: string, ...args: any[]) {
        if (type.includes("webgl")) {
          return null;
        }
        return origGetContext.apply(this, [type, ...args]);
      };
    });

    const pageErrors: string[] = [];
    page.on("pageerror", (err) => pageErrors.push(err.message));

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Click 3D Depth Runway tab in App Shell
    const runwayTab = page.getByRole("button", { name: /3D Depth runway/i });
    await runwayTab.click();

    // Verify app did not crash with unhandled exception
    expect(pageErrors).toEqual([]);

    // Verify CorridorView gracefully fell back to 2D command view
    const btn2D = page.getByRole("button", { name: "2D command view" });
    await expect(btn2D).toBeVisible();
    await expect(btn2D).toHaveClass(/bg-primary/);

    // Verify high-density 2D companion cards are displayed for CERT-In, RBI, DPDP
    const corridorContainer = page.locator("div.flex.flex-col.border.border-rule");
    await expect(corridorContainer.getByText("CERT-In").first()).toBeVisible();
    await expect(corridorContainer.getByText("RBI").first()).toBeVisible();
  });
});
