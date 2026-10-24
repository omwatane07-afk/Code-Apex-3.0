import { test } from "@playwright/test";
import path from "path";

test.describe("Walkthrough Screenshots Capture", () => {
  const artifactDir =
    process.env.CYBERQ_ARTIFACT_DIR ||
    "C:/Users/Om Avinash Watane/.gemini/antigravity/brain/5805ddb1-1b03-4c70-9000-4730144da056";

  test("captures desktop and mobile screenshots across day and night themes", async ({ page }) => {
    // 1. Desktop 1440px - Command Center with 3D Runway in Night Desk
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1500);
    await page.screenshot({ path: path.join(artifactDir, "corridor-runway-night.png") });

    // 2. Desktop 1440px - Wallboard Display (/wall)
    await page.goto("/wall");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(artifactDir, "wallboard-1440px.png") });

    // 3. Desktop 1440px - Day Ledger Theme
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    const themeBtn = page.getByRole("button", { name: "Toggle theme" });
    await themeBtn.click();
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(artifactDir, "1440px-day.png") });

    // 4. Mobile 390px - Responsive 2D Companion
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.screenshot({ path: path.join(artifactDir, "390px-mobile-day.png") });
  });
});
