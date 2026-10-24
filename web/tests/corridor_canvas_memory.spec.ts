import { test, expect } from "@playwright/test";

test.describe("3D Corridor Canvas Memory Stability (Three.js Clean Disposal)", () => {
  test("50 open/close cycles with flat renderer.info memory geometries and textures", async ({ page }) => {
    test.setTimeout(60000);

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Switch to 3D Depth Runway in App Shell
    const runwayTab = page.getByRole("button", { name: /3D Depth runway/i });
    await runwayTab.click();

    const btn2D = page.getByRole("button", { name: "2D command view" });
    const btn3D = page.getByRole("button", { name: "3D corridor" });

    // Ensure 3D is active initially
    await btn3D.click();
    await page.waitForSelector("canvas", { state: "attached" });
    await page.waitForTimeout(50);

    const initialMemInfo = await page.evaluate(() => {
      return (window as any).__CYBERQ_RENDERER_INFO__ || null;
    });
    expect(initialMemInfo).not.toBeNull();
    const initialGeometries = initialMemInfo.geometries;
    const initialTextures = initialMemInfo.textures;

    // Run 50 cycles of unmounting (2D) and mounting (3D) the Three.js procedural canvas
    for (let cycle = 1; cycle <= 50; cycle++) {
      await btn2D.click();
      await btn3D.click();
    }

    // Allow cycle 50 render
    await page.waitForSelector("canvas", { state: "attached" });
    await page.waitForTimeout(50);

    const finalMemInfo = await page.evaluate(() => {
      return (window as any).__CYBERQ_RENDERER_INFO__ || null;
    });

    expect(finalMemInfo).not.toBeNull();
    console.log(`[MEMORY 50-CYCLE AUDIT] Initial geometries: ${initialGeometries}, Final geometries: ${finalMemInfo.geometries}`);
    console.log(`[MEMORY 50-CYCLE AUDIT] Initial textures: ${initialTextures}, Final textures: ${finalMemInfo.textures}`);

    // Geometries and textures must remain strictly flat (zero unbounded leak across 50 cycles)
    expect(finalMemInfo.geometries).toBeLessThanOrEqual(initialGeometries + 2);
    expect(finalMemInfo.textures).toBeLessThanOrEqual(initialTextures + 2);
  });
});
