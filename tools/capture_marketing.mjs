// Captures the real React app against the isolated fictional IPC fixture.
// NODE_PATH points to the bundled runtime when Playwright is not installed locally.
import { createRequire } from "node:module";
import { mkdir } from "node:fs/promises";
import path from "node:path";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const root = path.resolve(import.meta.dirname, "..");
const landingOnly = process.argv.includes("--landing-only");
const storeOnly = process.argv.includes("--store-only");
if (landingOnly && storeOnly)
  throw new Error("Choose one capture destination.");
const landingScreens = new Set(["messages", "chat", "buzz", "spaces"]);
if (!landingOnly) {
  await mkdir(path.join(root, "release/store/raw"), { recursive: true });
  await mkdir(path.join(root, "release/store/raw/android"), {
    recursive: true,
  });
}
await mkdir(path.join(root, "landingpage/assets"), { recursive: true });
const browser = await chromium.launch({
  executablePath:
    process.env.CHROME_PATH ??
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  headless: true,
});
try {
  const page = await browser.newPage({
    viewport: { width: 402, height: 874 },
    deviceScaleFactor: 3,
    isMobile: true,
    hasTouch: true,
    timezoneId: "UTC",
  });
  const device = await page.context().newCDPSession(page);
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (msg) => {
    if (msg.type() === "error" || process.env.MARKETING_DEBUG)
      console.error(msg.text());
  });
  await page.route("**/*", (route) =>
    new URL(route.request().url()).hostname === "127.0.0.1"
      ? route.continue()
      : route.abort(),
  );
  const preview =
    process.env.MARKETING_PREVIEW_URL ?? "http://127.0.0.1:1437/marketing/";
  const load = async (audience) => {
    await page.goto(`${preview}?audience=${audience}`);
    await page
      .getByLabel("Password", { exact: true })
      .fill("fictional-capture-only");
    await page.getByRole("button", { name: "Unlock", exact: true }).click();
    await page.getByRole("navigation", { name: "Main navigation" }).waitFor();
    // Marketing previews omit native system chrome. Share the landing header
    // geometry instead of reserving an empty status-bar band in store artwork.
    await page.addStyleTag({
      content:
        "html[data-marketing-capture] .screen-header { min-height: 60px; }",
    });
    await page.waitForTimeout(500);
    await page
      .getByRole("button", { name: "Recent and ungrouped chats", exact: true })
      .click();
    await page.waitForTimeout(300);
  };
  const audience = landingOnly ? "work" : "family";
  await load(audience);
  const capture = async (name) => {
    await page.waitForTimeout(500);
    if (await page.getByRole("alert").isVisible())
      throw new Error(
        "Capture blocked by an application alert. Check the fixture IPC responses.",
      );
    await page.evaluate(() =>
      document.documentElement.setAttribute("data-marketing-capture", ""),
    );
    const targets = landingOnly
      ? []
      : [
          {
            file: path.join(root, "release/store/raw", `${name}.png`),
            top: 0,
            bottom: 0,
          },
          {
            file: path.join(root, "release/store/raw/android", `${name}.png`),
            top: 0,
            bottom: 0,
          },
        ];
    if (!storeOnly && landingScreens.has(name))
      targets.push({
        file: path.join(root, "landingpage/assets", `product-${name}.png`),
        top: 0,
        bottom: 0,
      });
    for (const { file, top, bottom } of targets) {
      await device.send("Emulation.setSafeAreaInsetsOverride", {
        insets: { top, bottom, left: 0, right: 0 },
      });
      await page.waitForTimeout(250);
      if (name === "chat") {
        await page
          .locator(".conversation .messages.pull-surface")
          .evaluate((element) => {
            element.scrollTop = 0;
          });
        await page.waitForTimeout(100);
      }
      await page.screenshot({ path: file });
    }
    console.log("Captured", name);
  };
  await capture("messages");
  await page
    .getByRole("button", {
      name: audience === "work" ? /^Chat Launch day / : /^Chat Birthday plans /,
    })
    .click();
  await capture("chat");
  await page
    .getByRole("button", { name: "Back to Messages", exact: true })
    .click();
  await load("work");
  await page.getByRole("button", { name: /^Buzz/ }).click();
  await capture("buzz");
  await load(audience);
  await page.getByRole("button", { name: "More", exact: true }).click();
  await page
    .getByRole("button", { name: "Manage Spaces", exact: true })
    .click();
  await capture("spaces");
  if (!landingOnly) {
    await page.getByRole("button", { name: "Back", exact: true }).click();
    await page.getByRole("button", { name: "Appearance", exact: true }).click();
    await page.getByRole("button", { name: "Pink", exact: true }).click();
    await capture("appearance");
    await page.getByRole("button", { name: "Mint", exact: true }).click();
    await page
      .getByRole("button", { name: "Back to More", exact: true })
      .click();
    await page.getByRole("button", { name: /^Reminders/ }).click();
    await capture("reminders");
  }
  if (errors.length) throw new Error(errors.join("\n"));
} finally {
  await browser.close();
}
