// Run `npx playwright install chromium` once before `npm run test:responsive`.
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const test = require("node:test");
const { chromium } = require("playwright");

async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.once("error", reject).listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitForServer(url, process) {
  const deadline = Date.now() + 300000;
  while (Date.now() < deadline) {
    if (process.exitCode !== null || process.signalCode !== null) throw new Error("Next server exited before becoming ready");
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(300000) });
      if (response.ok) return;
      throw new Error(`Next server returned HTTP ${response.status}`);
    } catch (error) {
      if (error.message.startsWith("Next server returned HTTP")) throw error;
      // The server is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  throw new Error("Next server did not become ready within 300 seconds");
}

test("QuickStart remains usable without horizontal overflow on narrow screens", { timeout: 600000 }, async (t) => {
  const port = await availablePort();
  const baseURL = `http://127.0.0.1:${port}`;
  const server = spawn(process.execPath, [require.resolve("next/dist/bin/next"), "start", "--port", String(port)], {
    cwd: path.join(__dirname, ".."),
    env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR, NEXT_TELEMETRY_DISABLED: "1" },
    stdio: "ignore",
  });
  t.after(() => server.kill());
  await waitForServer(`${baseURL}/secrets`, server);

  // Use Playwright's installed browser, falling back to a locally installed Chrome.
  const launchOptions = fs.existsSync(chromium.executablePath()) ? {} : { channel: "chrome" };
  const browser = await chromium.launch(launchOptions);
  t.after(() => browser.close());
  for (const width of [320, 375]) {
    const context = await browser.newContext({ viewport: { width, height: 800 }, permissions: ["clipboard-read", "clipboard-write"] });
    try {
      const page = await context.newPage();
      await page.route("**/*", (route) => new URL(route.request().url()).origin === baseURL ? route.continue() : route.abort());
      await page.goto(`${baseURL}/secrets`, { waitUntil: "networkidle", timeout: 120000 });
      const section = page.locator("#install");
      const selector = section.getByRole("group", { name: "Choose an operating system" });
      // SSR renders macOS selected. Wait for a real selection change so that
      // the remaining interactions run after the client has hydrated.
      const windows = selector.getByRole("button", { name: "Windows" });
      const hydrationDeadline = Date.now() + 60000;
      while (await windows.getAttribute("aria-pressed") !== "true" && Date.now() < hydrationDeadline) {
        await windows.click();
        await page.waitForTimeout(250);
      }
      assert.equal(await windows.getAttribute("aria-pressed"), "true", "platform selector did not become interactive");
      for (const [platform, expected] of [
        ["macOS", "shasum -a 256 -c -"],
        ["Windows", "Get-FileHash -Algorithm SHA256"],
        ["Linux", "sha256sum -c -"],
      ]) {
        const control = selector.getByRole("button", { name: platform });
        await control.click();
        assert.equal(await control.getAttribute("aria-pressed"), "true");
        const card = section.locator(".platform-install-card");
        assert.equal(await card.getByRole("heading", { name: platform }).count(), 1);
        const command = card.getByRole("button", { name: /^Copy command:/ });
        const displayed = await command.locator("span").first().evaluate((node) =>
          Array.from(node.childNodes).filter((child) => child.nodeType === Node.TEXT_NODE).map((child) => child.textContent).join(""));
        assert.ok(displayed.includes(expected));
        assert.ok(displayed.includes("\n"), `${platform}: command retains line breaks`);
        assert.equal(await command.locator("span").first().evaluate((node) => getComputedStyle(node).whiteSpace), "pre-wrap",
          `${platform}: command displays line breaks`);

        for (const element of [selector, ...await selector.getByRole("button").all(), card, command]) {
          const bounds = await element.evaluate((node) => {
            const rect = node.getBoundingClientRect();
            return { left: rect.left, right: rect.right, width: rect.width };
          });
          assert.ok(bounds.width > 0 && bounds.left >= -1 && bounds.right <= width + 1,
            `${width}px ${platform}: ${await element.getAttribute("class")} extends outside the viewport`);
        }
        const textFits = await command.locator("span").first().evaluate((node) => node.scrollWidth <= node.clientWidth + 1);
        assert.ok(textFits, `${width}px ${platform}: command text overflows its panel`);
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth),
          `${width}px ${platform}: page overflows horizontally`);

        await command.click();
        await page.waitForFunction(async (expected) => (await navigator.clipboard.readText()) === expected, displayed,
          { timeout: 10000 });
      }
    } finally {
      await context.close();
    }
  }
});
