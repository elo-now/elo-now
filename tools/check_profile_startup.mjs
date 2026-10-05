// Delayed local IPC reproduces a cold start on a slow device; no real profiles.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const { chromium } = createRequire(import.meta.url)('playwright');
const browser = await chromium.launch({ headless: true, executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
try {
  for (const fresh of [false, true]) {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await page.addInitScript(() => {
      window.startupFrames = [];
      window.launchReveals = [];
      window.eloAppearance = {
        setDarkMode() {},
        revealApp() {
          window.launchReveals.push({
            pending: document.querySelector('.unlock-content')?.getAttribute('aria-busy') === 'true',
            forms: document.querySelectorAll('.unlock form').length,
          });
        },
      };
      const record = () => {
        if (document.querySelector('.unlock')) window.startupFrames.push({
          pending: document.querySelector('.unlock-content')?.getAttribute('aria-busy') === 'true',
          forms: document.querySelectorAll('.unlock form').length,
          registration: document.querySelectorAll('.unlock-content[data-registration="true"] form').length,
        });
        requestAnimationFrame(record);
      };
      requestAnimationFrame(record);
    });
    await page.goto(`http://127.0.0.1:1420/tests/desktop.html?mobile&profile-delay=1500&cleanup-delay=5000${fresh ? '&new-profile' : ''}`);
    await page.locator('.unlock-content[aria-busy="true"]').waitFor();
    assert.equal(await page.locator('.unlock form').count(), 0);
    // Password access is ready without waiting for obsolete keychain cleanup.
    await page.getByRole('button', { name: fresh ? 'Create' : 'Unlock', exact: true }).waitFor({ timeout: 3000 });
    assert.equal(await page.getByLabel('Repeat password', { exact: true }).count(), fresh ? 1 : 0);
    const frames = await page.evaluate(() => window.startupFrames);
    assert.ok(frames.some(frame => frame.pending));
    assert.ok(frames.every(frame => !frame.pending || frame.forms === 0));
    if (!fresh) assert.ok(frames.every(frame => frame.registration === 0), 'Registration flashed before Unlock');
    await page.waitForFunction(() => window.launchReveals.length > 0);
    assert.ok((await page.evaluate(() => window.launchReveals)).every(frame => !frame.pending && frame.forms === 1), 'Native cover was removed before the form committed');
    await page.close();
  }
  // Exercise the actual injected iOS bridge together with the web theme startup.
  const nativeSource = readFileSync(new URL('../crates/tauri-plugin-elo-privacy/ios/Sources/PrivacyPlugin.swift', import.meta.url), 'utf8');
  const appearanceBridge = nativeSource.match(/let script = """([\s\S]*?)"""/)[1];
  for (const preference of ['dark', 'light', 'auto']) {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 }, colorScheme: preference === 'light' ? 'dark' : 'light' });
    await page.addInitScript((bridge) => {
      window.nativePreferences = [];
      window.webkit = { messageHandlers: { eloAppearance: { postMessage(value) { window.nativePreferences.push(value); } } } };
      (0, eval)(bridge);
    }, appearanceBridge);
    await page.goto(`http://127.0.0.1:1420/tests/desktop.html?mobile&profile-delay=500&theme=${preference}`);
    await page.getByRole('button', { name: 'Unlock', exact: true }).waitFor();
    assert.equal(await page.locator('html').getAttribute('data-theme'), preference === 'auto' ? 'light' : preference);
    assert.equal(await page.evaluate(() => window.nativePreferences.at(-1)), preference,
      'Native presentation must receive the preference, including Auto, not only the resolved color');
    if (preference === 'auto') {
      await page.emulateMedia({ colorScheme: 'dark' });
      await page.waitForFunction(() => document.documentElement.dataset.theme === 'dark');
      assert.equal(await page.evaluate(() => window.nativePreferences.at(-1)), 'auto');
    }
    await page.reload();
    await page.getByRole('button', { name: 'Unlock', exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.nativePreferences.at(-1)), preference);
    await page.close();
  }
  const failed = await browser.newPage();
  await failed.addInitScript(() => {
    window.launchReveals = [];
    window.eloAppearance = { setDarkMode() {}, revealApp() { window.launchReveals.push(true); } };
  });
  await failed.goto('http://127.0.0.1:1420/tests/desktop.html?mobile&profile-error');
  await failed.waitForFunction(() => window.launchReveals.length > 0);
  await failed.locator('.toast[data-tone="error"]').waitFor();
  assert.equal(await failed.locator('.unlock form').count(), 0, 'Failed discovery must not pretend this is a new profile');
  await failed.close();
  console.log('PASS: Dark/Light/Auto native preference bridge and reload; cold start waits for local profile discovery, with no wrong form or keychain cleanup delay; native cover reveals the form or startup error.');
} finally { await browser.close(); }
