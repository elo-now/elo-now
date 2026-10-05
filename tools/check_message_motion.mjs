// Live arrivals enter once; history, saved receipts and navigation remain still.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const { chromium } = createRequire(import.meta.url)('playwright');
const browser = await chromium.launch({ headless: true, executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const base = process.env.ELO_QA_URL || 'http://127.0.0.1:1420';
try {
  for (const width of [393, 1280]) for (const reducedMotion of ['no-preference', 'reduce']) {
    const page = await browser.newPage({ viewport: { width, height: 844 }, reducedMotion });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    page.setDefaultTimeout(6000);
    await page.goto(`${base}/tests/desktop.html?paged${width < 768 ? '&mobile' : ''}`);
    await page.getByLabel('Password', { exact: true }).fill('fictional desktop password');
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    const open = async name => {
      if (width < 768) await page.locator('.channel-list button').filter({ has: page.getByText(name, { exact: true }) }).click();
      else await page.getByRole('button', { name, exact: true }).click();
      await page.locator('.conversation .messages').waitFor();
      await page.waitForFunction(() => !document.querySelector('.conversation .history-loading'));
    };
    await open('General');
    await page.evaluate(() => {
      window.motionRecords = [];
      document.addEventListener('animationstart', event => {
        if (event.animationName === 'message-enter') window.motionRecords.push(event.target.dataset.recordId);
      });
      window.__desktopQA.latency.send = 400;
    });
    const count = () => page.evaluate(() => window.motionRecords.length);
    await page.locator('.composer textarea').fill('Immediate local motion');
    await page.locator('.composer').getByRole('button', { name: 'Send', exact: true }).click();
    await page.locator('.messages .message').filter({ hasText: 'Immediate local motion' }).waitFor();
    await page.waitForTimeout(600);
    assert.equal(await count(), reducedMotion === 'reduce' ? 0 : 1, 'Local echo enters once, without replay after receipt');
    const live = await page.evaluate(() => window.__desktopQA.backgroundMessage(true));
    await page.locator(`.messages [data-record-id="${live}"]`).waitFor();
    await page.waitForTimeout(250);
    assert.equal(await count(), reducedMotion === 'reduce' ? 0 : 2, 'Verified live arrival enters once');
    const baseline = await count();
    const old = await page.evaluate(() => window.__desktopQA.backgroundMessage(false));
    await page.locator(`.messages [data-record-id="${old}"]`).waitFor();
    await page.waitForTimeout(200);
    assert.equal(await count(), baseline, 'History refresh must not animate new row IDs');
    if (width < 768) await page.locator('.conversation [data-system-back]').click();
    await open('Design');
    if (width < 768) await page.locator('.conversation [data-system-back]').click();
    await open('General');
    await page.waitForTimeout(200);
    assert.equal(await count(), baseline, 'Returning to a chat must not replay history motion');
    assert.deepEqual(errors, []);
    console.log(`PASS ${width}px/${reducedMotion}: local echo, verified live receipt, history refresh, chat remount`);
    await page.close();
  }
} finally { await browser.close(); }
