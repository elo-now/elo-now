// Synthetic keyboard geometry complements, but does not replace, native iOS QA.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
const { chromium } = createRequire(import.meta.url)('playwright');
const macChrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const browser = await chromium.launch({
  executablePath: process.env.CHROME_PATH ?? (existsSync(macChrome) ? macChrome : undefined),
  headless: true,
});
const origin = process.env.ELO_QA_ORIGIN || 'http://127.0.0.1:1437';
const results = [];
try {
  for (const width of [320, 390, 1440]) {
    const page = await browser.newPage({ viewport: { width, height: 850 }, hasTouch: true });
    await page.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
    await page.addInitScript(() => {
      const viewport = window.visualViewport;
      const realHeight = Object.getOwnPropertyDescriptor(VisualViewport.prototype, 'height').get;
      Object.defineProperty(viewport, 'height', { get: () => window.__qaHeight ?? realHeight.call(viewport) });
      window.__qaResize = height => { window.__qaHeight = height; viewport.dispatchEvent(new Event('resize')); };
    });
    await page.goto(`${origin}/marketing/?audience=work`);
    await page.getByLabel('Password', { exact: true }).fill('fictional-only');
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    if (width < 768) {
      await page.getByRole('button', { name: 'Recent and ungrouped chats', exact: true }).click();
      await page.getByRole('button', { name: /^Chat Launch day / }).click();
    } else await page.getByText('Launch day', { exact: true }).click();
    const input = page.locator('.conversation .composer textarea');
    const group = page.getByRole('group', { name: 'Keep:', exact: true });
    await input.fill('Short draft');
    await page.evaluate(() => window.__qaResize(500));
    await page.waitForFunction(() => document.documentElement.dataset.keyboardOpen === 'true');
    // Let the initial keyboard opening and bottom alignment finish before the
    // measured Keep taps; that first resize is intentionally allowed to scroll.
    await page.waitForTimeout(150);
    await page.evaluate(() => {
      const input = document.querySelector('.conversation .composer textarea');
      window.__qaStyles = [];
      window.__qaStyleObserver = new MutationObserver(records => window.__qaStyles.push(...records.map(record => record.oldValue)));
      window.__qaStyleObserver.observe(input, { attributes: true, attributeFilter: ['style'], attributeOldValue: true });
      window.__qaSamples = [];
      window.__qaSampling = true;
      const sample = () => {
        const list = document.querySelector('.conversation .messages');
        window.__qaSamples.push({
          height: input.getBoundingClientRect().height,
          listHeight: list.getBoundingClientRect().height,
          scroll: list.scrollTop,
          keyboard: document.documentElement.dataset.keyboardOpen,
        });
        if (window.__qaSampling) requestAnimationFrame(sample);
      };
      sample();
      // iOS can briefly blur before the click restores focus, with the keyboard
      // still visible. Wait multiple frames to expose a premature inset reset.
      input.blur();
    });
    await page.waitForTimeout(80);
    assert.equal(await page.evaluate(() => document.documentElement.dataset.keyboardOpen), 'true');
    for (const name of ['24h', '1h', 'No expiry']) {
      await group.getByRole('button', { name, exact: true }).tap();
      await page.waitForTimeout(80);
    }
    const trace = await page.evaluate(() => { window.__qaSampling = false; return window.__qaSamples; });
    for (const field of ['height', 'listHeight', 'scroll']) {
      const values = trace.map(row => row[field]);
      assert.ok(Math.max(...values) - Math.min(...values) <= 1, `${width}: ${field} moved during Keep/blur: ${JSON.stringify(trace)}`);
    }
    assert.ok(trace.every(row => row.keyboard === 'true'));
    // Subpixel visualViewport changes must not reset the live textarea height.
    for (const height of [500.25, 499.75, 500]) {
      await page.evaluate(height => window.__qaResize(height), height);
      await page.waitForTimeout(40);
    }
    assert.equal(await page.evaluate(() => window.__qaStyles.length), 0, 'Unchanged content height must not be rewritten');
    const minimum = await input.evaluate(node => node.getBoundingClientRect().height);
    await input.fill('First line\nSecond line\nThird line');
    const grown = await input.evaluate(node => node.getBoundingClientRect().height);
    assert.ok(grown > minimum, 'Multiline text must grow');
    await input.fill(Array(30).fill('A wrapped line of text').join('\n'));
    assert.ok(await input.evaluate(node => node.scrollHeight > node.clientHeight && getComputedStyle(node).overflowY === 'auto'));
    await input.fill('');
    assert.equal(await input.evaluate(node => node.getBoundingClientRect().height), minimum, 'Clearing must shrink');
    assert.ok(await page.evaluate(() => window.__qaStyles.every(style => !/\bheight:\s*0px\b/.test(style ?? ''))), 'The live textarea was temporarily collapsed');
    await page.evaluate(() => window.__qaResize(850));
    await page.waitForFunction(() => document.documentElement.dataset.keyboardOpen === 'false');
    assert.ok(await input.evaluate(node => node === document.activeElement), 'Dismissal detection must not require blur');
    results.push({ width, frames: trace.length, keepStable: true, viewportCapStable: true, growsAndShrinks: true, noLiveCollapse: true });
    await page.close();
  }
  console.log(JSON.stringify(results, null, 2));
} finally {
  await browser.close();
}
