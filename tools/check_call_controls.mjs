// Shared session controls and full-screen layout; no network or capture.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const { chromium } = createRequire(import.meta.url)('playwright');
const base = process.env.ELO_QA_URL || 'http://127.0.0.1:1420';
const browser = await chromium.launch({ headless: true, executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
try {
  for (const width of [320, 393, 1280]) {
    const page = await browser.newPage({ viewport: { width, height: 844 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => new URL(route.request().url()).origin === new URL(base).origin ? route.continue() : route.abort());
    page.setDefaultTimeout(6000);
    await page.goto(base + '/tests/calls.html');
    await page.waitForFunction(() => window.callQA);
    await page.evaluate(() => window.callQA.calls.change({ phase: 'connecting' }));
    const preparing = page.locator('.call-widget');
    await preparing.locator('.call-widget-heading small').getByText('Establishing connection…', { exact: true }).waitFor();
    assert.equal(await preparing.locator('.call-widget-controls button').count(), 1);
    assert.equal(await preparing.getByRole('button', { name: 'Open call', exact: true }).isDisabled(), true);
    const pendingFont = await preparing.locator('.call-widget-heading strong').evaluate(node => getComputedStyle(node).fontSize);
    await page.evaluate(() => window.callQA.compact());
    await page.waitForFunction(() => document.documentElement.dataset.uiScale === 'compact');
    const compactPendingFont = await preparing.locator('.call-widget-heading strong').evaluate(node => getComputedStyle(node).fontSize);
    assert.ok(parseFloat(compactPendingFont) < parseFloat(pendingFont), 'Pending call ignores interface size');
    await preparing.getByRole('button', { name: 'Cancel call', exact: true }).click();
    await preparing.waitFor({ state: 'detached' });
    await page.evaluate(() => window.callQA.start());
    const dock = page.locator('.call-widget');
    assert.equal(await dock.locator('.call-widget-heading strong').evaluate(node => getComputedStyle(node).fontSize), compactPendingFont, 'Call title changes size after connection');
    assert.deepEqual(await dock.locator('.call-widget-controls > button.icon').evaluateAll(nodes => nodes.map(n => n.getAttribute('aria-label'))), ['Mute microphone', 'Mute session audio', 'Leave session']);
    await dock.getByRole('button', { name: 'Mute session audio', exact: true }).click();
    const audioMuted = () => page.locator('.call-media video').evaluateAll(nodes => nodes.length > 0 && nodes.every(n => n.muted));
    assert.equal(await audioMuted(), true);
    assert.equal(await page.evaluate(() => window.callQA.toggleCount()), 0, 'Speaker mute changed microphone or signaling');
    await dock.getByRole('button', { name: 'Open call', exact: true }).click();
    const full = page.locator('.call-dialog');
    await full.getByRole('button', { name: 'Unmute session audio', exact: true }).waitFor();
    const controls = await full.locator('.call-controls > button').evaluateAll(nodes => nodes.map(n => n.getAttribute('aria-label')));
    assert.deepEqual(controls, width < 768 ? ['Mute microphone', 'Unmute session audio', 'Turn camera off', 'Leave session'] : ['Mute microphone', 'Unmute session audio', 'Turn camera off', 'Share screen', 'Leave session']);
    await page.evaluate(() => window.callQA.reconnect());
    await page.waitForTimeout(100);
    assert.equal(await audioMuted(), true, 'Reconnected audio escaped speaker mute');
    await full.getByRole('button', { name: 'Unmute session audio', exact: true }).click();
    assert.equal(await audioMuted(), false);
    const geometry = await full.evaluate(node => {
      const buttons = [...node.querySelectorAll('.call-controls > button'), node.querySelector('.close')];
      return buttons.map(button => { const r = button.getBoundingClientRect(); return { x: r.x, right: r.right, y: r.y, width: r.width, height: r.height }; });
    });
    for (let i = 0; i < geometry.length; i++) {
      const a = geometry[i];
      assert.ok(a.x >= 0 && a.right <= width && Math.abs(a.width - a.height) < 1, `Clipped/non-square control at ${width}`);
      for (const b of geometry.slice(i + 1)) assert.ok(a.right <= b.x || b.right <= a.x, `Controls overlap at ${width}`);
    }
    await page.screenshot({ path: `/private/tmp/elo-call-controls-${width}.png` });
    await full.getByRole('button', { name: 'Mute session audio', exact: true }).click();
    await full.getByRole('button', { name: 'Collapse session', exact: true }).click();
    await dock.getByRole('button', { name: 'Unmute session audio', exact: true }).waitFor();
    await page.evaluate(() => window.callQA.start('new-call'));
    await dock.getByRole('button', { name: 'Mute session audio', exact: true }).waitFor();
    await page.evaluate(() => window.callQA.clear());
    await dock.waitFor({ state: 'detached' });
    assert.deepEqual(errors, []);
    console.log(`Passed ${width}px: floating controls, speaker isolation/reconnect, compact and full-screen layouts, no overlap`);
    await page.close();
  }
} finally { await browser.close(); }
