// Exercise the shared scanner/image/clear flow without real codes or devices.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const { chromium } = createRequire(import.meta.url)('playwright');
const browser = await chromium.launch({ headless: true, executablePath: process.env.ELO_QA_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const base = process.env.ELO_QA_URL || 'http://127.0.0.1:1420';
const file = { name: 'synthetic.png', mimeType: 'image/png', buffer: Buffer.from('synthetic decoder input') };
try {
  for (const [width, height, theme, scale] of [[393, 852, 'light', 'normal'], [393, 852, 'dark', 'compact'], [1280, 860, 'light', 'normal']]) {
    const page = await browser.newPage({ viewport: { width, height } });
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    await page.goto(`${base}/tests/code-input.html?theme=${theme}&scale=${scale}${width > 760 ? '&desktop' : ''}`);
    const scan = page.getByRole('button', { name: 'Scan QR', exact: true });
    const choose = page.getByRole('button', { name: 'Choose image', exact: true });
    await choose.waitFor();
    if (width < 760) {
      const a = await scan.boundingBox(), b = await choose.boundingBox();
      const or = await page.locator('.recovery-actions').getByText('or', { exact: true }).boundingBox();
      assert.ok(a.y + a.height < or.y && or.y + or.height < b.y, 'or must separate the two full-width buttons');
      assert.equal(a.width, b.width);
      assert.ok(await scan.evaluate(node => !node.classList.contains('ghost')));
      await scan.click();
    } else {
      assert.equal(await scan.count(), 0);
      await page.locator('input[type=file]').setInputFiles(file);
    }
    await page.getByRole('status').getByText('QR code added', { exact: true }).waitFor();
    assert.equal(await choose.count(), 0);
    assert.equal(await scan.count(), 0);
    assert.equal(await page.getByRole('textbox', { name: 'Paste code', exact: true }).count(), 0);
    const change = page.getByRole('button', { name: 'Use another code', exact: true });
    assert.equal(await change.isEnabled(), true);
    if (process.env.ELO_QA_SCREENSHOTS) await page.screenshot({ path: `${process.env.ELO_QA_SCREENSHOTS}/qr-added-${width}-${theme}.png` });
    await change.click();
    await choose.waitFor();
    assert.equal(await page.getByRole('textbox', { name: 'Paste code', exact: true }).inputValue(), '');
    assert.equal(await page.getByRole('button', { name: 'Use code', exact: true }).isEnabled(), false);
    await page.evaluate(() => { codeInputQA.fail = true; });
    await page.locator('input[type=file]').setInputFiles(file);
    await page.locator('.toast').waitFor();
    assert.equal(await choose.isEnabled(), true);
    assert.equal(await change.count(), 0);
    await page.evaluate(() => { codeInputQA.fail = false; });
    await page.locator('input[type=file]').setInputFiles(file);
    await change.waitFor();
    await page.getByRole('button', { name: 'Use code', exact: true }).click();
    await page.waitForFunction(() => codeInputQA.requests.length === 1);
    assert.equal(await page.evaluate(() => codeInputQA.requests[0].code), 'synthetic-image-code');
    assert.deepEqual(errors, []);
    console.log(`PASS ${width}/${theme}/${scale}: scan/image, clear, retry and selected code submission`);
    await page.close();
  }
  for (const failed of [false, true]) {
    const page = await browser.newPage({ viewport: { width: 393, height: 852 } });
    await page.goto(`${base}/tests/code-input.html?pairing`);
    await page.getByRole('button', { name: /Use another device/ }).click();
    await page.getByRole('button', { name: 'Scan QR', exact: true }).click();
    await page.getByText('Pairing request sent. Accept it on your other device.', { exact: true }).waitFor();
    assert.equal(await page.locator('input[type=password]').count(), 0);
    assert.equal(await page.getByRole('textbox', { name: 'Device name', exact: true }).count(), 0);
    assert.equal(await page.evaluate(() => codeInputQA.requests.length), 1);
    await page.evaluate(fail => { codeInputQA.ready = true; codeInputQA.finishFail = fail; }, failed);
    if (failed) {
      await page.getByText('Could not finish linking. Try again.', { exact: true }).waitFor();
      assert.equal(await page.evaluate(() => codeInputQA.finishes), 1);
      await page.evaluate(() => { codeInputQA.finishFail = false; });
      await page.getByRole('button', { name: 'Try again', exact: true }).click();
    }
    await page.waitForFunction(() => codeInputQA.opened);
    assert.equal(await page.evaluate(() => codeInputQA.finishes), failed ? 2 : 1);
    console.log(`PASS automatic pairing${failed ? ' with explicit retry after failure' : ''}`);
    await page.close();
  }
  for (const accept of [false, true]) {
    const page = await browser.newPage({ viewport: { width: 393, height: 852 } });
    await page.goto(`${base}/tests/code-input.html?source`);
    await page.getByRole('button', { name: 'Link device', exact: true }).click();
    await page.getByText('Waiting for acceptance', { exact: true }).waitFor();
    assert.equal(await page.locator('input[type=password]').count(), 0, 'Pair acceptance must not require another password form');
    if (accept) {
      await page.getByRole('button', { name: 'Accept', exact: true }).click();
      await page.getByText('Accepted', { exact: true }).waitFor();
      assert.equal(await page.locator('.private-qr').count(), 0);
      await page.getByRole('button', { name: 'Delete', exact: true }).click();
      await page.getByRole('dialog', { name: 'Delete this device?', exact: true }).waitFor();
      assert.equal(await page.evaluate(() => codeInputQA.accepted), true);
    } else {
      await page.getByRole('button', { name: 'Delete', exact: true }).click();
      await page.getByRole('dialog', { name: 'Delete pairing request?', exact: true }).getByRole('button', { name: 'Delete', exact: true }).click();
      await page.getByRole('button', { name: 'Link device', exact: true }).waitFor();
      assert.equal(await page.getByText('Waiting for acceptance', { exact: true }).count(), 0);
      assert.equal(await page.evaluate(() => codeInputQA.rejected), true);
    }
    console.log(`PASS source device ${accept ? 'acceptance and Delete availability' : 'pending request deletion'}`);
    await page.close();
  }
} finally { await browser.close(); }
