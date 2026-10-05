// Isolated desktop/mobile rendering with mocked IPC; no production account data.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const { chromium } = createRequire(import.meta.url)('playwright');
const browser = await chromium.launch({ headless: true, executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
try {
  for (const width of [320, 390, 1280]) {
    const mobile = width < 768;
    const page = await browser.newPage({ viewport: { width, height: 844 }, hasTouch: mobile });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`http://127.0.0.1:1420/tests/desktop.html?paged&inline-images&composer-blur${mobile ? '&mobile' : ''}`);
    await page.getByLabel('Password', { exact: true }).fill('fictional desktop password');
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    if (mobile) await page.locator('.channel-list button').filter({ has: page.getByText('General', { exact: true }) }).click();
    else await page.getByRole('button', { name: 'General', exact: true }).click();
    const composer = page.locator('.conversation .composer');
    const input = composer.locator('textarea');
    const before = await input.evaluate(node => node.getBoundingClientRect().height);
    const group = composer.getByRole('group', { name: 'Keep:' });
    assert.equal(await group.isVisible(), true, 'Expiry must be visible before focusing');
    const initialBounds = await input.boundingBox();
    if (mobile) await input.tap();
    else await input.click();
    assert.ok(await input.evaluate(node => node === document.activeElement),
      'The first tap must focus the input');
    await page.keyboard.type('First tap');
    assert.equal(await input.inputValue(), 'First tap');
    assert.deepEqual(await input.boundingBox(), initialBounds, 'Focus must not move the input');
    await input.fill('');
    const after = await input.evaluate(node => node.getBoundingClientRect().height);
    assert.equal(after, before, "Focus must not change input height");
    await input.fill('First line\nSecond line\nThird line');
    assert.ok(await input.evaluate(node => node.getBoundingClientRect().height) > before,
      'Content must grow the input without a focus multiplier');
    await input.fill('');
    assert.equal(await input.evaluate(node => node.getBoundingClientRect().height), before,
      'Deleting text must restore the one-line height');
    if (mobile) {
      await page.setViewportSize({ width, height: 480 });
      const list = page.locator('.conversation .messages');
      await page.waitForFunction(() => {
        const node = document.querySelector('.conversation .messages');
        return Math.abs(node.scrollHeight - node.clientHeight - node.scrollTop) <= 1;
      });
      // Reproduce WebKit firing a scroll after layout, before ResizeObserver.
      await list.evaluate(node => {
        node.style.maxHeight = '180px';
        node.dispatchEvent(new Event('scroll'));
      });
      await page.waitForFunction(() => {
        const node = document.querySelector('.conversation .messages');
        return Math.abs(node.scrollHeight - node.clientHeight - node.scrollTop) <= 1;
      });
      await list.evaluate(node => {
        node.scrollTop -= 250;
        node.dispatchEvent(new Event('scroll'));
      });
      const readingTop = await list.evaluate(node => node.scrollTop);
      await page.setViewportSize({ width, height: 420 });
      await list.evaluate(node => {
        node.style.maxHeight = '140px';
        node.dispatchEvent(new Event('scroll'));
      });
      await page.waitForTimeout(100);
      assert.ok(Math.abs(await list.evaluate(node => node.scrollTop) - readingTop) <= 2,
        'Keyboard resizing must preserve the older reading position');
      await list.evaluate(node => {
        node.style.removeProperty('max-height');
        node.scrollTop = node.scrollHeight;
        node.dispatchEvent(new Event('scroll'));
      });
      await page.setViewportSize({ width, height: 844 });
    }
    await group.waitFor();
    assert.deepEqual(await group.getByRole('button').allTextContents(), ['∞', '1h', '24h']);
    assert.equal(await group.getByRole('button', { name: 'No expiry', exact: true }).getAttribute('aria-pressed'), 'true');
    await group.getByRole('button', { name: '1h', exact: true }).click();
    assert.ok(await input.evaluate(node => node === document.activeElement),
      'Pointer selection must keep focus and the software keyboard on the draft');
    await group.getByRole('button', { name: '24h', exact: true }).click();
    assert.equal(await group.locator('[aria-pressed="true"]').count(), 1);
    await group.getByRole('button', { name: '24h', exact: true }).click();
    assert.equal(await group.getByRole('button', { name: 'No expiry', exact: true }).getAttribute('aria-pressed'), 'true');
    assert.ok(await input.evaluate(node => node === document.activeElement),
      'Deselecting the last chip must not blur or collapse the draft');
    assert.ok(await input.evaluate(node => node.getBoundingClientRect().height) === before,
      'A null-focus interval during deselection must keep the input height');
    await page.getByText('Conversation message 39', { exact: true }).click();
    assert.equal(await group.isVisible(), true, 'Expiry must remain visible after leaving the input');
    await input.focus();
    await group.getByRole('button', { name: '24h', exact: true }).click();
    assert.ok(await input.evaluate(node => node.getBoundingClientRect().height) === before,
      'Choosing a chip must keep the input height');
    const chips = await group.getByRole('button').evaluateAll(nodes => nodes.map(node => {
      const rect = node.getBoundingClientRect();
      return { top: rect.top, right: rect.right, left: rect.left, width: rect.width, height: rect.height };
    }));
    assert.ok(chips.every(chip => chip.width > chip.height && chip.top === chips[0].top),
      'Expiry chips must stay horizontal and wider than tall');
    assert.ok(chips.slice(1).every((chip, index) => chip.left - chips[index].right >= 8),
      'Expiry chips must have space between them');
    await input.fill('Expiring composer test');
    const bounds = await composer.evaluate(node => ({ right: node.getBoundingClientRect().right, width: document.documentElement.clientWidth,
      controls: [...node.querySelectorAll('button')].map(button => button.getBoundingClientRect().right) }));
    assert.ok(bounds.right <= bounds.width && bounds.controls.every(right => right <= bounds.right), `${width}: controls overflow`);
    await page.screenshot({ path: `/private/tmp/elo-expiry-${width}.png` });
    await composer.getByRole('button', { name: 'Send', exact: true }).click();
    const request = await page.evaluate(() => window.__desktopQA.calls.filter(call => call.request?.op === 'send').at(-1)?.request);
    assert.equal(request?.expires_in_hours, 24, 'Selected expiry must reach the native send command');
    const keepId = await page.evaluate(() => window.__desktopQA.ownMessage('chat.message', { text: 'Keep dialog fixture' }));
    const keepRow = page.locator(`[data-record-id="${keepId}"]`);
    await keepRow.getByText('Keep dialog fixture', { exact: true }).waitFor();
    const expiryRequests = () => page.evaluate(target => window.__desktopQA.calls
      .filter(call => call.request?.op === 'message_action' && call.request.action?.type === 'expiry' && call.request.action.target === target)
      .map(call => call.request), keepId);
    const openKeep = async () => {
      await keepRow.locator('.message-more').click();
      await page.getByRole('menuitem', { name: 'Keep', exact: true }).click();
      const dialog = page.getByRole('dialog', { name: 'Keep', exact: true });
      await dialog.getByRole('heading', { name: 'Keep', exact: true }).waitFor();
      return dialog;
    };
    const keepDialog = await openKeep();
    const keepOptions = keepDialog.getByRole('group', { name: 'Keep', exact: true });
    assert.deepEqual(await keepOptions.getByRole('button').allTextContents(), ['No expiry', '1h', '24h']);
    assert.equal(await keepDialog.locator('.message-expiry-picker > p').textContent(), 'The new time starts when you save.');
    assert.equal(await keepDialog.getByText('Choose No expiry to keep this message.', { exact: false }).count(), 0);
    assert.equal(await keepOptions.getByRole('button', { name: 'No expiry', exact: true }).getAttribute('aria-pressed'), 'true');
    assert.equal((await expiryRequests()).length, 0, 'Opening Keep must not change the message');
    await keepOptions.getByRole('button', { name: '1h', exact: true }).click();
    await keepDialog.getByRole('button', { name: 'Save', exact: true }).click();
    await keepDialog.waitFor({ state: 'hidden' });
    assert.deepEqual((await expiryRequests()).at(-1)?.action, { target: keepId, type: 'expiry', hours: 1 },
      'Saving 1h must send the selected expiry for this message');
    await openKeep();
    assert.equal(await keepOptions.getByRole('button', { name: '1h', exact: true }).getAttribute('aria-pressed'), 'true');
    await keepOptions.getByRole('button', { name: 'No expiry', exact: true }).click();
    await keepDialog.getByRole('button', { name: 'Save', exact: true }).click();
    await keepDialog.waitFor({ state: 'hidden' });
    assert.deepEqual((await expiryRequests()).at(-1)?.action, { target: keepId, type: 'expiry', hours: null },
      'No expiry must explicitly cancel the existing deadline');
    await keepRow.locator('.message-expiry').waitFor({ state: 'hidden' });
    await openKeep();
    assert.equal(await keepOptions.getByRole('button', { name: 'No expiry', exact: true }).getAttribute('aria-pressed'), 'true');
    const beforeCancel = (await expiryRequests()).length;
    await keepOptions.getByRole('button', { name: '24h', exact: true }).click();
    await keepDialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    await keepDialog.waitFor({ state: 'hidden' });
    assert.equal((await expiryRequests()).length, beforeCancel, 'Cancel must discard the unsaved choice without an expiry action');
    await openKeep();
    assert.equal(await keepOptions.getByRole('button', { name: 'No expiry', exact: true }).getAttribute('aria-pressed'), 'true');
    await keepDialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    await keepDialog.waitFor({ state: 'hidden' });
    // Seed a supported legacy value through the existing IPC fixture, outside the available UI choices.
    await page.evaluate(async target => {
      const previous = window.__desktopQA.calls.filter(call => call.request?.op === 'message_action' && call.request.action?.target === target).at(-1).request;
      const response = await window.__TAURI_INTERNALS__.invoke('operate', {
        request: { ...previous, action: { target, type: 'expiry', hours: 12 } },
      });
      await window.__TAURI_INTERNALS__.invoke('plugin:event|emit', {
        event: 'desktop-sync', payload: { view: response.view, identity: response.view.identity, result: {} },
      });
    }, keepId);
    await keepRow.locator('.message-expiry').waitFor();
    const beforeLegacy = (await expiryRequests()).length;
    await openKeep();
    assert.equal(await keepOptions.locator('[aria-pressed="true"]').count(), 0,
      'A legacy 12h duration must not appear as a different selected choice');
    assert.equal(await keepDialog.getByRole('button', { name: 'Save', exact: true }).isDisabled(), true,
      'A hidden legacy duration requires an explicit available choice before Save');
    await keepDialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    await keepDialog.waitFor({ state: 'hidden' });
    assert.equal((await expiryRequests()).length, beforeLegacy, 'Opening and cancelling legacy expiry must preserve it without a write');
    await openKeep();
    assert.equal(await keepDialog.getByRole('button', { name: 'Save', exact: true }).isDisabled(), true);
    await keepOptions.getByRole('button', { name: '24h', exact: true }).click();
    assert.equal(await keepDialog.getByRole('button', { name: 'Save', exact: true }).isEnabled(), true);
    await keepDialog.getByRole('button', { name: 'Save', exact: true }).click();
    await keepDialog.waitFor({ state: 'hidden' });
    assert.deepEqual((await expiryRequests()).at(-1)?.action, { target: keepId, type: 'expiry', hours: 24 },
      'An explicit choice must replace legacy expiry with the selected duration');
    const id = await page.evaluate(() => window.__desktopQA.ownMessage('chat.message', { text: 'Expiry content must disappear', expiresAt: Date.now() + 2000 }));
    const row = page.locator(`[data-record-id="${id}"]`);
    await row.getByText('Expiry content must disappear', { exact: true }).waitFor();
    await row.locator('.message-more').click();
    await page.getByRole('dialog').waitFor();
    await row.getByText('Message expired', { exact: true }).waitFor();
    await page.getByRole('dialog').waitFor({ state: 'hidden' });
    assert.equal(await row.getByText('Expiry content must disappear', { exact: true }).count(), 0);
    assert.equal(await row.locator('.message-controls').count(), 0);
    const attachment = await page.evaluate(() => window.__desktopQA.ownMessage('file.shared', { attachmentExpiresAt: Date.now() + 1200 }));
    const file = page.locator(`[data-record-id="${attachment}"]`);
    await file.getByText(/^Expires:/).waitFor();
    await file.getByText('Expired', { exact: true }).waitFor();
    assert.equal(await file.locator('button.attachment').isDisabled(), true);
    const cachedId = await page.evaluate(() => window.__desktopQA.ownMessage('file.shared', { attachmentExpiresAt: Date.now() + 2000 }));
    const cached = page.locator(`[data-record-id="${cachedId}"]`);
    await cached.locator('button.attachment').click();
    await cached.locator('.attachment-active').waitFor();
    await page.evaluate(() => window.__desktopQA.finishTransfers());
    await cached.locator('.attachment-preview img').waitFor();
    await cached.getByText('Expired', { exact: true }).waitFor();
    await cached.locator('.attachment-preview img').focus();
    await page.keyboard.press('Enter');
    await page.waitForFunction(() => window.__desktopQA.calls.some(call => call.command === 'share_cached_attachment'));
    assert.deepEqual(errors, [], `${width}: unhandled page errors`);
    console.log(`PASS ${width}: platform-appropriate focus sizing, exclusive/toggle expiry chips, Keep save/cancel/null and legacy expiry, native payload, live message and attachment expiry, menu closes, cached image remains shareable, no overflow`);
    await page.close();
  }
} finally { await browser.close(); }
