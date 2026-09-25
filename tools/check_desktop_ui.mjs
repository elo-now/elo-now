// Real React/CSS navigation with fictional, stateful IPC. No server or user data.
// Start Vite, then run with NODE_PATH pointing to Playwright when installed outside the project.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
const { chromium } = createRequire(import.meta.url)('playwright');
const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_PATH ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const origin = process.env.DESKTOP_TEST_URL ?? 'http://127.0.0.1:1420';
const screenshots = process.env.DESKTOP_SCREENSHOTS;
if (screenshots) await mkdir(screenshots, { recursive: true });
const errors = [], checks = [];
const check = async (name, fn) => { await fn(); checks.push(name); };
async function openPage(width, height, theme = 'light', mobile = false, platform = '', paged = false) {
  const context = await browser.newContext({ viewport: { width, height }, hasTouch: mobile });
  const page = await context.newPage(); page.setDefaultTimeout(5000);
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(`${origin}/tests/desktop.html?theme=${theme}${mobile ? '&mobile' : ''}&platform=${platform}${paged ? '&paged' : ''}`);
  await page.getByLabel('Password', { exact: true }).fill('fictional desktop password');
  await page.getByRole('button', { name: 'Unlock', exact: true }).click();
  await page.locator('.shell').waitFor();
  return { page, context };
}
async function menu(page, name) {
  await page.locator('.desktop-workspace-trigger').click();
  await page.locator('.desktop-workspace-menu').getByRole('button', { name, exact: true }).click();
  await page.getByRole('heading', { name, exact: true }).waitFor({ state: 'visible' });
}
async function editProfile(page) {
  await page.locator('.desktop-workspace-trigger').click();
  await page.locator('.desktop-workspace-profile').hover();
  await page.getByRole('button', { name: 'Edit profile', exact: true }).click();
  await page.locator('.desktop-profile-editor').waitFor({ state: 'visible' });
}
async function spaces(page) {
  await page.locator('.desktop-workspace-trigger').click();
  await page.locator('.desktop-current-space').hover();
  await page.getByRole('button', { name: 'Manage Spaces', exact: true }).click();
}
async function screenshot(page, name) { if (screenshots) await page.screenshot({ path: `${screenshots}/${name}.png` }); }
async function headerSearch(page, label) {
  const input = page.locator('.content-pane:visible .screen-header').getByRole('searchbox', { name: label, exact: true });
  const search = await input.boundingBox();
  const sidebar = await page.locator('.desktop-sidebar-search input').boundingBox();
  const header = await page.locator('.content-pane:visible .screen-header').boundingBox();
  assert.ok(Math.abs(search.width - sidebar.width) < 2, 'Header search width differs from sidebar');
  assert.ok(search.y >= header.y && search.y + search.height <= header.y + header.height, 'Search is outside header');
  const group = page.locator('.content-pane:visible .screen-header-actions');
  const groupBox = await group.boundingBox();
  assert.ok(header.x + header.width - groupBox.x - groupBox.width <= 20, 'Header actions are not right-aligned');
  for (const button of await group.locator(':scope > button').all()) {
    const box = await button.boundingBox();
    if (box) assert.ok(search.x + search.width <= box.x, 'Header search must precede action icons');
  }
}
async function assertPane(page) {
  await page.locator('.desktop-sidebar').waitFor({ state: 'visible' });
  assert.equal(await page.locator('dialog[open]').count(), 0, 'Top-level destination opened as a dialog');
  const geometry = await page.evaluate(() => {
    const sidebar = document.querySelector('.desktop-sidebar').getBoundingClientRect();
    const candidates = document.querySelectorAll('.shell > .details, .shell > .conversation, .shell > .contacts-page, .shell > .message-stream, .shell > .invitation-page, .shell > .members-page, #desktop-page-outlet > .desktop-page');
    const visible = [...candidates].filter(node => node.checkVisibility() && getComputedStyle(node).visibility === "visible").map(node => { const r = node.getBoundingClientRect(); return { x: r.x, width: r.width, bottom: r.bottom }; });
    return { sidebar: sidebar.right, width: innerWidth, height: innerHeight, overflow: document.documentElement.scrollWidth > innerWidth, visible };
  });
  assert.equal(geometry.overflow, false, 'Horizontal page overflow');
  assert.equal(geometry.visible.length, 1, `Expected one active content pane: ${JSON.stringify(geometry)}`);
  assert.ok(Math.abs(geometry.visible[0].x - geometry.sidebar) < 2, 'Content is outside the main column');
  assert.ok(geometry.visible[0].bottom <= geometry.height + 1, 'Page extends below the window');
}
async function contentGeometry(page) {
  return page.evaluate(() => {
    const visible = node => node.checkVisibility() && getComputedStyle(node).visibility === 'visible';
    const pane = [...document.querySelectorAll('.shell .content-pane')].find(visible);
    const body = pane.querySelector('.page-content, .settings-page');
    const header = pane.querySelector('.screen-header');
    const rect = node => { const r = node.getBoundingClientRect(); return { x: r.x, y: r.y, width: r.width, height: r.height }; };
    const style = getComputedStyle(body), background = getComputedStyle(pane);
    return { pane: rect(pane), header: rect(header), body: rect(body), padding: [style.paddingTop, style.paddingRight, style.paddingBottom, style.paddingLeft], background: background.backgroundColor, headerBackground: getComputedStyle(header).backgroundColor, motif: background.backgroundImage };
  });
}
try {
  for (const [width, height, theme] of [[1280, 860, 'light'], [820, 620, 'light'], [1600, 1000, 'dark']]) {
    const { page, context } = await openPage(width, height, theme);
    await check(`${width}/${theme}: shared Contacts, Buzz and menu layout`, async () => {
      let reference;
      for (const name of ['Contacts', 'Buzz', 'Reminders', 'Notifications', 'Invitations', 'Settings']) {
        if (name === 'Contacts' || name === 'Buzz') {
          await page.locator('.desktop-sidebar').getByRole('button', { name, exact: true }).click();
        } else await menu(page, name);
        await assertPane(page);
        if (name === 'Contacts') {
          await headerSearch(page, 'Search contacts');
          assert.equal(await page.locator('.contacts-page .screen-header button').count(), 1);
          await page.locator('.contacts-page .screen-header').getByRole('button', { name: 'Add contact', exact: true }).waitFor();
        }
        if (name === 'Buzz') assert.equal(await page.locator('.message-stream .screen-header button').count(), 1);
        if (name === 'Buzz' || name === 'Reminders') {
          const card = page.locator('.content-pane:visible .stream-card').first();
          await card.waitFor({ state: 'visible' });
          assert.equal(await card.evaluate(node => getComputedStyle(node.parentElement).opacity), '1');
        }
        const layout = await contentGeometry(page);
        assert.deepEqual(layout.padding, ['24px', '24px', '24px', '24px'], `${name} uses different body padding`);
        assert.equal(layout.header.x, layout.pane.x, `${name} header is inset`);
        assert.equal(layout.header.width, layout.pane.width, `${name} header is not full width`);
        assert.equal(layout.header.height, 68, `${name} header height differs`);
        assert.equal(layout.headerBackground, layout.background, `${name} header has a different background`);
        if (reference) {
          assert.deepEqual(layout.body, reference.body, `${name} has a different content area`);
          assert.equal(layout.background, reference.background, `${name} background differs`);
          assert.equal(layout.motif, reference.motif, `${name} decoration differs`);
        } else reference = layout;
        await screenshot(page, `${name.toLowerCase()}-${width}-${theme}`);
      }
    });
    await check(`${width}: background sync does not animate manual refresh`, async () => {
      await page.evaluate(() => Object.assign(window.__desktopQA.latency, { invitation_activity: 600, invitation_sync: 400 }));
      await menu(page, 'Notifications');
      const refresh = page.locator('.invitation-page .desktop-refresh-button');
      const box = await refresh.boundingBox();
      assert.equal(await refresh.isEnabled(), true);
      assert.equal(await refresh.getAttribute('aria-busy'), 'false');
      assert.equal(await refresh.locator('svg').evaluate(node => getComputedStyle(node).animationName), 'none');
      await refresh.click();
      assert.equal(await refresh.getAttribute('aria-busy'), 'true');
      assert.deepEqual(await refresh.boundingBox(), box);
      await page.waitForFunction(() => document.querySelector('.invitation-page .desktop-refresh-button')?.getAttribute('aria-busy') === 'false');
      assert.deepEqual(await refresh.boundingBox(), box);
      await page.evaluate(() => Object.assign(window.__desktopQA.latency, { invitation_activity: 0, invitation_sync: 0 }));
    });
    await check(`${width}: Invitations loading and empty state share position`, async () => {
      await page.evaluate(() => { window.__desktopQA.latency.space_manage = 600; });
      await menu(page, 'Invitations');
      const heading = page.locator('.space-join-requests > h3');
      await heading.filter({ hasText: 'Loading' }).waitFor();
      const before = await heading.boundingBox();
      await heading.filter({ hasText: 'No pending requests' }).waitFor();
      assert.deepEqual(await heading.boundingBox(), before);
      assert.equal(await heading.evaluate(node => getComputedStyle(node).textAlign), 'center');
      await page.evaluate(() => { window.__desktopQA.latency.space_manage = 0; });
    });
    for (const name of ['Appearance', 'Settings', 'Devices', 'Recovery', 'Legal', 'Blocked users', 'Reminders', 'Notifications', 'Invitations', 'My code']) {
      await check(`${width}/${theme}: ${name}`, async () => {
        await menu(page, name); await assertPane(page);
        assert.equal(await page.locator('.content-pane:visible .screen-header [data-system-back]').count(), 0, `${name} must use the desktop menu instead of Back`);
        if (name === 'Settings') {
          assert.equal(await page.getByRole('heading', { name: 'Profile identifiers', exact: true }).count(), 0);
          await page.getByRole('checkbox', { name: 'Enable debug mode' }).check();
          await page.getByRole('heading', { name: 'Profile identifiers', exact: true }).waitFor();
          for (const legacy of ['Import configuration', 'Add Replica', 'Export device public key', 'Recovery control']) {
            assert.equal(await page.getByRole('button', { name: legacy, exact: true }).count(), 0);
          }
          await page.getByRole('checkbox', { name: 'Enable debug mode' }).uncheck();
        }
      });
    }
    await check(`${width}: Space list and settings`, async () => {
      await spaces(page); await assertPane(page);
      assert.equal(await page.locator('.spaces-page .screen-header [data-system-back]').count(), 0);
      await screenshot(page, `spaces-${width}`);
      await page.getByRole('button', { name: /Settings.*Studio/i }).click();
      assert.equal(await page.locator('.spaces-page .screen-header [data-system-back]').count(), 1);
      await page.getByRole('button', { name: 'Preview attachment cleanup', exact: true }).click();
      const emptyCleanup = page.locator('.space-attachment-cleanup [role=status]');
      await emptyCleanup.waitFor();
      assert.equal(await emptyCleanup.textContent(), 'No attachments are old enough to remove.');
      assert.equal(await page.locator('.toast').count(), 0);
      assert.ok((await emptyCleanup.boundingBox()).y < (await page.getByRole('button', { name: 'Preview attachment cleanup', exact: true }).boundingBox()).y);
      await page.getByRole('button', { name: 'Members', exact: true }).click();
      await page.getByRole('searchbox', { name: 'Search members' }).fill('Maya');
      assert.equal(await page.locator('.space-members .dm-person').count(), 1);
      await assertPane(page);
    });
    await check(`${width}: create channel, send, search`, async () => {
      await menu(page, 'Notifications');
      await page.locator('.desktop-sidebar').getByRole('button', { name: 'New chat', exact: true }).click();
      await assertPane(page);
      assert.equal(await page.getByRole('button', { name: 'Chat', exact: true }).getAttribute('aria-pressed'), 'true');
      await page.getByLabel('Name', { exact: true }).fill('Desktop QA');
      await page.getByRole('button', { name: 'Create', exact: true }).click();
      await page.locator('.conversation h2').filter({ hasText: 'Desktop QA' }).waitFor();
      await page.getByRole('textbox', { name: 'Message text', exact: true }).fill('Keyboard sending works');
      await page.getByRole('textbox', { name: 'Message text', exact: true }).press('Enter');
      await page.locator('.messages').getByText('Keyboard sending works', { exact: true }).waitFor();
      await page.getByRole('textbox', { name: 'Message text', exact: true }).fill('Two lines');
      await page.getByRole('textbox', { name: 'Message text', exact: true }).press('Shift+Enter');
      assert.equal(await page.getByRole('textbox', { name: 'Message text', exact: true }).inputValue(), 'Two lines\n');
      await page.getByRole('textbox', { name: 'Message text', exact: true }).fill('');
      await page.keyboard.press('Control+f');
      await headerSearch(page, 'Search messages');
      assert.equal(await page.getByRole('searchbox', { name: 'Search messages', exact: true }).evaluate(node => document.activeElement === node), true);
      await page.getByRole('searchbox', { name: 'Search messages', exact: true }).fill('missing phrase');
      assert.equal(await page.locator('.messages').getByText('Keyboard sending works', { exact: true }).count(), 0);
      await page.getByRole('searchbox', { name: 'Search messages', exact: true }).fill('');
      const ownBubble = page.locator('.messages .message[data-own="true"] .message-bubble').first();
      const plainBackground = await ownBubble.evaluate(node => getComputedStyle(node).backgroundColor);
      await menu(page, 'Appearance');
      await page.getByRole('switch', { name: 'Highlight my messages' }).click();
      await page.locator('.desktop-sidebar').getByRole('button', { name: 'Desktop QA', exact: true }).click();
      assert.notEqual(await ownBubble.evaluate(node => getComputedStyle(node).backgroundColor), plainBackground);
      await menu(page, 'Appearance');
      await page.getByRole('switch', { name: 'Highlight my messages' }).click();
      await page.locator('.desktop-sidebar').getByRole('button', { name: 'Desktop QA', exact: true }).click();
      assert.equal(await ownBubble.evaluate(node => getComputedStyle(node).backgroundColor), plainBackground);
      await screenshot(page, `conversation-${width}-${theme}`);
    });
    await check(`${width}: new DM and navigation away`, async () => {
      await page.locator('.desktop-sidebar').getByRole('button', { name: 'New DM', exact: true }).click();
      await assertPane(page);
      assert.equal(await page.getByRole('button', { name: 'DM', exact: true }).getAttribute('aria-pressed'), 'true');
      await page.getByRole('checkbox', { name: 'Maya', exact: true }).check();
      await page.locator('.new-chat-footer button').click();
      await page.locator('.conversation h2').waitFor({ state: 'visible' });
      await menu(page, 'Reminders');
      await page.locator('.desktop-sidebar').getByRole('button', { name: 'General', exact: true }).click();
      assert.equal(await page.locator('.desktop-page:visible').count(), 0);
      await assertPane(page);
    });
    await check(`${width}: closing a page restores the same conversation`, async () => {
      for (let i = 0; i < 3; i++) {
        await page.locator('.desktop-sidebar').getByRole('button', { name: 'New chat', exact: true }).click();
        await page.locator('.desktop-page.new-chat-dialog').waitFor({ state: 'visible' });
        await page.locator('.desktop-sidebar').getByRole('button', { name: 'General', exact: true }).click();
        await page.locator('.conversation').waitFor({ state: 'visible' });
        assert.equal(await page.locator('#desktop-page-outlet').isVisible(), false);
        await assertPane(page);
      }
    });
    await check(`${width}: reminder removal`, async () => {
      await menu(page, 'Reminders'); await page.getByRole('button', { name: 'Done', exact: true }).click();
      assert.equal(await page.locator('.message-collection .reminder-actions').count(), 0);
    });
    await check(`${width}: legal draft is a page`, async () => {
      await menu(page, 'Legal'); await page.getByRole('button', { name: 'Report a concern', exact: true }).click();
      await page.locator('.desktop-page.service-request-dialog').waitFor({ state: 'visible' });
      await page.getByText(/It opens in your default email app/).waitFor();
      await assertPane(page); await screenshot(page, `legal-draft-${width}`);
      await page.getByRole('button', { name: 'Use draft', exact: true }).click();
      assert.ok(await page.evaluate(() => window.__desktopQA.calls.some(entry => entry.command === 'open_mail_draft')));
      await page.locator('.desktop-sidebar').getByRole('button', { name: 'Contacts', exact: true }).click();
      await assertPane(page);
    });
    await check(`${width}: profile editing and internal menu navigation`, async () => {
      await menu(page, 'Settings');
      await page.locator('.desktop-sidebar').getByRole('button', { name: 'Contacts', exact: true }).click();
      await page.locator('.contacts-page').waitFor({ state: 'visible' });
      await page.locator('.contacts-page').evaluate(node => { node.dataset.returnMarker = 'preserved'; });
      await page.locator('.desktop-workspace-trigger').click();
      const profile = page.locator('.desktop-workspace-profile');
      const space = page.locator('.desktop-current-space');
      const opacity = row => row.locator('.desktop-menu-context-action').evaluate(node => getComputedStyle(node).opacity);
      assert.equal(await opacity(profile), '0');
      assert.equal(await opacity(space), '0');
      const before = await profile.boundingBox();
      await profile.hover();
      assert.equal(await opacity(profile), '1');
      assert.deepEqual(await profile.boundingBox(), before, 'Hover must not move the profile row');
      await page.mouse.move(width - 10, height - 10);
      await profile.getByRole('button', { name: 'Edit profile', exact: true }).focus();
      assert.equal(await opacity(profile), '1', 'Keyboard focus must reveal the pencil');
      await profile.locator('strong').click();
      await page.locator('.contacts-page').waitFor({ state: 'visible' });
      assert.equal(await page.getByRole('textbox', { name: 'Name', exact: true }).count(), 0);
      await screenshot(page, `profile-menu-${width}-${theme}`);
      await page.getByRole('button', { name: 'Edit profile', exact: true }).click();
      await assertPane(page);
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill('Alex Desktop');
      await page.evaluate(() => { window.__desktopQA.failures.set_profile_details = 'network error'; });
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await page.locator('.toast').waitFor({ state: 'visible' });
      const notice = await page.locator('.toast').boundingBox();
      const pane = await page.locator('.desktop-profile-editor').boundingBox();
      assert.ok(Math.abs(notice.x + notice.width / 2 - pane.x - pane.width / 2) < 2, 'Toast must be centered on the main pane');
      assert.equal(await page.getByRole('textbox', { name: 'Name', exact: true }).inputValue(), 'Alex Desktop');
      await page.evaluate(() => { delete window.__desktopQA.failures.set_profile_details; });
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await page.locator('.desktop-profile-editor').waitFor({ state: 'detached' });
      await page.locator('.contacts-page').waitFor({ state: 'visible' });
      assert.equal(await page.locator('.contacts-page').getAttribute('data-return-marker'), 'preserved');
      await menu(page, 'Notifications');
      await editProfile(page);
      await page.keyboard.press('Escape');
      await page.locator('.invitation-page').waitFor({ state: 'visible' });
      await assertPane(page);
      assert.ok(await page.evaluate(() => window.__desktopQA.calls.some(entry => entry.request?.op === 'set_profile_details' && entry.request.name === 'Alex Desktop')));
    });
    await check(`${width}: device linking`, async () => {
      await menu(page, 'Devices');
      const add = page.locator('.screen-header').getByRole('button', { name: 'Link device', exact: true });
      assert.equal(await page.locator('.devices-page').getByRole('button', { name: 'Link device', exact: true }).count(), 0);
      await add.click();
      await page.locator('.devices-page[data-device-screen="qr"] .private-qr svg').waitFor();
      assert.equal(await page.locator('.devices-page .linked-devices').count(), 0, 'QR must have its own screen');
      await assertPane(page);
      await page.getByRole('button', { name: 'Back to devices', exact: true }).click();
      await page.locator('.devices-page[data-device-screen="list"] .linked-devices').waitFor();
    });
    await check(`${width}: workspace search shortcut`, async () => {
      await page.keyboard.press('Control+k');
      assert.equal(await page.getByRole('searchbox', { name: 'Search chats' }).evaluate(node => document.activeElement === node), true);
    });
    await check(`${width}: Compact reduces spacing and navigation height`, async () => {
      const measure = () => page.evaluate(() => {
        const rect = selector => document.querySelector(selector).getBoundingClientRect().height;
        return { row: rect('.desktop-nav-item'), header: rect('.details .screen-header'), search: rect('.desktop-sidebar-search .search-input'), padding: parseFloat(getComputedStyle(document.querySelector('.appearance-page')).paddingTop) };
      });
      await menu(page, 'Appearance');
      const normal = await measure();
      assert.equal(await page.getByRole('switch', { name: 'Hide avatars', exact: true }).evaluate(node => getComputedStyle(node).borderBottomWidth), '0px');
      await page.getByRole('slider', { name: 'Interface size', exact: true }).press('Home');
      await page.waitForFunction(() => document.documentElement.dataset.uiScale === 'compact');
      const compact = await measure();
      assert.ok(compact.row <= normal.row * 0.75, 'Compact sidebar rows are not meaningfully shorter');
      assert.ok(compact.header <= normal.header * 0.75, 'Compact header is not shorter');
      assert.ok(compact.search < normal.search, 'Compact search is not shorter');
      assert.equal(compact.padding, normal.padding / 2);
      await screenshot(page, `compact-appearance-${width}-${theme}`);
      await page.locator('.desktop-sidebar').getByRole('button', { name: 'Contacts', exact: true }).click();
      await assertPane(page);
      const contactFont = await page.locator('.contact-row .dm-person-name').first().evaluate(node => getComputedStyle(node).fontSize);
      assert.ok(parseFloat(contactFont) < 14, 'Compact contacts still use the larger body text');
      assert.ok((await page.locator('.contact-row').first().boundingBox()).height <= 42, 'Compact contacts are too tall');
      await screenshot(page, `compact-contacts-${width}-${theme}`);
      await page.locator('.desktop-sidebar').getByRole('button', { name: 'General', exact: true }).click();
      const messageFont = await page.locator('.messages .message p').first().evaluate(node => getComputedStyle(node).fontSize);
      assert.equal(contactFont, messageFont, 'Contacts and messages must share Compact text size');
      assert.equal(await page.getByRole('textbox', { name: 'Message text', exact: true }).evaluate(node => getComputedStyle(node).fontSize), messageFont);
      await page.locator('.messages .message-more').first().click();
      const messageMenu = page.locator('dialog.message-action-menu[open]');
      const menuItem = messageMenu.getByRole('menuitem').first();
      assert.equal(await menuItem.evaluate(node => getComputedStyle(node).fontSize), messageFont);
      assert.ok((await menuItem.boundingBox()).height <= 32, 'Compact message menu rows are too tall');
      await page.keyboard.press('Escape');
      await menu(page, 'Blocked users');
      assert.equal(await page.locator('.blocked-user-list strong').first().evaluate(node => getComputedStyle(node).fontSize), messageFont);
      await spaces(page);
      await page.getByRole('button', { name: /Settings.*Studio/i }).click();
      await page.getByRole('button', { name: 'Members', exact: true }).click();
      assert.equal(await page.locator('.space-members .dm-person-name').first().evaluate(node => getComputedStyle(node).fontSize), messageFont);
      await editProfile(page);
      assert.equal(await page.getByLabel('Name', { exact: true }).evaluate(node => getComputedStyle(node).fontSize), messageFont);
      await menu(page, 'Appearance');
      await page.getByRole('slider', { name: 'Interface size', exact: true }).press('ArrowRight');
      assert.deepEqual(await measure(), normal, 'Returning to System must restore spacing');
    });
    await context.close();
  }
  await check('author-only Delete is last, red, confirmed and replaces text/files', async () => {
    const {page, context} = await openPage(1280, 860);
    await page.locator('.desktop-sidebar').getByRole('button', {name: 'General', exact: true}).click();
    await page.locator('.messages .message-more').first().click();
    assert.equal(await page.getByRole('menuitem', {name: 'Delete', exact: true}).count(), 0);
    await page.keyboard.press('Escape');
    for (const kind of ['chat.message', 'file.shared']) {
      const id = await page.evaluate(kind => window.__desktopQA.ownMessage(kind), kind);
      const row = page.locator(`.messages [data-record-id="${id}"]`);
      await row.locator('.message-more').click();
      const items = page.locator('dialog[open]').getByRole('menuitem');
      assert.equal(await items.last().innerText(), 'Delete');
      assert.equal(await items.last().evaluate(node => getComputedStyle(node).color), 'rgb(177, 60, 53)');
      await items.last().click();
      const confirm = page.getByRole('dialog', {name: 'Delete this message?', exact: true});
      await confirm.getByRole('button', {name: 'Cancel', exact: true}).click();
      assert.equal(await row.locator('.deleted-message').count(), 0);
      await row.locator('.message-more').click();
      await page.getByRole('menuitem', {name: 'Delete', exact: true}).click();
      await confirm.getByRole('button', {name: 'Delete', exact: true}).click();
      await row.getByText('Message deleted', {exact: true}).waitFor();
      assert.equal(await row.locator('.message-controls').count(), 0);
      assert.equal(await row.locator('.attachment-button').count(), 0);
    }
    await context.close();
  });
  for (const platform of ['macos', 'windows', 'linux']) {
    await check(`${platform}: integrated window header`, async () => {
      const { page, context } = await openPage(1180, 800, 'light', false, platform);
      await page.waitForFunction(platform => document.documentElement.dataset.windowPlatform === platform, platform);
      const sidebar = await page.locator('.desktop-sidebar').boundingBox();
      assert.equal(sidebar.y, 0);
      if (platform === 'macos') {
        assert.equal(await page.locator('.desktop-window-controls').count(), 0);
        assert.ok((await page.locator('.desktop-workspace-trigger > span').boundingBox()).x >= 78);
      } else {
        assert.equal(await page.locator('.desktop-window-controls button').count(), 3);
        await page.getByRole('button', { name: 'Minimize window', exact: true }).click();
        assert.ok(await page.evaluate(() => window.__desktopQA.calls.some(call => call.command === 'plugin:window|minimize')));
        await menu(page, 'Notifications');
        const right = await page.locator('.invitation-page .screen-header-actions').boundingBox();
        const controls = await page.locator('.desktop-window-controls').boundingBox();
        assert.ok(right.x + right.width <= controls.x, 'Window controls overlap header actions');
      }
      const trigger = page.locator('.desktop-workspace-trigger');
      const title = trigger.locator('strong');
      const arrow = trigger.locator('.ui-icon');
      const header = await page.locator('.desktop-workspace').boundingBox();
      const before = await arrow.boundingBox();
      const bounds = await trigger.boundingBox();
      assert.equal(bounds.x, header.x);
      assert.equal(bounds.width, header.width, 'Space trigger must cover the full sidebar header');
      const nameBounds = await title.boundingBox();
      assert.ok(Math.abs(nameBounds.x + nameBounds.width / 2 - (header.x + header.width / 2)) < 1);
      await trigger.hover();
      await page.mouse.down();
      await page.waitForTimeout(180);
      assert.deepEqual(await arrow.boundingBox(), before, 'The Space arrow moves while pressing the header');
      await page.mouse.up();
      await page.locator('.desktop-workspace-menu').waitFor();
      const menuBounds = await page.locator('.desktop-workspace-menu').boundingBox();
      assert.ok(menuBounds.y >= header.y + header.height + 4, 'Space menu overlaps its header');
      assert.deepEqual(await arrow.boundingBox(), before, 'The Space arrow moves after opening the menu');
      await trigger.click();
      await screenshot(page, `window-${platform}`);
      await context.close();
    });
  }
  for (const mobile of [false, true]) {
    await check(`${mobile ? 'Phone' : 'Desktop'}: own-message highlight defaults off and can be toggled`, async () => {
      const { page, context } = await openPage(mobile ? 390 : 1280, 844, 'light', mobile);
      const openAppearance = async () => {
        if (!mobile) return menu(page, 'Appearance');
        await page.getByRole('button', { name: 'More', exact: true }).click();
        await page.getByRole('button', { name: 'Appearance', exact: true }).click();
      };
      await openAppearance();
      const toggle = page.getByRole('switch', { name: 'Highlight my messages', exact: true });
      assert.equal(await toggle.getAttribute('aria-checked'), 'false');
      assert.ok((await toggle.boundingBox()).y > (await page.getByRole('switch', { name: 'Hide avatars' }).boundingBox()).y);
      await toggle.click();
      assert.equal(await toggle.getAttribute('aria-checked'), 'true');
      assert.equal(await page.evaluate(() => JSON.parse(localStorage.getItem('elo.userPreferences.v1')).highlightMyMessages), true);
      await toggle.click();
      assert.equal(await page.evaluate(() => document.documentElement.dataset.highlightMyMessages), 'false');
      await context.close();
    });
  }
  await check('Thread back restores paged conversation, loaded older rows and search without target frames', async () => {
    const { page, context } = await openPage(1280, 860, 'dark', false, '', true);
    await page.locator('.desktop-sidebar').getByRole('button', { name: 'General', exact: true }).click();
    const list = page.locator('.conversation .messages');
    await list.locator('[data-record-id="parent-39"]').waitFor();
    const verifyReturn = async (id) => {
      const row = list.locator(`[data-record-id="${id}"]`);
      await row.scrollIntoViewIfNeeded();
      await row.locator('.thread-link').click();
      const savedTop = await list.evaluate(node => window.__savedChatTop);
      await page.locator('.thread-view').getByText(`Thread response ${Number(id.slice(-2))}`, { exact: true }).waitFor();
      await page.locator('.thread-view').evaluate(node => { node.dataset.returnMarker = 'preserved'; });
      await editProfile(page);
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await page.locator('.thread-view').waitFor({ state: 'visible' });
      assert.equal(await page.locator('.thread-view').getAttribute('data-return-marker'), 'preserved', 'Profile editing must preserve the open thread');
      assert.equal(await page.locator('.thread-view [data-thread-root="true"]').evaluate(node => getComputedStyle(node).outlineStyle), 'none');
      await page.getByRole('button', { name: 'Back to chat', exact: true }).click();
      await list.waitFor({ state: 'visible' });
      await page.waitForTimeout(250);
      assert.ok(Math.abs(await list.evaluate(node => node.scrollTop) - savedTop) <= 2, 'Back changed the reading position');
      assert.equal(await list.getByRole('button', { name: 'Latest messages', exact: true }).count(), 0);
      assert.equal(await list.getByRole('button', { name: 'Load newer messages', exact: true }).count(), 0);
      assert.equal(await list.locator('.message[data-target="true"]').count(), 0);
    };
    await page.evaluate(() => document.querySelector('.conversation .messages').addEventListener('pointerdown', () => {
      window.__savedChatTop = document.querySelector('.conversation .messages').scrollTop;
    }, true));
    await verifyReturn('parent-39');
    assert.equal(await list.locator('.message').count(), 20);
    await list.getByRole('button', { name: 'Load older messages', exact: true }).click();
    await list.locator('[data-record-id="parent-00"]').waitFor();
    await verifyReturn('parent-10');
    assert.equal(await list.locator('.message').count(), 40, 'Loaded pages were discarded');
    await page.getByRole('searchbox', { name: 'Search messages', exact: true }).fill('Thread response 12');
    await list.locator('[data-record-id="reply-12"]').waitFor();
    await list.locator('[data-record-id="reply-12"] .thread-link').click();
    await page.locator('.thread-view').getByText('Thread response 12', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Back to chat', exact: true }).click();
    assert.equal(await page.getByRole('searchbox', { name: 'Search messages', exact: true }).inputValue(), 'Thread response 12');
    await list.locator('[data-record-id="reply-12"]').waitFor();
    assert.equal(await page.evaluate(() => window.__desktopQA.calls.filter(item => item.request?.op === 'history_page' && !item.request.thread && item.request.around).length), 0, 'Ordinary thread back must not load a single-message target');
    await screenshot(page, 'thread-back-retains-history');
    await context.close();
  });
  await check('Device requests return to the list with right-aligned actions and primary Done', async () => {
    const { page, context } = await openPage(1280, 860);
    await menu(page, 'Devices');
    await page.getByRole('button', { name: 'Link device', exact: true }).click();
    await page.locator('.private-qr svg').waitFor();
    await page.evaluate(() => { window.__desktopQA.pairing.request = {id:'synthetic-request', name:'Test Android'}; });
    const row = page.locator('.linked-device-row').filter({hasText:'Test Android'});
    await row.getByRole('button', {name:'Accept', exact:true}).waitFor();
    assert.equal(await page.locator('.private-qr').count(), 0);
    const accept = await row.getByRole('button', {name:'Accept', exact:true}).boundingBox();
    const remove = await row.getByRole('button', {name:'Delete', exact:true}).boundingBox();
    const bounds = await row.boundingBox();
    assert.ok(Math.abs(accept.y - remove.y) < 2 && remove.x - accept.x - accept.width <= 16);
    assert.ok(Math.abs(bounds.x + bounds.width - remove.x - remove.width) < 2);
    await row.getByRole('button', {name:'Accept', exact:true}).click();
    const done = page.locator('[data-device-screen="done"]').getByRole('button', {name:'Done', exact:true});
    await done.waitFor();
    assert.equal(await done.evaluate(node => getComputedStyle(node).backgroundColor), await page.locator('button').first().evaluate(node => { const probe = document.createElement('button'); node.parentElement.append(probe); const color = getComputedStyle(probe).backgroundColor; probe.remove(); return color; }));
    assert.equal(await done.getAttribute('class'), null);
    await done.click();
    await page.locator('[data-device-screen="list"] .linked-devices').waitFor();
    await context.close();
  });
  await check('Device removal needs only confirmation and shows pending delivery', async () => {
    const { page, context } = await openPage(1280, 860);
    await menu(page, 'Devices');
    const revoke = page.getByRole('button', { name: 'Delete', exact: true });
    assert.equal(await revoke.count(), 1, 'The current device must not expose revocation');
    await revoke.click();
    const dialog = page.getByRole('dialog', { name: 'Delete this device?', exact: true });
    assert.equal(await dialog.locator('input, textarea').count(), 0, 'Removal must not request a password or recovery words');
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    assert.equal(await page.evaluate(() => window.__desktopQA.calls.filter(entry => entry.request?.op === 'device_revoke').length), 0);
    await revoke.click();
    await page.evaluate(() => { window.__desktopQA.latency.device_revoke = 500; });
    await dialog.getByRole('button', { name: 'Delete', exact: true }).click();
    assert.equal(await dialog.locator('button.danger').isDisabled(), true);
    await dialog.waitFor({ state: 'detached' });
    const pending = page.getByText('Device removal is waiting for a server. Keep elo open to retry.', { exact: true });
    await pending.waitFor();
    assert.ok((await pending.getAttribute('class')).includes('error'));
    assert.equal(await page.evaluate(() => window.__desktopQA.calls.filter(entry => entry.request?.op === 'device_revoke' && entry.request.confirmed === true && entry.request.credential === 'synthetic-other-credential').length), 1);
    assert.equal(await page.evaluate(() => window.__desktopQA.calls.some(entry => entry.request?.op === 'device_revoke' && ('password' in entry.request || 'words' in entry.request))), false);
    await screenshot(page, 'device-revocation-pending');
    await context.close();
  });
  await check('Error notices expire after ten seconds and pause during interaction', async () => {
    const { page, context } = await openPage(1280, 860);
    await menu(page, 'Devices');
    await page.clock.install();
    await page.evaluate(() => { window.__desktopQA.failures.pair_start = 'Connect to a Space before linking a device.'; });
    const start = page.getByRole('button', { name: 'Link device', exact: true });
    const toast = page.locator('.toast[data-tone="error"]');
    await start.click(); await toast.waitFor();
    await page.mouse.move(10, 10);
    await page.clock.fastForward(9000);
    assert.equal(await toast.count(), 1);
    await page.clock.fastForward(1200);
    await toast.waitFor({ state: 'hidden' });
    await start.click(); await toast.waitFor();
    await toast.hover();
    await page.clock.fastForward(11000);
    assert.equal(await toast.count(), 1, 'Reading a hovered notice must pause dismissal');
    await toast.getByRole('button', { name: 'Dismiss error' }).focus();
    await page.mouse.move(10, 10);
    await page.clock.fastForward(11000);
    assert.equal(await toast.count(), 1, 'Keyboard focus must pause dismissal');
    await start.focus();
    await page.clock.fastForward(11000);
    await toast.waitFor({ state: 'hidden' });
    await context.close();
  });
  await check('Desktop background delivery stays unread until the window gains focus', async () => {
    const { page, context } = await openPage(1280, 860, 'light', false, 'macos');
    await page.locator('.desktop-sidebar').getByRole('button', { name: 'General', exact: true }).click();
    await page.locator('.conversation h2').filter({ hasText: 'General' }).waitFor();
    const id = await page.evaluate(async () => {
      Object.defineProperty(document, 'hasFocus', { configurable: true, value: () => false });
      window.dispatchEvent(new Event('blur'));
      return window.__desktopQA.backgroundMessage();
    });
    await page.locator('.conversation').getByText('Background delivery', { exact: true }).waitFor();
    await page.waitForTimeout(400);
    const read = () => page.evaluate(id => window.__desktopQA.calls.some(call =>
      call.request?.op === 'mark_read' && call.request.records?.includes(id)), id);
    assert.equal(await read(), false, 'An inactive desktop window silently read the message');
    await page.evaluate(() => {
      Object.defineProperty(document, 'hasFocus', { configurable: true, value: () => true });
      window.dispatchEvent(new Event('focus'));
    });
    await page.waitForFunction(id => window.__desktopQA.calls.some(call =>
      call.request?.op === 'mark_read' && call.request.records?.includes(id)), id);
    await context.close();
  });
  await check('Phone keeps native modal chat creation', async () => {
    const { page, context } = await openPage(390, 844, 'light', true);
    assert.equal(await page.locator('.desktop-sidebar').count(), 0);
    // Layout-specific pages are still rendered as dialogs on phones.
    await page.getByRole('button', { name: 'New chat', exact: true }).click();
    await page.locator('dialog.new-chat-dialog[open]').waitFor();
    assert.equal(await page.locator('#desktop-page-outlet > *').count(), 0);
    await context.close();
  });
  await check('Phone drawer preserves the first tap after swipe and shows call presence; Members is first in More', async () => {
    const { page, context } = await openPage(390, 844, 'light', true);
    await page.locator('.channel-list button').filter({ has: page.getByText('General', { exact: true }) }).click();
    const header = page.locator('.conversation .screen-header');
    assert.equal(await header.getByRole('button', { name: 'Members', exact: true }).count(), 0);
    assert.equal(await header.locator('.desktop-refresh-button').count(), 0);
    await header.getByRole('button', { name: 'More actions and settings', exact: true }).click();
    const menu = page.locator('dialog.message-action-menu[open]');
    assert.equal(await menu.getByRole('menuitem').first().innerText(), 'Members');
    await menu.getByRole('menuitem', { name: 'Members', exact: true }).click();
    await page.getByRole('heading', { name: 'Members', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Back to chat', exact: true }).click();
    const drawer = page.locator('.conversation-edge-tools');
    const tab = drawer.locator('.conversation-edge-tools-tab');
    const call = drawer.locator('.call-trigger');
    // Simulate the presence marker supplied by the live call controller.
    await call.evaluate(node => { const dot = document.createElement('span'); dot.className = 'call-indicator'; node.append(dot); });
    assert.equal(await tab.evaluate(node => getComputedStyle(node, '::after').content), '""');
    await tab.evaluate(node => {
      for (const [type, x] of [['touchstart', 380], ['touchmove', 340], ['touchend', 340]]) {
        const touch = new Touch({ identifier: 1, target: node, clientX: x, clientY: 500 });
        node.dispatchEvent(new TouchEvent(type, { bubbles: true, cancelable: true,
          touches: type === 'touchend' ? [] : [touch], changedTouches: [touch] }));
      }
    });
    assert.equal(await drawer.getAttribute('data-open'), 'true');
    assert.equal(await tab.evaluate(node => getComputedStyle(node, '::after').content), 'none');
    // Browsers need not send a compatibility click after a cancelled swipe.
    // The following fresh physical tap must still open the chooser immediately.
    await call.tap();
    await page.getByRole('heading', { name: 'Start call', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Video call', exact: true }).waitFor();
    await page.keyboard.press('Escape');
    await call.locator('.call-indicator').evaluate(node => node.remove());
    await tab.tap();
    assert.equal(await tab.evaluate(node => getComputedStyle(node, '::after').content), 'none');
    await context.close();
  });
  await check('Logout hides chats after native cleanup failure and permits a fresh unlock', async () => {
    const { page, context } = await openPage(1280, 860);
    for (const failure of ['profile_logout_notifications_pending', 'profile_logout_cleanup_pending', '']) {
      await page.evaluate(value => { __desktopQA.failures.lock = value; }, failure);
      await page.locator('.desktop-workspace-trigger').click();
      await page.locator('.desktop-workspace-menu').getByRole('button', { name: 'Log out', exact: true }).click();
      await page.getByRole('dialog', { name: 'Log out on this device?', exact: true }).getByRole('button', { name: 'Log out', exact: true }).click();
      await page.getByLabel('Password', { exact: true }).waitFor();
      assert.equal(await page.locator('.shell').count(), 0, 'Logged-out chats must not stay visible after a cleanup error');
      if (failure) await page.locator('.toast').getByText(/^Logged out\./).waitFor();
      await page.getByLabel('Password', { exact: true }).fill('fictional desktop password');
      await page.getByRole('button', { name: 'Unlock', exact: true }).click();
      await page.locator('.shell').waitFor();
    }
    await context.close();
  });
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed: checks.length, checks, errors }, null, 2));
} catch (error) {
  for (const context of browser.contexts()) for (const page of context.pages()) {
    await screenshot(page, 'failure');
    console.error(await page.locator('.shell').evaluate(node => ({ attributes: Object.fromEntries([...node.attributes].map(a => [a.name, a.value])), outlet: document.querySelector('#desktop-page-outlet')?.innerHTML.slice(0, 1500) })));
  }
  throw error;
} finally { await browser.close(); }
