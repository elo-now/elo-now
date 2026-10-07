// Native bridge lifecycle and real call layout with fictional IPC; no device media.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const { chromium } = createRequire(import.meta.url)('playwright');
const { PNG } = createRequire(import.meta.url)('pngjs');
const browser = await chromium.launch({ headless: true, executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const base = process.env.ELO_QA_URL || 'http://127.0.0.1:1420';
try {
  const page = await browser.newPage({ viewport: { width: 393, height: 852 } });
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  await page.route('**/*', route => new URL(route.request().url()).origin === new URL(base).origin ? route.continue() : route.abort());
  await page.goto(base + '/tests/calls.html');
  await page.waitForFunction(() => window.callQA);
  const result = await page.evaluate(async () => {
    const { NativePeer } = await import('/src/calls/nativePeer.ts');
    const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
    const tick = () => new Promise(r => setTimeout(r, 10));
    const calls = [], updates = [], presence = [];
    let failures = 0, connected = 0;
    const start = deferred(), firstPoll = deferred();
    const old = new NativePeer('self', 'profile', v => updates.push(v), () => failures++, () => connected++, v => presence.push(v), async v => {
      calls.push(v); if (v.op === 'start') return start.promise; return {};
    });
    const pendingUpdate = old.update({ audio_muted: false, video_published: false, screen_published: false });
    const stopped = old.stop();
    start.resolve({}); await stopped; await pendingUpdate;
    if (calls.some(v => ['poll', 'update'].includes(v.op))) throw Error('Late start revived a stopped peer');
    const liveCalls = [];
    const peer = new NativePeer('self', 'profile', v => updates.push(v), () => failures++, () => connected++, v => presence.push(v), async v => {
      liveCalls.push(v);
      if (v.op === 'poll') return firstPoll.promise;
      return {};
    });
    await tick();
    await peer.update({ audio_muted: false, video_published: false, screen_published: false });
    await peer.setSpeakerMuted(true);
    await peer.stop();
    const count = updates.length;
    firstPoll.resolve({ connection: 'connected', revision: 1, call: { call_id: 'stale' }, remote: 'peer', tracks: [{ id: 'remote-camera', source: 'camera', local: false }] });
    await tick();
    if (updates.length !== count || presence.length || connected || failures) throw Error('A stopped poll leaked media/presence/callbacks');
    if (!liveCalls.some(v => v.op === 'speaker' && v.muted)) throw Error('Speaker mute did not reach native media');
    // Media updates must be serialized while stop remains immediate. Native
    // owns SDP/ICE; the WebView sends only capture/control changes now.
    const update = deferred(), serial = [];
    const p = new NativePeer('self', 'profile', () => {}, () => {}, () => {}, () => {}, async v => {
      serial.push(v.op);
      if (v.op === 'poll') return { connection: 'new', revision: 0, tracks: [] };
      if (v.op === 'update') return update.promise;
      return {};
    });
    const first = p.update({ audio_muted: true, video_published: false, screen_published: false });
    const second = p.update({ audio_muted: false, video_published: false, screen_published: false });
    await tick();
    if (serial.filter(op => op === 'update').length !== 1) throw Error('Media updates raced each other');
    await p.stop(); update.resolve({}); await first; await second;
    if (serial.filter(op => op === 'update').length !== 1) throw Error('Queued media update survived cancellation');
    const { Calls } = await import('/src/calls/controller.ts');
    const controller = new Calls(), stopping = deferred();
    controller.adapter = { stop: () => stopping.promise };
    const firstStop = controller.stopMedia();
    let replacementAllowed = false;
    const nextStop = controller.stopMedia().then(() => { replacementAllowed = true; });
    await tick();
    if (replacementAllowed) throw Error('Reconnect could replace native media before old stop completed');
    stopping.resolve(); await firstStop; await nextStop;
    return { stoppedStarts: calls.filter(v => v.op === 'stop').length, stalePollIgnored: true, serialized: true };
  });
  assert.ok(result.stoppedStarts >= 1); assert.ok(result.stalePollIgnored && result.serialized);
  console.log('PASS native media: late start/poll cancellation, serialized media updates, speaker mute');
  await page.evaluate(() => {
    callQA.start();
    const calls = callQA.calls, state = calls.getSnapshot();
    window.nativeFrames = [];
    window.releaseNativeRender = undefined;
    calls.isNativeMedia = () => true;
    const active = structuredClone(state.active);
    active.participants.remote.media.video_published = true;
    active.participants.local.media.video_published = true;
    calls.change({ active, tiles: ['remote', 'local'].map(who => ({ id: who + '-camera', credential: who + '-device', local: who === 'local', source: 'camera', stream: new MediaStream(), native: {
      session: 'fictional-session', revision: 1, track: who + '-camera', render: async frames => {
        nativeFrames.push(frames);
        if (frames.length && window.delayNativeRender) await new Promise(resolve => { window.releaseNativeRender = resolve; });
      },
    } })) });
  });
  await page.locator('.call-widget').getByRole('button', { name: 'Open call', exact: true }).click();
  await page.waitForFunction(() => document.documentElement.classList.contains('native-call-video'));
  assert.equal(await page.locator('.call-native-video').count(), 2);
  const frames = await page.evaluate(() => nativeFrames.at(-1));
  assert.equal(frames.length, 2); assert.ok(frames.every(f => f.width > 0 && f.height > 0));
  assert.equal(await page.locator('.call-dialog').evaluate(n => getComputedStyle(n).backgroundColor), 'rgba(0, 0, 0, 0)');
  assert.equal(await page.locator('.call-dialog .call-controls').evaluate(n => getComputedStyle(n).visibility), 'visible');
  // Reproduce an audio call upgraded to local video only. Paint a fictional
  // UIKit layer below the actual dialog, then check the visible screenshot.
  await page.evaluate(() => {
    const calls = callQA.calls, state = calls.getSnapshot();
    window.bothNativeTiles = state.tiles;
    const active = structuredClone(state.active);
    active.participants.remote.media.video_published = false;
    const underlay = document.createElement('div');
    underlay.id = 'fictional-native-underlay';
    underlay.style.cssText = 'position:fixed;inset:0;background:rgb(231,17,203);pointer-events:none';
    document.body.prepend(underlay);
    calls.change({ active, tiles: state.tiles.filter(tile => tile.local) });
  });
  await page.waitForFunction(() => nativeFrames.at(-1)?.length === 1 && document.querySelector('.call-stage > [data-main]').style.clipPath);
  const preview = await page.locator('.call-self-preview .native-video-frame').boundingBox();
  const pixel = PNG.sync.read(await page.screenshot());
  const offset = (Math.floor(preview.y + preview.height / 2) * pixel.width + Math.floor(preview.x + preview.width / 2)) * 4;
  const visiblePixel = [...pixel.data.subarray(offset, offset + 3)];
  // Chromium color conversion can round a channel by one byte. The vivid
  // underlay must still be visible, rather than the opaque placeholder.
  assert.ok(visiblePixel.every((channel, index) => Math.abs(channel - [231, 17, 203][index]) <= 2), `Audio-only main tile obscured native self video: ${visiblePixel}`);
  const repeatedWrites = await page.evaluate(async () => {
    let writes = 0;
    const observer = new MutationObserver(records => { writes += records.length; });
    observer.observe(document.querySelector('.call-stage > [data-main]'), { attributes: true, attributeFilter: ['style'] });
    await new Promise(resolve => setTimeout(resolve, 250));
    observer.disconnect();
    return writes;
  });
  assert.equal(repeatedWrites, 0, 'Stable self-preview layout keeps rewriting styles');
  await page.evaluate(() => {
    const calls = callQA.calls, state = calls.getSnapshot(), active = structuredClone(state.active);
    active.participants.local.media.video_published = false;
    calls.change({ active, tiles: [] });
  });
  await page.waitForFunction(() => !document.documentElement.classList.contains('native-call-video'));
  assert.equal(await page.locator('.call-stage > [data-main]').evaluate(n => n.style.clipPath), '');
  await page.evaluate(() => {
    document.getElementById('fictional-native-underlay').remove();
    const calls = callQA.calls, active = structuredClone(calls.getSnapshot().active);
    active.participants.local.media.video_published = true;
    active.participants.remote.media.video_published = true;
    calls.change({ active, tiles: bothNativeTiles });
  });
  await page.waitForFunction(() => nativeFrames.at(-1)?.length === 2);
  console.log('PASS audio to video: self preview pixels visible above remote initials; camera-off restores placeholder');
  await page.getByRole('button', { name: 'Collapse session', exact: true }).click();
  await page.waitForFunction(() => !document.documentElement.classList.contains('native-call-video') && nativeFrames.at(-1)?.length === 0);
  await page.evaluate(() => { window.delayNativeRender = true; });
  await page.locator('.call-widget').getByRole('button', { name: 'Open call', exact: true }).click();
  await page.waitForFunction(() => window.releaseNativeRender);
  await page.getByRole('button', { name: 'Collapse session', exact: true }).click();
  await page.evaluate(() => releaseNativeRender());
  await page.waitForFunction(() => nativeFrames.at(-1)?.length === 0);
  assert.equal(await page.evaluate(() => document.documentElement.classList.contains('native-call-video')), false);
  assert.deepEqual(errors, []);
  console.log('PASS native video: two tiles, transparent stage/visible controls, collapse including delayed render restores chat');
} finally { await browser.close(); }
