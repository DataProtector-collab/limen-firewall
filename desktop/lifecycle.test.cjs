'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createLifecycle } = require('./lifecycle.cjs');

function setup(options = {}) {
  const state = { visible: true, minimized: false, skipTaskbar: false, focus: 0,
    quit: 0, cleanup: 0, dialogs: 0, balloons: 0, errors: 0 };
  const window = Object.assign(new EventEmitter(), {
    isDestroyed: () => false, isMinimized: () => state.minimized,
    restore: () => { state.minimized = false; }, show: () => { state.visible = true; },
    hide: () => { state.visible = false; }, focus: () => { state.focus++; },
    setSkipTaskbar: value => { state.skipTaskbar = value; },
  });
  const app = Object.assign(new EventEmitter(), {
    getLocale: () => 'de-DE', quit: () => { state.quit++; },
  });
  const trays = [];
  class FakeTray extends EventEmitter {
    constructor() { super(); trays.push(this); this.destroyed = false; }
    setToolTip() {}
    setContextMenu(menu) { this.menu = menu; }
    displayBalloon() { state.balloons++; }
    isDestroyed() { return this.destroyed; }
    destroy() { this.destroyed = true; }
  }
  const dialog = {
    showMessageBox: async (_window, details) => { state.dialogs++; state.dialog = details; return { response: 0 }; },
    showErrorBox: () => { state.errors++; },
  };
  const lifecycle = createLifecycle({ app, window, Tray: FakeTray,
    Menu: { buildFromTemplate: entries => entries }, dialog,
    nativeImage: { createFromPath: () => ({ isEmpty: () => false }) },
    iconPath: 'limen.ico', beforeQuit: async () => { state.cleanup++; }, ...options,
  });
  function event(target, name) {
    const ev = { prevented: false, preventDefault() { this.prevented = true; } };
    target.emit(name, ev);
    return ev;
  }
  return { state, window, app, tray: trays[0], dialog, lifecycle, event };
}

test('X keeps the app alive in the notification area and every restore route shows the window', () => {
  const h = setup();
  const restore = [() => h.tray.emit('click'), () => h.tray.emit('double-click'),
    () => h.tray.menu[0].click(), () => h.app.emit('second-instance'), () => h.app.emit('activate')];
  for (const open of restore) {
    assert.equal(h.event(h.window, 'close').prevented, true);
    assert.equal(h.state.visible, false);
    assert.equal(h.state.skipTaskbar, true);
    assert.equal(h.state.quit, 0);
    h.state.minimized = true;
    open();
    assert.equal(h.state.visible, true);
    assert.equal(h.state.minimized, false);
    assert.equal(h.state.skipTaskbar, false);
  }
  assert.equal(h.state.balloons, 1);
  assert.equal(h.state.dialogs, 0);
  h.lifecycle.dispose();
});

test('cancel is the safe default for explicit quit and duplicate quit events share one dialog', async () => {
  const h = setup();
  let respond;
  h.dialog.showMessageBox = (_window, details) => {
    h.state.dialogs++; h.state.dialog = details;
    return new Promise(resolve => { respond = resolve; });
  };
  h.tray.menu[2].click();
  assert.equal(h.event(h.app, 'before-quit').prevented, true);
  const pending = h.lifecycle.requestQuit();
  await Promise.resolve();
  assert.equal(h.state.dialogs, 1);
  assert.equal(h.state.dialog.defaultId, 0);
  assert.equal(h.state.dialog.cancelId, 0);
  assert.match(h.state.dialog.detail, /temporären Sperren enden/);
  assert.match(h.state.dialog.detail, /Windows-Firewall-Regeln bleiben/);
  respond({ response: 0 });
  assert.equal(await pending, false);
  assert.equal(h.state.quit, 0);
  assert.equal(h.tray.destroyed, false);
  h.lifecycle.dispose();
});

test('confirmed quit awaits cleanup exactly once and permits close without hiding again', async () => {
  let finish;
  let cleanup = 0;
  const h = setup({ beforeQuit: () => { cleanup++; return new Promise(resolve => { finish = resolve; }); } });
  h.dialog.showMessageBox = async () => ({ response: 1 });
  const pending = h.lifecycle.requestQuit();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(cleanup, 1);
  assert.equal(h.state.quit, 0);
  assert.equal(h.event(h.window, 'close').prevented, false);
  finish();
  assert.equal(await pending, true);
  assert.equal(h.state.quit, 1);
  assert.equal(h.tray.destroyed, true);
  h.app.emit('will-quit');
  await Promise.resolve();
  assert.equal(cleanup, 1);
  assert.equal(h.app.listenerCount('second-instance'), 0);
  assert.equal(h.window.listenerCount('close'), 0);
});

test('Windows shutdown does not block logoff or open a confirmation dialog', async () => {
  const h = setup();
  assert.equal(h.event(h.window, 'query-session-end').prevented, false);
  assert.equal(h.tray.destroyed, false);
  assert.equal(h.state.cleanup, 0);
  assert.equal(h.event(h.window, 'session-end').prevented, false);
  assert.equal(h.event(h.window, 'close').prevented, false);
  assert.equal(h.event(h.app, 'before-quit').prevented, false);
  await Promise.resolve();
  assert.equal(h.state.dialogs, 0);
  assert.equal(h.state.cleanup, 1);
  assert.equal(h.tray.destroyed, true);
  h.lifecycle.dispose();
});

test('a cancelled Windows shutdown leaves the tray and ordinary close behavior intact', () => {
  const h = setup();
  assert.equal(h.event(h.window, 'query-session-end').prevented, false);
  assert.equal(h.event(h.window, 'close').prevented, true);
  h.tray.emit('click');
  assert.equal(h.state.visible, true);
  assert.equal(h.state.cleanup, 0);
  h.lifecycle.dispose();
});

test('failed tray creation preserves a visible reachable app and requires consent to quit', async () => {
  const h = setup({ nativeImage: { createFromPath: () => ({ isEmpty: () => true }) } });
  assert.equal(h.state.errors, 1);
  assert.equal(h.event(h.window, 'close').prevented, true);
  await h.lifecycle.requestQuit();
  assert.equal(h.state.visible, true);
  assert.equal(h.state.quit, 0);
  h.lifecycle.dispose();
});

test('shutdown while a quit dialog is pending cannot trigger a second exit or cleanup', async () => {
  const h = setup();
  let respond;
  h.dialog.showMessageBox = () => new Promise(resolve => { respond = resolve; });
  const pending = h.lifecycle.requestQuit();
  await Promise.resolve();
  h.window.emit('session-end');
  respond({ response: 1 });
  assert.equal(await pending, false);
  assert.equal(h.state.cleanup, 1);
  assert.equal(h.state.quit, 0);
  h.lifecycle.dispose();
});

test('shutdown before a queued dialog opens suppresses the modal', async () => {
  const h = setup();
  const pending = h.lifecycle.requestQuit();
  h.window.emit('session-end');
  assert.equal(await pending, false);
  assert.equal(h.state.dialogs, 0);
  h.lifecycle.dispose();
});

test('a native dialog error does not cache a failed exit request forever', async () => {
  const h = setup();
  h.dialog.showMessageBox = () => { throw new Error('Temporary desktop dialog failure'); };
  assert.equal(await h.lifecycle.requestQuit(), false);
  assert.equal(h.state.quit, 0);
  h.dialog.showMessageBox = async () => ({ response: 1 });
  assert.equal(await h.lifecycle.requestQuit(), true);
  assert.equal(h.state.quit, 1);
  h.lifecycle.dispose();
});

test('unresponsive cleanup cannot hang an authorized exit indefinitely', async () => {
  const h = setup({ beforeQuit: () => new Promise(() => {}), cleanupTimeoutMs: 10 });
  h.dialog.showMessageBox = async () => ({ response: 1 });
  assert.equal(await h.lifecycle.requestQuit(), true);
  assert.equal(h.state.quit, 1);
  assert.equal(h.tray.destroyed, true);
  h.lifecycle.dispose();
});
