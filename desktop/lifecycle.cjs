'use strict';

const TRAY_GUID = '87c26a34-39a0-4d73-85fa-8b16e7d0f430';

function createLifecycle({ app, window, Tray, Menu, dialog, nativeImage, iconPath,
  beforeQuit = async () => {}, getLocale = () => app.getLocale(), cleanupTimeoutMs = 5000 }) {
  const de = /^de(?:-|$)/i.test(getLocale());
  const words = de ? {
    open: 'Limen öffnen', exit: 'Limen beenden …', title: 'Limen wirklich beenden?',
    detail: 'Verbindungsbeobachtung und Freigabekontrolle werden beendet. Aktive Freigabesitzungen und ihre temporären Sperren enden. Gespeicherte Windows-Firewall-Regeln bleiben bestehen.',
    cancel: 'Weiterlaufen lassen', confirm: 'Limen beenden',
    trayError: 'Das Limen-Symbol konnte nicht im Infobereich angezeigt werden. Das Fenster bleibt zugänglich.',
    background: 'Limen läuft im Infobereich weiter',
    backgroundDetail: 'Mit einem Klick auf das Limen-Symbol öffnen. Zum Beenden das Symbol rechts anklicken und „Limen beenden“ wählen.',
  } : {
    open: 'Open Limen', exit: 'Quit Limen…', title: 'Really quit Limen?',
    detail: 'Connection observation and approval control will stop. Active approval sessions and their temporary blocks will end. Saved Windows Firewall rules will remain.',
    cancel: 'Keep running', confirm: 'Quit Limen',
    trayError: 'The Limen notification icon could not be created. The window will remain accessible.',
    background: 'Limen is still running in the notification area',
    backgroundDetail: 'Click the Limen icon to open it. To quit, right-click the icon and choose “Quit Limen”.',
  };
  let tray;
  let ending = false;
  let disposed = false;
  let promptedBackground = false;
  let exitRequest;
  let cleanup;
  const listeners = [];

  function listen(target, event, callback) {
    target.on(event, callback);
    listeners.push(() => target.removeListener(event, callback));
  }

  function show() {
    if (ending || disposed || window.isDestroyed()) return;
    if (window.isMinimized()) window.restore();
    window.show();
    window.setSkipTaskbar(false);
    window.focus();
  }

  function destroyTray() {
    if (tray && !tray.isDestroyed()) tray.destroy();
    tray = undefined;
  }

  function startCleanup() {
    if (!cleanup) {
      // The OS may end the session without waiting for promises. The native
      // controller must also release dynamic filters when its process exits.
      cleanup = Promise.resolve().then(beforeQuit).catch(() => {});
    }
    return cleanup;
  }

  async function quitImmediately() {
    if (ending) return;
    ending = true;
    let timer;
    try {
      await Promise.race([startCleanup(), new Promise(resolve => {
        timer = setTimeout(resolve, cleanupTimeoutMs);
      })]);
    } finally {
      clearTimeout(timer);
      destroyTray();
      app.quit();
    }
  }

  function requestQuit() {
    if (ending || disposed) return Promise.resolve(false);
    if (exitRequest) return exitRequest;
    show();
    exitRequest = Promise.resolve().then(async () => {
      try {
        if (ending || disposed) return false;
        const result = await dialog.showMessageBox(window, {
          type: 'question', title: words.title, message: words.title,
          detail: words.detail, buttons: [words.cancel, words.confirm],
          defaultId: 0, cancelId: 0, noLink: true,
        });
        if (result.response !== 1 || ending || disposed) return false;
        await quitImmediately();
        return true;
      } catch {
        // A failed or interrupted dialog cannot authorize quitting.
        return false;
      } finally {
        exitRequest = undefined;
      }
    });
    return exitRequest;
  }

  try {
    const icon = nativeImage.createFromPath(iconPath);
    if (icon.isEmpty()) throw new Error('Missing tray icon');
    tray = new Tray(icon, TRAY_GUID);
    tray.setToolTip('Limen');
    tray.setContextMenu(Menu.buildFromTemplate([
      { label: words.open, click: show },
      { type: 'separator' },
      { label: words.exit, click: () => { void requestQuit(); } },
    ]));
    listen(tray, 'click', show);
    listen(tray, 'double-click', show);
    listen(tray, 'balloon-click', show);
  } catch {
    destroyTray();
    dialog.showErrorBox('Limen', words.trayError);
  }

  listen(window, 'close', (event) => {
    if (ending) return;
    event.preventDefault();
    if (!tray || tray.isDestroyed()) { void requestQuit(); return; }
    window.hide();
    window.setSkipTaskbar(true);
    if (!promptedBackground) {
      promptedBackground = true;
      try { tray.displayBalloon({ title: words.background, content: words.backgroundDetail, respectQuietTime: true }); }
      catch { /* The icon remains available when Windows suppresses balloons. */ }
    }
  });
  listen(app, 'second-instance', show);
  listen(app, 'activate', show);
  listen(app, 'before-quit', (event) => {
    if (ending) return;
    event.preventDefault();
    void requestQuit();
  });
  const shutdown = () => {
    ending = true;
    void startCleanup();
    destroyTray();
  };
  // Querying may still be cancelled by Windows or another app. Keep the tray
  // and active session intact until Windows commits to ending the session.
  listen(window, 'query-session-end', () => {});
  listen(window, 'session-end', shutdown);
  listen(app, 'window-all-closed', () => { if (!ending) void quitImmediately(); });
  listen(app, 'will-quit', () => { shutdown(); dispose(); });

  function dispose() {
    if (disposed) return;
    disposed = true;
    for (const remove of listeners.splice(0)) remove();
    destroyTray();
  }

  return { show, requestQuit, quitImmediately, dispose };
}

module.exports = { createLifecycle };
