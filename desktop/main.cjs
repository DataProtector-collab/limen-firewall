'use strict';

const { app, BrowserWindow, ipcMain, session, dialog, Tray, Menu, nativeImage } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { createBackend } = require('./backend.cjs');
const { isRendererResource, validateSender } = require('./security.cjs');
const { createLifecycle } = require('./lifecycle.cjs');
const { createApprovalBackend } = require('./approval-backend.cjs');
const { createGeolocation } = require('./geolocation.cjs');
const { verifyRuntime } = require('./runtime-integrity.cjs');
const nativeManifest = require('./native-runtime.json');

app.enableSandbox();
const rendererDirectory = path.resolve(__dirname, '../dist');
const entry = path.join(rendererDirectory, 'index.html');
const entryUrl = pathToFileURL(entry).href;
let mainWindow;
let lifecycle;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440, height: 940, minWidth: 900, minHeight: 650, title: 'Limen', backgroundColor: '#101820',
    autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true,
      sandbox: true, nodeIntegration: false, nodeIntegrationInWorker: false,
      webSecurity: true, allowRunningInsecureContent: false, webviewTag: false,
      devTools: !app.isPackaged, spellcheck: false, backgroundThrottling: false },
  });
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event) => event.preventDefault());
  mainWindow.webContents.on('will-attach-webview', (event) => event.preventDefault());
  mainWindow.loadFile(entry).catch((error) => {
    dialog.showErrorBox('Limen could not start', `Build the local interface before starting Limen.\n${error.message}`);
    if (lifecycle) void lifecycle.quitImmediately(); else app.quit();
  });
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.whenReady().then(() => {
    const native = createBackend({ scriptPath: app.isPackaged
      ? path.join(process.resourcesPath, 'windows-firewall.ps1')
      : path.join(__dirname, 'windows-firewall.ps1') });
    const runtimeDirectory = app.isPackaged ? path.join(process.resourcesPath, 'native') : path.join(__dirname, '../native/runtime');
    const approval = createApprovalBackend({ hostPath: path.join(runtimeDirectory, 'Limen.Approval.Host.exe'),
      verifyRuntime: () => verifyRuntime(runtimeDirectory, nativeManifest) });
    const geolocation = createGeolocation({ databasePath: path.join(__dirname, 'data/geo-country.bin.gz') });
    const localSession = session.defaultSession;
    localSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
    localSession.setPermissionCheckHandler(() => false);
    localSession.webRequest.onBeforeRequest((details, callback) => callback({ cancel: !isRendererResource(details.url, rendererDirectory) }));
    localSession.webRequest.onHeadersReceived((details, callback) => callback({
      responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': [
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'",
      ] },
    }));
    for (const operation of ['status', 'snapshot', 'processes', 'process-inspect', 'list', 'apply', 'remove', 'enabled']) {
      ipcMain.handle(`limen:${operation}`, (event, payload, ...extra) => {
        validateSender(event, mainWindow, entryUrl);
        if (extra.length) throw new Error('Unexpected native arguments.');
        return native.invoke(operation, payload);
      });
    }
    for (const operation of ['status', 'start', 'stop', 'decide']) {
      ipcMain.handle(`limen:approval-${operation}`, (event, payload, ...extra) => {
        validateSender(event, mainWindow, entryUrl);
        if (extra.length) throw new Error('Unexpected native approval arguments.');
        return approval.invoke(operation, payload);
      });
    }
    ipcMain.handle('limen:geo-locations', (event, addresses, ...extra) => {
      validateSender(event, mainWindow, entryUrl);
      if (extra.length) throw new Error('Unexpected geolocation arguments.');
      return geolocation.lookup(addresses);
    });
    ipcMain.handle('limen:quit', (event, ...arguments_) => {
      validateSender(event, mainWindow, entryUrl);
      if (arguments_.length) throw new Error('Quit takes no arguments.');
      // Return before destroying the requesting renderer. The native dialog owns confirmation.
      void lifecycle.requestQuit();
    });
    createWindow();
    let attentionTimer;
    let stopping = false;
    let lastAttentionAt = 0;
    let notified = new Set();
    lifecycle = createLifecycle({ app, window: mainWindow, Tray, Menu, dialog, nativeImage,
      iconPath: path.join(__dirname, '../public/limen.ico'), beforeQuit: async () => {
        stopping = true;
        clearTimeout(attentionTimer);
        approval.close();
      } });
    // Main-process polling continues when the renderer is hidden. A burst opens
    // one review surface; it never approves traffic or executes a rule itself.
    const pollAttention = async () => {
      try {
        const status = await approval.invoke('status');
        if (stopping) return;
        const pending = status.active ? status.attempts.filter(item => item.decision === 'pending') : [];
        const fresh = pending.filter(item => !notified.has(item.id));
        if (fresh.length && Date.now() - lastAttentionAt >= 5000 && !mainWindow.isDestroyed()
          && !mainWindow.webContents.isLoading()) {
          lastAttentionAt = Date.now();
          for (const item of fresh) notified.add(item.id);
          lifecycle.show();
          mainWindow.webContents.send('limen:approval-attention');
          mainWindow.flashFrame(true);
        }
        const retained = new Set(status.attempts.map(item => item.id));
        notified = new Set([...notified].filter(id => retained.has(id)));
      } catch { /* Renderer status polling displays native failures. */ }
      if (!stopping) attentionTimer = setTimeout(() => void pollAttention(), 1500);
    };
    void pollAttention();
    mainWindow.on('focus', () => mainWindow.flashFrame(false));
  });
}
