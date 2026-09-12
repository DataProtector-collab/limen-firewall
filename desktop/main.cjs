'use strict';

const { app, BrowserWindow, ipcMain, session, dialog } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { createBackend } = require('./backend.cjs');
const { isRendererResource, validateSender } = require('./security.cjs');

app.enableSandbox();
const rendererDirectory = path.resolve(__dirname, '../dist');
const entry = path.join(rendererDirectory, 'index.html');
const entryUrl = pathToFileURL(entry).href;
let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440, height: 940, minWidth: 900, minHeight: 650, title: 'Limen', backgroundColor: '#101820',
    autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true,
      sandbox: true, nodeIntegration: false, nodeIntegrationInWorker: false,
      webSecurity: true, allowRunningInsecureContent: false, webviewTag: false,
      devTools: !app.isPackaged, spellcheck: false },
  });
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event) => event.preventDefault());
  mainWindow.webContents.on('will-attach-webview', (event) => event.preventDefault());
  mainWindow.loadFile(entry).catch((error) => {
    dialog.showErrorBox('Limen could not start', `Build the local interface before starting Limen.\n${error.message}`);
    app.quit();
  });
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow && !mainWindow.isDestroyed()) { if (mainWindow.isMinimized()) mainWindow.restore(); mainWindow.focus(); }
  });
  app.whenReady().then(() => {
    const native = createBackend({ scriptPath: app.isPackaged
      ? path.join(process.resourcesPath, 'windows-firewall.ps1')
      : path.join(__dirname, 'windows-firewall.ps1') });
    const localSession = session.defaultSession;
    localSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
    localSession.setPermissionCheckHandler(() => false);
    localSession.webRequest.onBeforeRequest((details, callback) => callback({ cancel: !isRendererResource(details.url, rendererDirectory) }));
    localSession.webRequest.onHeadersReceived((details, callback) => callback({
      responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': [
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'",
      ] },
    }));
    for (const operation of ['status', 'snapshot', 'list', 'apply', 'remove', 'enabled']) {
      ipcMain.handle(`limen:${operation}`, (event, payload, ...extra) => {
        validateSender(event, mainWindow, entryUrl);
        if (extra.length) throw new Error('Unexpected native arguments.');
        return native.invoke(operation, payload);
      });
    }
    createWindow();
    app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
  app.on('window-all-closed', () => app.quit());
}
