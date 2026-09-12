'use strict';

const { contextBridge, ipcRenderer } = require('electron');

// Expose one capability per operation. Never expose ipcRenderer or a generic shell API.
contextBridge.exposeInMainWorld('limen', Object.freeze({
  platform: process.platform,
  getStatus: () => ipcRenderer.invoke('limen:status'),
  getSnapshot: () => ipcRenderer.invoke('limen:snapshot'),
  getProcessSnapshot: () => ipcRenderer.invoke('limen:processes'),
  inspectProcess: (identity) => ipcRenderer.invoke('limen:process-inspect', identity),
  listRules: () => ipcRenderer.invoke('limen:list'),
  applyRule: (input) => ipcRenderer.invoke('limen:apply', input),
  removeRule: (id) => ipcRenderer.invoke('limen:remove', id),
  setRuleEnabled: (id, enabled) => ipcRenderer.invoke('limen:enabled', { id, enabled }),
}));
