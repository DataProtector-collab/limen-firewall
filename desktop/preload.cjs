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
  getGeoLocations: (addresses) => ipcRenderer.invoke('limen:geo-locations', addresses),
  getApprovalStatus: () => ipcRenderer.invoke('limen:approval-status'),
  startApproval: () => ipcRenderer.invoke('limen:approval-start'),
  stopApproval: () => ipcRenderer.invoke('limen:approval-stop'),
  decideApproval: (input) => ipcRenderer.invoke('limen:approval-decide', input),
  quitApplication: () => ipcRenderer.invoke('limen:quit'),
  onApprovalAttention: (listener) => {
    if (typeof listener !== 'function') throw new TypeError('An attention listener is required.');
    const callback = () => listener();
    ipcRenderer.on('limen:approval-attention', callback);
    return () => ipcRenderer.removeListener('limen:approval-attention', callback);
  },
}));
