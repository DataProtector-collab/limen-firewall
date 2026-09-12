'use strict';

const path = require('node:path');
const { fileURLToPath } = require('node:url');

function isRendererResource(url, directory) {
  try {
    if (new URL(url).protocol !== 'file:') return false;
    const relative = path.relative(directory, fileURLToPath(url));
    return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
  } catch { return false; }
}

function validateSender(event, window, entryUrl) {
  if (!window || window.isDestroyed() || event.sender !== window.webContents
    || event.senderFrame !== window.webContents.mainFrame
    || event.senderFrame.url.split('#')[0] !== entryUrl) {
    throw new Error('Native access is restricted to the local Limen application.');
  }
}

module.exports = { isRendererResource, validateSender };
