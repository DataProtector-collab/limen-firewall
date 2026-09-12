'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { isRendererResource, validateSender } = require('./security.cjs');

test('native IPC rejects foreign windows, subframes, navigation and URL lookalikes', () => {
  const url = 'file:///C:/Limen/resources/app.asar/dist/index.html';
  const frame = { url };
  const window = { isDestroyed: () => false, webContents: { mainFrame: frame } };
  const event = { sender: window.webContents, senderFrame: frame };
  assert.doesNotThrow(() => validateSender(event, window, url));
  frame.url += '#rules';
  assert.doesNotThrow(() => validateSender(event, window, url));
  assert.throws(() => validateSender({ ...event, sender: {} }, window, url));
  assert.throws(() => validateSender({ ...event, senderFrame: { url } }, window, url));
  assert.throws(() => validateSender(event, null, url));
  for (const untrusted of ['https://github.com/', url + '?remote=1', url + '.evil', 'file:///C:/evil/index.html', 'about:blank']) {
    frame.url = untrusted;
    assert.throws(() => validateSender(event, window, url), undefined, untrusted);
  }
  frame.url = url;
  window.isDestroyed = () => true;
  assert.throws(() => validateSender(event, window, url));
});

test('renderer resources stay inside the bundled dist directory and cannot use a network protocol', () => {
  const directory = path.resolve('dist');
  assert.equal(isRendererResource(pathToFileURL(path.join(directory, 'index.html')).href, directory), true);
  assert.equal(isRendererResource(pathToFileURL(path.join(directory, 'assets', 'app.js')).href, directory), true);
  for (const file of [path.resolve('desktop', 'main.cjs'), path.resolve('dist-evil', 'app.js'), path.resolve('package.json')]) {
    assert.equal(isRendererResource(pathToFileURL(file).href, directory), false);
  }
  for (const url of ['https://example.com/app.js', 'http://localhost:8080/', 'ws://127.0.0.1/', 'javascript:alert(1)', 'data:text/html,hello', 'not-a-url']) {
    assert.equal(isRendererResource(url, directory), false);
  }
});
