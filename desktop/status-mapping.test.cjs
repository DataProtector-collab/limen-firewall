'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

test('Windows ActiveStore status overrides persistent OK and handles missing rules without claiming enforcement', {
  skip: process.platform !== 'win32', timeout: 20000,
}, () => {
  const powershell = path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const result = spawnSync(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', path.join(__dirname, 'status-mapping-tests.ps1'), '-SourcePath', path.join(__dirname, 'windows-firewall.ps1')],
  { windowsHide: true, shell: false, encoding: 'utf8', timeout: 15000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /ActiveStore status mapping passed/);
});
