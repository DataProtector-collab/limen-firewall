'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

test('Windows verifies real 8.3 program aliases and reports exact mismatched fields without private paths', {
  skip: process.platform !== 'win32', timeout: 20000,
}, (context) => {
  const powershell = path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const result = spawnSync(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', path.join(__dirname, 'path-normalization-tests.ps1'), '-SourcePath', path.join(__dirname, 'windows-firewall.ps1'),
    '-NodePath', process.execPath], { windowsHide: true, shell: false, encoding: 'utf8', timeout: 15000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout.trim());
  assert.equal(report.fieldDiagnosticsChecked, true);
  if (!report.aliasChecked) context.diagnostic('This filesystem exposed no 8.3 alias; distinct-path and diagnostic checks still passed.');
  else context.diagnostic('Verified an existing DOS 8.3 alias against its canonical long program path.');
});
