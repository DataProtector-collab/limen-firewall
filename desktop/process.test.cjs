'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough, Writable } = require('node:stream');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { createBackend } = require('./backend.cjs');
const { validateRequest } = require('./validation.cjs');

test('process inspection accepts only a bounded exact PID/start identity, never caller file paths', () => {
  const valid = { pid: 42, startedAt: 1700000000000 };
  assert.deepEqual(validateRequest('process-inspect', valid), valid);
  for (const invalid of [undefined, null, [], {}, { ...valid, pid: 0 }, { ...valid, pid: '42' },
    { ...valid, pid: 4294967296 }, { ...valid, startedAt: NaN }, { ...valid, startedAt: Infinity },
    { ...valid, startedAt: 1.1 }, { ...valid, startedAt: '1700000000000' },
    { ...valid, startedAt: 8640000000000001 }, { ...valid, path: 'C:\\secret.txt' }]) {
    assert.throws(() => validateRequest('process-inspect', invalid));
  }
  assert.throws(() => validateRequest('processes', {}));
});

function deferredSpawner() {
  const calls = [];
  const spawn = () => {
    const child = new EventEmitter();
    child.stdout = new PassThrough(); child.stderr = new PassThrough();
    const call = { input: '', killed: false, respond(data, ok = true) {
      child.stdout.end(JSON.stringify(ok ? { ok, data } : { ok, error: data })); child.emit('close', ok ? 0 : 1);
    } };
    child.kill = () => { call.killed = true; child.emit('close', 1); };
    child.stdin = new Writable({ write(chunk, _encoding, done) { call.input += chunk; done(); } });
    calls.push(call);
    return child;
  };
  return { calls, spawn };
}

test('process reads deduplicate only identical instances and do not delay ordinary network capture', async () => {
  const mock = deferredSpawner();
  const backend = createBackend({ platform: 'win32', spawnProcess: mock.spawn });
  const first = backend.invoke('process-inspect', { pid: 42, startedAt: 1000 });
  assert.equal(first, backend.invoke('process-inspect', { pid: 42, startedAt: 1000 }));
  const reused = backend.invoke('process-inspect', { pid: 42, startedAt: 2000 });
  const other = backend.invoke('process-inspect', { pid: 43, startedAt: 1000 });
  const snapshot = backend.invoke('snapshot');
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(mock.calls.length, 4);
  assert.deepEqual(mock.calls.map((call) => JSON.parse(call.input)), [
    { operation: 'process-inspect', data: { pid: 42, startedAt: 1000 } },
    { operation: 'process-inspect', data: { pid: 42, startedAt: 2000 } },
    { operation: 'process-inspect', data: { pid: 43, startedAt: 1000 } },
    { operation: 'snapshot' },
  ]);
  mock.calls[3].respond({ available: true });
  assert.equal((await snapshot).available, true);
  mock.calls[0].respond({ available: false, errors: ['exited'] });
  mock.calls[1].respond({ available: true }); mock.calls[2].respond({ available: true });
  assert.equal((await first).available, false);
  assert.equal((await reused).available, true);
  await other;
  const retry = backend.invoke('process-inspect', { pid: 42, startedAt: 1000 });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(mock.calls.length, 5, 'Unavailable observations must not remain cached.');
  mock.calls[4].respond({ available: true }); await retry;
});

test('process timeout terminates its reader and leaves no poisoned in-flight cache', async () => {
  const mock = deferredSpawner();
  const backend = createBackend({ platform: 'win32', spawnProcess: mock.spawn, timeout: 25 });
  await assert.rejects(backend.invoke('process-inspect', { pid: 42, startedAt: 1000 }), /Process observation timed out/);
  assert.equal(mock.calls[0].killed, true);
  const retry = backend.invoke('process-inspect', { pid: 42, startedAt: 1000 });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(mock.calls.length, 2);
  mock.calls[1].respond({ available: true }); await retry;
});

test('non-Windows process capabilities return unavailable without inventing observations', async () => {
  const backend = createBackend({ platform: 'linux', spawnProcess: () => { throw new Error('Must not launch'); } });
  const inventory = await backend.invoke('processes');
  assert.equal(inventory.available, false); assert.deepEqual(inventory.processes, []);
  const inspected = await backend.invoke('process-inspect', { pid: 42, startedAt: 1000 });
  assert.equal(inspected.available, false); assert.equal(inspected.process, undefined);
  assert.deepEqual(inspected.modules, []); assert.equal(inspected.signature.status, 'unknown');
});

test('Windows process correlation rejects PID reuse, bounds modules and preserves partial service failures', {
  skip: process.platform !== 'win32', timeout: 30000,
}, () => {
  const powershell = path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const result = spawnSync(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
    path.join(__dirname, 'process-tests.ps1'), '-SourcePath', path.join(__dirname, 'windows-firewall.ps1')],
  { windowsHide: true, shell: false, encoding: 'utf8', timeout: 20000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Native process regression cases passed/);
});

test('Windows process smoke reads real host containers and inspects only this exact test process', {
  skip: process.platform !== 'win32' || process.env.LIMEN_WINDOWS_READ_TEST !== '1', timeout: 90000,
}, async () => {
  const backend = createBackend();
  const inventory = await backend.invoke('processes');
  assert.equal(inventory.available, true, inventory.errors.join('; '));
  assert.ok(inventory.processes.length > 0 && inventory.processes.length <= 4096);
  const own = inventory.processes.find((entry) => entry.pid === process.pid);
  assert.ok(own?.startedAt); assert.ok(own.exe);
  for (const entry of inventory.processes) {
    assert.equal('commandLine' in entry, false);
    assert.ok(entry.services.length <= 128);
    for (const service of entry.services) { assert.ok(service.name); assert.equal('commandLine' in service, false); }
  }
  const identity = { pid: own.pid, startedAt: own.startedAt };
  const inspected = await backend.invoke('process-inspect', identity);
  assert.equal(inspected.available, true, inspected.errors.join('; '));
  assert.equal(inspected.process.pid, process.pid);
  assert.equal(inspected.process.startedAt, own.startedAt);
  assert.match(inspected.sha256, /^[0-9a-f]{64}$/);
  assert.ok(inspected.modules.length > 0 && inspected.modules.length <= 256);
  const mismatched = await backend.invoke('process-inspect', { ...identity, startedAt: own.startedAt - 1 });
  assert.equal(mismatched.available, false);
  assert.equal(mismatched.sha256, undefined);
  assert.deepEqual(mismatched.modules, []);
});
