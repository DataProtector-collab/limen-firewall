'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough, Writable } = require('node:stream');
const { validateRule, validateId, validateRequest } = require('./validation.cjs');
const { createBackend } = require('./backend.cjs');

const validRule = { program: 'C:\\Program Files\\Example\\app.exe', action: 'block', direction: 'out', protocol: 'TCP' };
const id = 'Limen-00000000-0000-4000-8000-000000000001';

test('validates only explicit local per-program firewall scopes', () => {
  assert.deepEqual(validateRule({ ...validRule, remoteAddress: '2001:db8::1', remotePort: 443 }), {
    ...validRule, remoteAddress: '2001:db8::1', remotePort: 443,
  });
  for (const program of ['app.exe', '\\\\server\\app.exe', '\\\\?\\C:\\app.exe', 'C:app.exe',
    'C:\\app.exe:stream.exe', 'C:\\*.exe', 'C:\\..\\app.exe', 'C:\\app.ps1', 'C:/app.exe', '%windir%\\app.exe']) {
    assert.throws(() => validateRule({ ...validRule, program }), undefined, program);
  }
  for (const remoteAddress of ['example.org', '*', 'LocalSubnet', '192.168.1.0/24', '127.1', '127.0.0.1;Write-Host', 'fe80::1%4']) {
    assert.throws(() => validateRule({ ...validRule, remoteAddress }), undefined, remoteAddress);
  }
  for (const port of [-1, 0, 65536, 1.2, '443', null, true]) {
    assert.throws(() => validateRule({ ...validRule, remotePort: port }));
  }
  assert.throws(() => validateRule({ ...validRule, protocol: 'ANY', localPort: 80 }));
  assert.throws(() => validateRule({ ...validRule, action: 'ask' }));
  assert.throws(() => validateRule({ ...validRule, direction: 'both' }));
  assert.throws(() => validateRule({ ...validRule, command: 'Set-NetFirewallProfile' }));
  assert.throws(() => validateRule(null));
});

test('restricts all mutations to individual names in the owned namespace', () => {
  assert.equal(validateId(id), id);
  for (const foreign of ['*', 'Limen-*', 'Windows-RemoteDesktop', id + '*', id + '; Get-Process']) {
    assert.throws(() => validateId(foreign));
  }
  assert.deepEqual(validateRequest('enabled', { id, enabled: false }), { id, enabled: false });
  assert.throws(() => validateRequest('enabled', { id, enabled: 'false' }));
  assert.throws(() => validateRequest('enabled', { id, enabled: true, program: '*' }));
  assert.throws(() => validateRequest('status', {}));
  assert.throws(() => validateRequest('setProfile', {}));
});

function fakeSpawn(response = { ok: true, data: [] }, exitCode = 0) {
  const calls = [];
  function spawn(executable, args, options) {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => { child.emit('close', 1); };
    const call = { executable, args, options, input: '' };
    calls.push(call);
    child.stdin = new Writable({ write(chunk, _encoding, done) { call.input += chunk.toString(); done(); } });
    child.stdin.on('finish', () => setImmediate(() => {
      child.stdout.end(typeof response === 'string' ? response : JSON.stringify(response));
      child.emit('close', exitCode);
    }));
    return child;
  }
  return { spawn, calls };
}

test('keeps shell syntax in JSON stdin with a fixed script and hidden process', async () => {
  const mock = fakeSpawn({ ok: true, data: { ...validRule, id, enabled: true, createdAt: 1 } });
  const backend = createBackend({ platform: 'win32', spawnProcess: mock.spawn, scriptPath: 'C:\\Limen\\windows-firewall.ps1' });
  const program = "C:\\Apps\\safe;$(Write-Host 'injection').exe";
  await backend.invoke('apply', { ...validRule, program });
  assert.equal(mock.calls.length, 1);
  const call = mock.calls[0];
  assert.equal(call.options.shell, false);
  assert.equal(call.options.windowsHide, true);
  assert.deepEqual(call.args, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', 'C:\\Limen\\windows-firewall.ps1']);
  assert.equal(JSON.parse(call.input).data.program, program);
  assert.ok(!call.args.includes(program));
});

test('propagates native failures without turning them into success or an empty list', async () => {
  const mock = fakeSpawn({ ok: false, error: 'Administrator permission is required.' }, 1);
  const backend = createBackend({ platform: 'win32', spawnProcess: mock.spawn });
  await assert.rejects(backend.invoke('remove', id), /Administrator/);
  const malformed = fakeSpawn('not json', 0);
  await assert.rejects(createBackend({ platform: 'win32', spawnProcess: malformed.spawn }).invoke('list'), /Cannot read/);
});

test('deduplicates concurrent reads but serializes distinct mutations', async () => {
  const mock = fakeSpawn();
  const backend = createBackend({ platform: 'win32', spawnProcess: mock.spawn });
  const first = backend.invoke('list');
  const second = backend.invoke('list');
  assert.equal(first, second);
  await Promise.all([first, second]);
  assert.equal(mock.calls.length, 1);
  await Promise.all([backend.invoke('remove', id), backend.invoke('enabled', { id, enabled: true })]);
  assert.deepEqual(mock.calls.map((call) => JSON.parse(call.input).operation), ['list', 'remove', 'enabled']);
});

test('post-mutation rule reads wait for writes and cannot reuse a stale in-flight list', async () => {
  const calls = [];
  const spawnProcess = (_executable, _args, _options) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => child.emit('close', 1);
    const call = { input: '', respond(data) { child.stdout.end(JSON.stringify({ ok: true, data })); child.emit('close', 0); } };
    calls.push(call);
    child.stdin = new Writable({ write(chunk, _encoding, done) { call.input += chunk.toString(); done(); } });
    return child;
  };
  const tick = () => new Promise((resolve) => setImmediate(resolve));
  const backend = createBackend({ platform: 'win32', spawnProcess });
  const stale = backend.invoke('list');
  await tick();
  const mutation = backend.invoke('apply', validRule);
  const fresh = backend.invoke('list');
  await tick();
  assert.equal(calls.length, 2, 'The new list must wait until the mutation finishes.');
  const rule = { ...validRule, id, enabled: true, createdAt: 1 };
  calls[1].respond(rule);
  await mutation;
  await tick();
  assert.equal(calls.length, 3);
  calls[0].respond([]);
  assert.deepEqual(await stale, []);
  assert.equal(backend.invoke('list'), fresh, 'An old read must not remove the current generation cache.');
  calls[2].respond([rule]);
  assert.deepEqual(await fresh, [rule]);
  assert.deepEqual(calls.map((call) => JSON.parse(call.input).operation), ['list', 'apply', 'list']);
});

test('unsupported platforms never simulate a firewall or launch a backend', async () => {
  const backend = createBackend({ platform: 'linux', spawnProcess: () => { throw new Error('Must not spawn.'); } });
  const status = await backend.invoke('status');
  assert.equal(status.available, false);
  assert.equal(status.backend, 'none');
  const snapshot = await backend.invoke('snapshot');
  assert.equal(snapshot.capture, 'unavailable');
  assert.deepEqual(snapshot.sockets, []);
  await assert.rejects(backend.invoke('apply', validRule), /Windows/);
});

test('Windows smoke: reads actual profile state and socket tables without mutations', {
  skip: process.platform !== 'win32' || process.env.LIMEN_WINDOWS_READ_TEST !== '1', timeout: 90000,
}, async () => {
  const backend = createBackend();
  const [status, snapshot] = await Promise.all([backend.invoke('status'), backend.invoke('snapshot')]);
  assert.equal(status.platform, 'win32');
  assert.equal(status.available, true, status.reason);
  assert.ok(status.profiles.length > 0);
  assert.equal(snapshot.available, true, snapshot.error);
  assert.equal(snapshot.capture, 'windows');
  assert.equal(snapshot.sockets.length, snapshot.tcpInuse + snapshot.udpInuse);
  for (const socket of snapshot.sockets) {
    assert.equal(socket.direction, 'unknown');
    assert.equal(socket.signature, undefined);
    if (socket.proto === 'UDP') { assert.equal(socket.remoteIp, ''); assert.equal(socket.remotePort, 0); }
  }
  if (!status.elevated) await assert.rejects(backend.invoke('apply', validRule), /Administrator permission/);
});
