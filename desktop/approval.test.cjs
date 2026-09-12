'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough, Writable } = require('node:stream');
const { createApprovalBackend } = require('./approval-backend.cjs');
const { validateApprovalRequest, validateTestProgram } = require('./approval-validation.cjs');

const status = (active = false) => ({ available: true, active, sessionId: active ? '86d5fcc6-833b-4c8b-a6f8-e530f6daf37d' : '', startedAt: 0,
  scope: 'internet', attempts: [], approvedCount: 0, deniedCount: 0, droppedEvents: 0 });
const tick = () => new Promise((resolve) => setImmediate(resolve));
function harness() {
  const commands = [];
  let child;
  const spawn = () => {
    const next = new EventEmitter();
    next.stdout = new PassThrough(); next.stderr = new PassThrough();
    next.stdin = new Writable({ write(chunk, _encoding, done) { commands.push(chunk.toString()); done(); } });
    next.killed = false;
    next.kill = () => { next.killed = true; next.emit('close', 1); };
    child = next; return next;
  };
  const reply = (data) => child.stdout.write(`${JSON.stringify({ ok: true, data })}\n`);
  let verificationCalls = 0;
  const backend = createApprovalBackend({ platform: 'win32', spawnProcess: spawn,
    verifyRuntime: async () => { verificationCalls += 1; }, timeout: 1000 });
  return { backend, get child() { return child; }, commands, reply, verificationCalls: () => verificationCalls };
}

test('approval accepts exact decisions and rejects renderer-controlled paths or native test commands', () => {
  const id = '86d5fcc6-833b-4c8b-a6f8-e530f6daf37d:1';
  assert.deepEqual(validateApprovalRequest('decide', { id, decision: 'allow-endpoint' }), { id, decision: 'allow-endpoint' });
  for (const payload of [{ id: `${id}\nSTOP`, decision: 'deny' }, { id, decision: 'allow' },
    { id, decision: 'deny', program: 'C:\\malicious.exe' }, [], null]) {
    assert.throws(() => validateApprovalRequest('decide', payload));
  }
  assert.throws(() => validateApprovalRequest('start', { scopeProgram: 'C:\\other.exe' }));
  assert.throws(() => validateApprovalRequest('TEST_START'));
  assert.throws(() => validateTestProgram('C:\\Windows\\System32\\cmd.exe'));
  assert.equal(validateTestProgram('C:\\Test\\LimenApprovalProbe-123.exe'), 'C:\\Test\\LimenApprovalProbe-123.exe');
});

test('approval checks native integrity before spawning and reports unavailable without a verifier', async () => {
  let spawns = 0;
  const backend = createApprovalBackend({ platform: 'win32', spawnProcess: () => { spawns += 1; } });
  const unavailable = await backend.invoke('status');
  assert.equal(unavailable.active, false); assert.match(unavailable.reason, /integrity verifier/); assert.equal(spawns, 0);
  const broken = createApprovalBackend({ platform: 'win32', verifyRuntime: async () => { throw new Error('Hash mismatch'); },
    spawnProcess: () => { spawns += 1; } });
  await assert.rejects(broken.invoke('start'), /Hash mismatch/); assert.equal(spawns, 0);
});

test('approval serializes mutations and does not coalesce status reads across a start', async () => {
  const h = harness();
  const before = h.backend.invoke('status');
  assert.equal(h.backend.invoke('status'), before);
  const start = h.backend.invoke('start');
  const after = h.backend.invoke('status');
  assert.notEqual(before, after);
  await tick(); assert.deepEqual(h.commands, ['STATUS\n']);
  h.reply(status(false)); assert.equal((await before).active, false);
  await tick(); assert.equal(h.commands[1], 'START\n');
  h.reply(status(true)); await start;
  await tick(); assert.equal(h.commands[2], 'STATUS\n');
  h.reply(status(true)); assert.equal((await after).active, true);
  assert.equal(h.verificationCalls(), 1); h.backend.close();
});

test('native host exit rejects a pending decision and clears reported protection', async () => {
  const h = harness();
  const start = h.backend.invoke('start'); await tick(); h.reply(status(true)); await start;
  const decide = h.backend.invoke('decide', { id: '86d5fcc6-833b-4c8b-a6f8-e530f6daf37d:1', decision: 'deny' });
  const rejection = assert.rejects(decide, /host exited/);
  await tick(); h.child.emit('close', 42); await rejection;
  const recovered = h.backend.invoke('status'); await tick(); h.reply(status(false));
  const failed = await recovered; assert.equal(failed.active, false); assert.equal(failed.available, true); assert.match(failed.reason, /host exited/);
  const restart = h.backend.invoke('start'); await tick(); h.reply(status(true));
  assert.equal((await restart).reason, undefined); h.backend.close();
});

test('malformed native status terminates the host rather than retaining a claimed active session', async () => {
  const h = harness(); const read = h.backend.invoke('status'); await tick();
  h.reply({ ...status(true), attempts: new Array(257).fill({}) });
  const value = await read;
  assert.equal(h.child.killed, true); assert.equal(value.active, false); assert.match(value.reason, /Invalid native approval status/);
});

test('closing approval kills its owning process and prevents a queued restart', async () => {
  const h = harness(); const start = h.backend.invoke('start');
  const failure = assert.rejects(start, /stopped/); await tick(); h.backend.close(); await failure;
  assert.equal(h.child.killed, true);
  await assert.rejects(h.backend.invoke('start'), /shutting down/);
});
