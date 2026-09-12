'use strict';

const path = require('node:path');
const { spawn } = require('node:child_process');
const { isIP } = require('node:net');
const { validateApprovalRequest, validateTestProgram } = require('./approval-validation.cjs');

function inactive(reason, available = false) {
  return { available, active: false, sessionId: '', startedAt: 0, scope: 'internet', attempts: [],
    approvedCount: 0, deniedCount: 0, droppedEvents: 0, ...(reason ? { reason } : {}) };
}

function validStatus(value) {
  const guid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
  const sessionPattern = new RegExp(`^${guid}$`, 'i');
  const attemptPattern = new RegExp(`^${guid}:[1-9][0-9]{0,9}$`, 'i');
  return value && typeof value === 'object' && typeof value.available === 'boolean' && typeof value.active === 'boolean'
    && typeof value.sessionId === 'string' && (value.sessionId === '' || sessionPattern.test(value.sessionId))
    && (!value.active || (value.available && sessionPattern.test(value.sessionId)))
    && Number.isSafeInteger(value.startedAt) && value.startedAt >= 0
    && ['internet', 'test-program'].includes(value.scope) && Array.isArray(value.attempts) && value.attempts.length <= 256
    && ['approvedCount', 'deniedCount', 'droppedEvents'].every((key) => Number.isSafeInteger(value[key]) && value[key] >= 0)
    && (value.reason === undefined || (typeof value.reason === 'string' && value.reason.length <= 2000))
    && value.attempts.every((attempt) => attempt && typeof attempt.id === 'string' && attemptPattern.test(attempt.id)
      && attempt.id.startsWith(`${value.sessionId}:`) && typeof attempt.program === 'string' && attempt.program.length <= 4096
      && typeof attempt.remoteAddress === 'string' && isIP(attempt.remoteAddress) && ['TCP', 'UDP'].includes(attempt.protocol)
      && Number.isInteger(attempt.remotePort) && attempt.remotePort >= 0 && attempt.remotePort <= 65535
      && ['pending', 'allow-endpoint', 'allow-program', 'deny'].includes(attempt.decision)
      && typeof attempt.canApprove === 'boolean'
      && ['firstSeenAt', 'lastSeenAt', 'count'].every((key) => Number.isSafeInteger(attempt[key]) && attempt[key] >= 0));
}

function createApprovalBackend({ hostPath = path.join(__dirname, '../native/runtime/Limen.Approval.Host.exe'),
  platform = process.platform, spawnProcess = spawn, verifyRuntime, timeout = 15000 } = {}) {
  let child = null;
  let pending = null;
  let buffer = '';
  let tail = Promise.resolve();
  const reads = new Map();
  let generation = 0;
  let queueLength = 0;
  let closing = false;
  let lastFailure = '';

  function disconnect(reason, processToStop = child) {
    if (!processToStop || processToStop !== child) return;
    child = null;
    buffer = '';
    if (reason) lastFailure = reason;
    if (pending) {
      const current = pending; pending = null; clearTimeout(current.timer);
      current.reject(new Error(reason || 'The native approval host was stopped. Its temporary filters are removed.'));
    }
    // Kill is also a safe recovery from malformed protocol/timeouts: dynamic WFP objects cannot outlive the host.
    processToStop.kill();
  }

  async function ensureHost() {
    if (child) return;
    if (closing) throw new Error('Connection approval is shutting down.');
    if (platform !== 'win32') throw new Error('Connection approval requires the Windows desktop application.');
    if (typeof verifyRuntime !== 'function') throw new Error('The native approval runtime has no integrity verifier.');
    await verifyRuntime();
    if (closing) throw new Error('Connection approval is shutting down.');
    const processToStart = spawnProcess(hostPath, [], { windowsHide: true, shell: false,
      cwd: path.dirname(hostPath), stdio: ['pipe', 'pipe', 'pipe'] });
    child = processToStart;
    buffer = '';
    processToStart.stdout.setEncoding('utf8');
    processToStart.stderr.setEncoding('utf8');
    processToStart.stdout.on('data', (chunk) => {
      if (child !== processToStart) return;
      buffer += chunk;
      if (Buffer.byteLength(buffer) > 12 * 1024 * 1024) return disconnect('Native approval response exceeded its limit.', processToStart);
      let newline;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1);
        if (!pending) return disconnect('Unexpected native approval response.', processToStart);
        const current = pending; pending = null; clearTimeout(current.timer);
        try {
          const result = JSON.parse(line);
          if (!result || typeof result.ok !== 'boolean') throw new Error('Invalid native approval response.');
          if (!result.ok) {
            current.reject(new Error(typeof result.error === 'string' ? result.error : 'Windows rejected the approval operation.'));
          } else {
            if (!validStatus(result.data)) throw new Error('Invalid native approval status.');
            current.resolve(result.data);
          }
        } catch (error) { current.reject(error); disconnect(error.message, processToStart); }
      }
    });
    // Runtime diagnostics never become an unbounded in-memory log or part of the IPC data contract.
    processToStart.stderr.on('data', () => {});
    processToStart.on('error', (error) => disconnect(`Cannot run the native approval host: ${error.message}`, processToStart));
    processToStart.stdin.on('error', (error) => disconnect(`Native approval input failed: ${error.message}`, processToStart));
    processToStart.on('close', () => {
      if (child === processToStart) disconnect('The native approval host exited. The session and its temporary permissions ended.', processToStart);
    });
  }

  async function command(text) {
    await ensureHost();
    if (!child || closing) throw new Error('Connection approval is shutting down or its host exited.');
    const currentChild = child;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => disconnect('Windows did not answer the approval request in time. The temporary session was stopped.'), timeout);
      pending = { resolve, reject, timer };
      try { currentChild.stdin.write(`${text}\n`, 'utf8'); }
      catch (error) { disconnect(`Cannot write the native approval request: ${error.message}`, currentChild); }
    });
  }

  function enqueue(work) {
    if (queueLength >= 32) return Promise.reject(new Error('Too many approval requests are pending.'));
    queueLength += 1;
    const result = tail.then(work);
    tail = result.catch(() => {}).finally(() => { queueLength -= 1; });
    return result;
  }

  function invoke(operation, payload) {
    const value = validateApprovalRequest(operation, payload);
    if (operation !== 'status') generation += 1;
    const readKey = generation;
    if (operation === 'status' && reads.has(readKey)) return reads.get(readKey);
    const work = async () => {
      if (platform !== 'win32') {
        if (operation === 'status' || operation === 'stop') return inactive('Connection approval requires the Windows desktop application.');
        throw new Error('Connection approval requires the Windows desktop application.');
      }
      if (closing) {
        if (operation === 'status' || operation === 'stop') return inactive('Connection approval is shutting down.');
        throw new Error('Connection approval is shutting down.');
      }
      if (operation === 'stop' && !child) return inactive(lastFailure || undefined, !lastFailure);
      const result = await command(operation === 'decide' ? `DECIDE\t${value.id}\t${value.decision}` : operation.toUpperCase());
      if (operation === 'start' || operation === 'stop') lastFailure = '';
      return operation === 'status' && lastFailure ? { ...result, reason: lastFailure } : result;
    };
    const result = enqueue(work);
    if (operation === 'status') {
      const read = result.catch((error) => inactive(error.message)).finally(() => { reads.delete(readKey); });
      reads.set(readKey, read);
      return read;
    }
    return result;
  }

  // Test-only local API: never expose this method or its input through Electron IPC.
  function startScopedTest(program) {
    const checked = validateTestProgram(program);
    return enqueue(() => command(`TEST_START\t${checked}`));
  }

  function close() {
    closing = true;
    disconnect(undefined);
  }

  return { invoke, close, startScopedTest };
}

module.exports = { createApprovalBackend, validStatus };
