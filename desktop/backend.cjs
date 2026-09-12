'use strict';

const path = require('node:path');
const { spawn } = require('node:child_process');
const { validateRequest } = require('./validation.cjs');

function unavailableSnapshot(reason, platform) {
  return { at: Date.now(), sockets: [], rxBytes: 0, txBytes: 0, tcpInuse: 0, udpInuse: 0,
    capture: 'unavailable', available: false, platform, error: reason,
    trafficAvailable: false, trafficError: reason, captureDurationMs: 0 };
}

function createBackend({ scriptPath = path.join(__dirname, 'windows-firewall.ps1'),
  platform = process.platform, spawnProcess = spawn, timeout = 45000 } = {}) {
  let mutationTail = Promise.resolve();
  let rulesGeneration = 0;
  const reads = new Map();

  function run(operation, payload) {
    const data = validateRequest(operation, payload);
    if (platform !== 'win32') {
      const reason = 'Native Windows Firewall is only available in the Windows desktop application.';
      if (operation === 'status') return Promise.resolve({ platform, available: false, elevated: false, firewallEnabled: false, backend: 'none', reason });
      if (operation === 'snapshot') return Promise.resolve(unavailableSnapshot(reason, platform));
      if (operation === 'processes') return Promise.resolve({ at: Date.now(), available: false, processes: [], errors: [reason], truncated: false, captureDurationMs: 0 });
      if (operation === 'process-inspect') return Promise.resolve({ at: Date.now(), available: false, identity: data,
        children: [], modules: [], modulesTruncated: false, signature: { status: 'unknown' }, errors: [reason], captureDurationMs: 0 });
      return Promise.reject(new Error(reason));
    }
    return new Promise((resolve, reject) => {
      const powershell = path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
      const child = spawnProcess(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath], {
        windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'pipe'],
      });
      let stdout = '';
      let stderr = '';
      let settled = false;
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error); else resolve(result);
      };
      const timer = setTimeout(() => {
        // Settle before kill: a synchronous close callback must not replace the timeout.
        finish(new Error(operation === 'process-inspect' || operation === 'processes'
          ? 'Process observation timed out. Refresh the process inventory before retrying.'
          : 'Windows Firewall did not respond in time. Refresh rules before retrying a change.'));
        child.kill();
      }, operation === 'process-inspect' || operation === 'processes' ? Math.min(timeout, 30000) : timeout);
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (chunk) => {
        stdout += chunk;
        if (Buffer.byteLength(stdout) > 16 * 1024 * 1024) {
          child.kill();
          finish(new Error('Native response exceeded the size limit.'));
        }
      });
      child.stderr.on('data', (chunk) => { if (stderr.length < 16000) stderr += chunk; });
      child.on('error', (error) => finish(new Error(`Cannot start the Windows Firewall backend: ${error.message}`)));
      child.stdin.on('error', (error) => finish(new Error(`Cannot send the native request: ${error.message}`)));
      child.on('close', (code) => {
        if (settled) return;
        try {
          const response = JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
          if (!response || typeof response.ok !== 'boolean') throw new Error('Invalid native response.');
          if (!response.ok) return finish(new Error(typeof response.error === 'string' ? response.error : 'Windows Firewall rejected the operation.'));
          if (code !== 0) return finish(new Error('Windows Firewall exited unexpectedly. Refresh rules before retrying.'));
          finish(null, response.data);
        } catch (error) {
          finish(new Error(`Cannot read Windows Firewall response: ${error.message}${stderr ? ` (${stderr.slice(0, 500).trim()})` : ''}`));
        }
      });
      // Untrusted values are JSON on stdin, never command text or command-line switches.
      child.stdin.end(JSON.stringify({ operation, data }), 'utf8');
    });
  }

  function invoke(operation, payload) {
    // Reject invalid input before queuing work. Mutations are serialized.
    validateRequest(operation, payload);
    // Diagnostic-only capability used by the opt-in CLI. No renderer IPC handler exposes it.
    if (operation === 'inspect') return mutationTail.then(() => run(operation, payload));
    if (['apply', 'remove', 'enabled'].includes(operation)) {
      rulesGeneration += 1;
      const requestedProgram = operation === 'apply' ? payload.program : undefined;
      const next = mutationTail.then(() => run(operation, payload)).then((result) => operation === 'apply'
        // Bind canonical Windows output to this exact caller request, after native
        // readback verification. List results never invent this per-call attestation.
        ? { ...result, requestedProgram }
        : result);
      mutationTail = next.catch(() => {});
      return next;
    }
    // A rule read belongs to the mutation generation at invocation time. Post-change
    // verification must wait for queued writes and must never reuse a pre-change read.
    const key = operation === 'list' ? `${operation}:${rulesGeneration}`
      : operation === 'process-inspect' ? `${operation}:${payload.pid}:${payload.startedAt}` : operation;
    if (reads.has(key)) return reads.get(key);
    const beforeRead = operation === 'list' ? mutationTail : Promise.resolve();
    const promise = beforeRead.then(() => run(operation, payload)).finally(() => {
      if (reads.get(key) === promise) reads.delete(key);
    });
    reads.set(key, promise);
    return promise;
  }

  return { invoke };
}

module.exports = { createBackend };
