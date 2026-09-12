'use strict';

// Explicit, isolated integration test. Never imported by the desktop app or ordinary unit tests.
// Only the randomly named temporary probe receives WFP filters and an exact owned Windows rule.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { realpathSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const dns = require('node:dns');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { createApprovalBackend } = require('./approval-backend.cjs');
const { createBackend } = require('./backend.cjs');
const { verifyRuntime } = require('./runtime-integrity.cjs');
const manifest = require('./native-runtime.json');

async function run() {
  const args = process.argv.slice(2);
  if (!args.includes('--confirm-isolated-approval-test')) throw new Error('Explicit --confirm-isolated-approval-test is required.');
  if (process.platform !== 'win32') throw new Error('This test requires an administrator terminal on Windows.');
  const option = (key) => { const index = args.indexOf(key); return index >= 0 ? args[index + 1] : undefined; };
  const reportPath = option('--report');
  if (!reportPath || !path.isAbsolute(reportPath) || path.extname(reportPath) !== '.json') throw new Error('--report requires an absolute .json path.');
  const runtime = option('--runtime-directory') || path.resolve(__dirname, '../native/runtime');
  if (!path.isAbsolute(runtime)) throw new Error('--runtime-directory requires an absolute path.');
  const report = { startedAt: new Date().toISOString(), passed: false, testKind: 'isolated-approval-enforcement',
    ruleScope: 'Dedicated temporary executable only; no global profiles or unrelated rules', checks: [],
    ipv6: 'IPv6 filters are installed and read back. Packet checks use IPv4 and do not validate IPv6 routing.',
    cleanup: { ruleRemoved: true, hostExited: true, directoryRemoved: false } };
  const save = async () => { await fs.mkdir(path.dirname(reportPath), { recursive: true }); await fs.writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`); };
  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const firewall = createBackend();
  // WFP preserves DOS aliases in an application ID, while connection events use
  // the executable's long path. Resolve both the probe and cleanup root natively.
  const temporaryRoot = realpathSync.native(os.tmpdir());
  let directory, program, approval, nativeHost, ruleId, interrupted = false;
  const helpers = new Set();
  const interrupt = () => { interrupted = true; approval?.close(); for (const helper of helpers) helper.kill(); };
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);

  function execute(filename, arguments_) {
    if (interrupted) throw new Error('Test interrupted.');
    return new Promise((resolve, reject) => {
      const child = spawn(filename, arguments_, { windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
      helpers.add(child);
      let stdout = '', stderr = '', timedOut = false;
      const timer = setTimeout(() => { timedOut = true; child.kill(); }, 15000);
      child.stdout.on('data', (chunk) => { if (stdout.length < 65536) stdout += chunk; });
      child.stderr.on('data', (chunk) => { if (stderr.length < 16000) stderr += chunk; });
      child.on('error', (error) => { clearTimeout(timer); helpers.delete(child); reject(error); });
      child.on('close', (code) => {
        clearTimeout(timer); helpers.delete(child);
        if (code || timedOut) reject(new Error(`Test helper failed: ${timedOut ? 'timeout' : code}; ${stderr.slice(0, 1000)}`));
        else resolve(stdout);
      });
    });
  }
  async function packet(protocol, address, port, success, label) {
    const result = JSON.parse(await execute(program, [protocol, address, String(port)]));
    report.checks.push({ label, ...result }); await save();
    assert.equal(result.success, success, `${label}: ${JSON.stringify(result)}`);
  }
  async function pending(protocol, address, port) {
    for (let i = 0; i < 25; i += 1) {
      const state = await approval.invoke('status');
      const found = state.attempts.find((a) => a.protocol === protocol && a.remoteAddress === address && a.remotePort === port && a.decision === 'pending');
      if (found) {
        assert.equal(found.program.toLowerCase(), program.toLowerCase()); assert.equal(found.canApprove, true);
        report.checks.push({ label: `Actual WFP ${protocol} blocked attempt`, attempt: found }); return found;
      }
      await delay(200);
    }
    throw new Error(`No owned WFP pending event for ${protocol} ${address}:${port}`);
  }
  try {
    await save(); await verifyRuntime(runtime, manifest);
    const capability = await firewall.invoke('status');
    if (!capability.available || !capability.elevated || !capability.firewallEnabled) throw new Error('Administrator rights and enabled Windows Firewall are required. The test changes no profiles.');
    const tcpAddress = option('--tcp-address') || (await dns.promises.lookup('github.com', { family: 4 })).address;
    const dnsAddress = option('--dns-address') || dns.getServers().find((server) => net.isIP(server) === 4 && !server.startsWith('127.'));
    if (net.isIP(tcpAddress) !== 4 || !dnsAddress || net.isIP(dnsAddress) !== 4 || tcpAddress.startsWith('127.') || dnsAddress.startsWith('127.'))
      throw new Error('A non-loopback IPv4 TCP endpoint and DNS server are required; use --tcp-address and --dns-address if necessary.');
    directory = realpathSync.native(await fs.mkdtemp(path.join(temporaryRoot, 'Limen-approval-selftest-')));
    program = path.join(directory, `LimenApprovalProbe-${crypto.randomUUID()}.exe`);
    report.program = program;
    const compiler = path.join(process.env.SystemRoot || 'C:\\Windows', 'Microsoft.NET/Framework64/v4.0.30319/csc.exe');
    await execute(compiler, ['/nologo', '/optimize+', '/target:exe', '/reference:System.Web.Extensions.dll', `/out:${program}`,
      path.join(__dirname, 'native-tests/approval-probe.cs')]);
    program = realpathSync.native(program);
    report.program = program;
    approval = createApprovalBackend({ hostPath: path.join(runtime, 'Limen.Approval.Host.exe'), verifyRuntime: () => verifyRuntime(runtime, manifest),
      spawnProcess: (...spawnArgs) => { nativeHost = spawn(...spawnArgs); report.cleanup.hostExited = false; return nativeHost; } });
    await packet('TCP', tcpAddress, 443, true, 'Baseline TCP');
    await packet('UDP', dnsAddress, 53, true, 'Baseline UDP DNS');
    assert.equal((await approval.startScopedTest(program)).scope, 'test-program');
    await packet('TCP', tcpAddress, 443, false, 'Unknown TCP blocked before decision');
    const tcp = await pending('TCP', tcpAddress, 443);
    await approval.invoke('decide', { id: tcp.id, decision: 'deny' });
    await packet('TCP', tcpAddress, 443, false, 'Denied TCP stays blocked');
    await packet('UDP', dnsAddress, 53, false, 'Unknown UDP blocked before decision');
    const udp = await pending('UDP', dnsAddress, 53);
    await approval.invoke('decide', { id: udp.id, decision: 'allow-endpoint' });
    await packet('UDP', dnsAddress, 53, true, 'Approved UDP endpoint succeeds on retry');
    await packet('TCP', tcpAddress, 443, false, 'UDP endpoint permission does not allow TCP');
    await approval.invoke('stop');
    await packet('TCP', tcpAddress, 443, true, 'Stop restores previous TCP connectivity');
    await approval.startScopedTest(program);
    await packet('TCP', tcpAddress, 443, false, 'New session has no remembered permissions');
    const second = await pending('TCP', tcpAddress, 443);
    await approval.invoke('decide', { id: second.id, decision: 'allow-program' });
    await packet('TCP', tcpAddress, 443, true, 'Program permission allows TCP retry');
    await packet('UDP', dnsAddress, 53, true, 'Program permission allows UDP retry');
    const rule = await firewall.invoke('apply', { program, action: 'block', direction: 'out', protocol: 'TCP', remoteAddress: tcpAddress, remotePort: 443 });
    ruleId = rule.id; report.ruleId = ruleId; report.cleanup.ruleRemoved = false; await save();
    await packet('TCP', tcpAddress, 443, false, 'Windows explicit block wins over Limen WFP permit');
    await firewall.invoke('remove', ruleId); ruleId = undefined; report.cleanup.ruleRemoved = true;
    await packet('TCP', tcpAddress, 443, true, 'Removing only test rule restores permitted TCP');
    await approval.invoke('stop');
    await approval.startScopedTest(program);
    await packet('TCP', tcpAddress, 443, false, 'Blocking before native host death');
    const exited = new Promise((resolve) => nativeHost.once('close', resolve)); nativeHost.kill(); await exited; await delay(500);
    await packet('TCP', tcpAddress, 443, true, 'Host termination removes dynamic blocking filters');
    await packet('UDP', dnsAddress, 53, true, 'Host termination restores UDP');
    const recovered = await approval.invoke('status'); assert.equal(recovered.active, false); assert.equal(recovered.available, true); assert.match(recovered.reason, /host exited/);
    report.passed = true;
  } catch (error) { report.error = error.message; }
  finally {
    if (ruleId) {
      try { await firewall.invoke('remove', ruleId); report.cleanup.ruleRemoved = true; }
      catch (error) { report.cleanup.ruleError = error.message; report.passed = false; }
    }
    if (program) {
      // A write can succeed in Windows before its reply is lost. Recover only
      // Limen IDs that Windows reports for this run's random temporary executable.
      try {
        const remaining = (await firewall.invoke('list')).filter((rule) => rule.program?.toLowerCase() === program.toLowerCase());
        for (const rule of remaining) await firewall.invoke('remove', rule.id);
        report.cleanup.recoveredRuleCount = remaining.length;
        report.cleanup.ruleRemoved = true;
      } catch (error) { report.cleanup.ruleError = error.message; report.cleanup.ruleRemoved = false; report.passed = false; }
    }
    if (nativeHost && nativeHost.exitCode === null && nativeHost.signalCode === null) {
      const ended = new Promise((resolve) => nativeHost.once('close', () => resolve(true)));
      approval?.close();
      report.cleanup.hostExited = await Promise.race([ended, delay(5000).then(() => false)]);
    } else { approval?.close(); report.cleanup.hostExited = true; }
    if (!report.cleanup.hostExited) report.passed = false;
    if (directory) {
      const resolved = path.resolve(directory), relative = path.relative(temporaryRoot, resolved);
      if (relative && !relative.startsWith('..') && !path.isAbsolute(relative) && path.basename(resolved).startsWith('Limen-approval-selftest-')) {
        try { await fs.rm(resolved, { recursive: true, force: true }); report.cleanup.directoryRemoved = true; }
        catch (error) { report.cleanup.directoryError = error.message; report.passed = false; }
      } else { report.cleanup.directoryError = 'Temporary directory containment check failed.'; report.passed = false; }
    } else report.cleanup.directoryRemoved = true;
    report.completedAt = new Date().toISOString(); await save();
    process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt);
    process.stdout.write(`${JSON.stringify({ passed: report.passed, checks: report.checks.length, cleanup: report.cleanup, error: report.error })}\n`);
    process.exitCode = report.passed ? 0 : 1;
  }
}
run().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
