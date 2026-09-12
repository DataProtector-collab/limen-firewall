'use strict';

// Explicit opt-in administrator integration test. Never imported by the application.
// Example: node desktop/firewall-selftest.cjs --confirm-isolated-firewall-test --report C:\\Temp\\limen-test.json --backend-script C:\\Limen\\resources\\windows-firewall.ps1
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { createBackend } = require('./backend.cjs');

async function run() {
  const args = process.argv.slice(2);
  if (!args.includes('--confirm-isolated-firewall-test')) throw new Error('Explicit --confirm-isolated-firewall-test is required.');
  const lifecycleOnly = args.includes('--lifecycle-only');
  const option = (name) => { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : undefined; };
  const reportPath = option('--report');
  const scriptPath = option('--backend-script');
  if (!reportPath || !path.isAbsolute(reportPath) || path.extname(reportPath) !== '.json') throw new Error('--report requires an absolute .json path.');
  if (scriptPath && !path.isAbsolute(scriptPath)) throw new Error('--backend-script requires an absolute path.');
  const report = { startedAt: new Date().toISOString(), backendScript: scriptPath || path.join(__dirname, 'windows-firewall.ps1'),
    testKind: lifecycleOnly ? 'rule-lifecycle' : 'packet-enforcement', endpoint: 'https://github.com/',
    ruleScope: 'Dedicated temporary program, outbound TCP', enforcementTested: false,
    passed: false, stages: {}, cleanup: { ruleRemoved: false, directoryRemoved: false } };
  const save = async () => { await fs.mkdir(path.dirname(reportPath), { recursive: true }); await fs.writeFile(reportPath, JSON.stringify(report, null, 2) + '\n'); };
  const backend = createBackend(scriptPath ? { scriptPath } : {});
  let directory;
  let ruleId;
  let probe;
  let interrupted = false;
  const interrupt = () => { interrupted = true; if (probe) probe.kill(); };
  process.on('SIGINT', interrupt);
  process.on('SIGTERM', interrupt);
  async function connect(program) {
    if (interrupted) throw new Error('Test interrupted.');
    return new Promise((resolve, reject) => {
      const started = Date.now();
      // --disable must be first: ignore local curl configuration while honoring the
      // ordinary HTTPS proxy environment. The rule follows only this unique executable.
      probe = spawn(program, ['--disable', '--silent', '--show-error', '--http1.1',
        '--connect-timeout', '8', '--max-time', '12', '--output', 'NUL', 'https://github.com/'],
      { windowsHide: true, shell: false, stdio: ['ignore', 'ignore', 'pipe'] });
      let stderr = '';
      const timer = setTimeout(() => probe?.kill(), 16000);
      probe.stderr.on('data', (chunk) => { stderr += chunk.toString().slice(0, 1000); });
      probe.on('error', (error) => { clearTimeout(timer); probe = undefined; reject(error); });
      probe.on('close', (code) => {
        clearTimeout(timer); probe = undefined;
        // Do not persist proxy credentials if a network error happens to include a URL.
        const error = stderr.replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, '$1[redacted]@').trim() || undefined;
        resolve({ success: code === 0, exitCode: code, elapsedMs: Date.now() - started, error });
      });
    });
  }
  try {
    await save();
    const status = await backend.invoke('status');
    report.status = status;
    if (!status.available || !status.elevated || !status.firewallEnabled) throw new Error('Test requires administrator privileges and enabled Windows Firewall profiles. No profile settings are changed.');
    directory = await fs.mkdtemp(path.join(os.tmpdir(), 'Limen-firewall-selftest-'));
    const program = path.join(directory, 'limen-isolated-network-probe.exe');
    await fs.copyFile(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'curl.exe'), program);
    report.program = program;
    if (!lifecycleOnly) {
      report.stages.baseline = await connect(program);
      if (!report.stages.baseline.success) throw new Error('Baseline connection failed; no firewall change was made. Use --lifecycle-only to test Windows rule operations without claiming packet enforcement.');
    }
    const rule = await backend.invoke('apply', { program, action: 'block', direction: 'out', protocol: 'TCP' });
    ruleId = rule.id;
    report.ruleId = ruleId;
    const listed = (await backend.invoke('list')).find((candidate) => candidate.id === ruleId);
    report.stages.persisted = Boolean(listed?.enabled && listed.action === 'block');
    report.ruleDiagnostics = await backend.invoke('inspect', ruleId);
    const actualRuntime = report.ruleDiagnostics.active;
    report.stages.activeStatusReported = rule.primaryStatus === actualRuntime.primaryStatus
      && listed?.primaryStatus === actualRuntime.primaryStatus
      && JSON.stringify(rule.enforcementStatus) === JSON.stringify(actualRuntime.enforcementStatus)
      && JSON.stringify(listed?.enforcementStatus) === JSON.stringify(actualRuntime.enforcementStatus);
    if (!report.stages.activeStatusReported) throw new Error('The native API did not report the actual ActiveStore rule status.');
    await save();
    if (!lifecycleOnly) {
      report.enforcementTested = true;
      report.stages.blocked = await connect(program);
      if (report.stages.blocked.success) throw new Error('The scoped block rule did not block a fresh connection.');
    }
    const disabled = await backend.invoke('enabled', { id: ruleId, enabled: false });
    report.stages.disabled = disabled.enabled === false;
    if (!lifecycleOnly) {
      report.stages.restored = await connect(program);
      if (!report.stages.restored.success) throw new Error('Connection was not restored after disabling the test rule.');
    }
    const enabled = await backend.invoke('enabled', { id: ruleId, enabled: true });
    report.stages.reenabled = enabled.enabled === true;
    if (!lifecycleOnly) {
      report.stages.blockedAgain = await connect(program);
      if (report.stages.blockedAgain.success) throw new Error('Re-enabling the test rule did not block a fresh connection.');
    }
    await backend.invoke('remove', ruleId);
    report.cleanup.ruleRemoved = true;
    ruleId = undefined;
    if (!lifecycleOnly) {
      report.stages.restoredAfterRemoval = await connect(program);
      if (!report.stages.restoredAfterRemoval.success) throw new Error('Connection was not restored after removing the test rule.');
    }
    report.passed = report.stages.persisted && report.stages.activeStatusReported && report.stages.disabled && report.stages.reenabled;
  } catch (error) {
    report.error = error.message;
  } finally {
    if (ruleId) {
      try { await backend.invoke('remove', ruleId); report.cleanup.ruleRemoved = true; }
      catch (error) { report.cleanup.error = `Rule ${ruleId}: ${error.message}`; report.passed = false; }
    } else if (!report.ruleId) { report.cleanup.ruleRemoved = true; }
    if (directory) {
      // Resolve and check the exact temporary directory before recursive deletion.
      const resolved = path.resolve(directory);
      const relative = path.relative(path.resolve(os.tmpdir()), resolved);
      if (relative && !relative.startsWith('..') && !path.isAbsolute(relative) && path.basename(resolved).startsWith('Limen-firewall-selftest-')) {
        try { await fs.rm(resolved, { recursive: true, force: true }); report.cleanup.directoryRemoved = true; }
        catch (error) { report.cleanup.directoryError = error.message; report.passed = false; }
      } else { report.cleanup.directoryError = 'Temporary directory containment check failed.'; report.passed = false; }
    } else { report.cleanup.directoryRemoved = true; }
    report.completedAt = new Date().toISOString();
    await save();
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', interrupt);
    process.stdout.write(JSON.stringify(report) + '\n');
    process.exitCode = report.passed ? 0 : 1;
  }
}

run().catch((error) => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
