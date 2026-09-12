import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { FuseVersion } from '@electron/fuses';
import { requiredFuses, verifyFuseValues, verifyIntegrityRecord } from './hardening-verify.mjs';

test('package verification rejects absent or reverted security fuses', () => {
  const correct = { version: FuseVersion.V1 };
  for (const [key, value] of Object.entries(requiredFuses)) correct[key] = value ? 0x31 : 0x30;
  assert.doesNotThrow(() => verifyFuseValues(correct));
  for (const key of Object.keys(requiredFuses)) {
    assert.throws(() => verifyFuseValues({ ...correct, [key]: correct[key] === 0x31 ? 0x30 : 0x31 }));
    assert.throws(() => verifyFuseValues({ ...correct, [key]: undefined }));
  }
});

test('package verification rejects substituted archives and unpacked privileged code', () => {
  const entry = { integrity: { algorithm: 'SHA256', hash: 'a'.repeat(64) } };
  const header = JSON.stringify({ files: {
    desktop: { files: { 'main.cjs': entry, 'preload.cjs': entry, 'lifecycle.cjs': entry, 'native-runtime.json': entry } },
    dist: { files: { 'index.html': entry } },
  } });
  const recordFor = value => [{ file: 'resources\\app.asar', alg: 'SHA256', value: createHash('sha256').update(value).digest('hex') }];
  const records = recordFor(header);
  assert.equal(verifyIntegrityRecord(records, header), records[0].value);
  assert.throws(() => verifyIntegrityRecord(records, header + ' '));
  assert.throws(() => verifyIntegrityRecord([...records, ...records], header));
  assert.throws(() => verifyIntegrityRecord([], header));
  const unpacked = header.replace('"main.cjs":{', '"main.cjs":{"unpacked":true,');
  assert.throws(() => verifyIntegrityRecord(recordFor(unpacked), unpacked));
});
