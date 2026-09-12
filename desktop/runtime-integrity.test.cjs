'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { FILES, validateManifest, verifyRuntime } = require('./runtime-integrity.cjs');

test('native runtime refuses substituted binaries and manifest path traversal', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'limen-runtime-integrity-'));
  try {
    const manifest = { version: '1.4.0', files: FILES.map(name => ({ name, size: 4,
      sha256: crypto.createHash('sha256').update('good').digest('hex') })) };
    for (const filename of FILES) await fs.writeFile(path.join(directory, filename), 'good');
    await verifyRuntime(directory, manifest);
    await fs.writeFile(path.join(directory, FILES[0]), 'evil');
    await assert.rejects(verifyRuntime(directory, manifest), /digest mismatch/);
    assert.throws(() => validateManifest({ ...manifest, files: [manifest.files[0], { ...manifest.files[1], name: '../payload.exe' }] }), /identity/);
    assert.throws(() => validateManifest({ ...manifest, files: [manifest.files[0], manifest.files[0]] }), /identity/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});
