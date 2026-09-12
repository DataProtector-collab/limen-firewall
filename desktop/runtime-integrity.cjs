'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const FILES = ['Limen.Approval.Core.dll', 'Limen.Approval.Host.exe'];

function validateManifest(manifest) {
  if (!manifest || manifest.version !== '1.4.0' || !Array.isArray(manifest.files)
    || manifest.files.length !== FILES.length) throw new Error('Invalid native runtime manifest.');
  for (const filename of FILES) {
    const matches = manifest.files.filter(item => item?.name === filename);
    if (matches.length !== 1 || !/^[a-f0-9]{64}$/.test(matches[0].sha256)
      || !Number.isSafeInteger(matches[0].size) || matches[0].size <= 0 || matches[0].size > 32 * 1024 * 1024) {
      throw new Error('Invalid native runtime file identity.');
    }
  }
  return manifest;
}

async function verifyRuntime(directory, manifest) {
  validateManifest(manifest);
  const resolved = path.resolve(directory);
  // Resolve directory aliases before checking individual binaries; the manifest
  // in the integrity-protected ASAR pins the exact executable and DLL bytes.
  const realDirectory = await fs.realpath(resolved);
  for (const item of manifest.files) {
    const filename = path.join(realDirectory, item.name);
    const info = await fs.lstat(filename);
    if (!info.isFile() || info.isSymbolicLink() || info.size !== item.size) {
      throw new Error(`Native runtime verification failed: ${item.name}. Reinstall a verified Limen release.`);
    }
    const data = await fs.readFile(filename);
    const digest = crypto.createHash('sha256').update(data).digest('hex');
    if (digest !== item.sha256) throw new Error(`Native runtime digest mismatch: ${item.name}. Reinstall a verified Limen release.`);
  }
}

module.exports = { FILES, validateManifest, verifyRuntime };
