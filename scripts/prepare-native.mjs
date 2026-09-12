import { mkdir, readFile, writeFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const { validateManifest, verifyRuntime } = require('../desktop/runtime-integrity.cjs');
const manifest = validateManifest(JSON.parse(await readFile(path.join(root, 'desktop/native-runtime.json'), 'utf8')));
const destination = path.join(root, 'native/runtime');
try {
  await verifyRuntime(destination, manifest);
  console.log('Native runtime matches the pinned release.');
} catch {
  await mkdir(destination, { recursive: true });
  for (const file of manifest.files) {
    // Fixed project/release and exact filenames from the validated public manifest.
    const url = `https://github.com/DataProtector-collab/limen-firewall/releases/download/native-v${manifest.version}/${file.name}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(60000) });
    if (!response.ok) throw new Error(`Cannot fetch the native runtime (${response.status}). Supply the verified native/runtime files from the release.`);
    const chunks = [];
    let length = 0;
    for await (const chunk of response.body) {
      length += chunk.length;
      if (length > file.size) throw new Error('Native download exceeded the pinned size.');
      chunks.push(chunk);
    }
    const bytes = Buffer.concat(chunks);
    if (length !== file.size || createHash('sha256').update(bytes).digest('hex') !== file.sha256) throw new Error('Native download integrity verification failed.');
    const temporary = path.join(destination, `${file.name}.${randomUUID()}.tmp`);
    try {
      await writeFile(temporary, bytes, { flag: 'wx' });
      await rename(temporary, path.join(destination, file.name));
    } finally { await rm(temporary, { force: true }); }
  }
  await verifyRuntime(destination, manifest);
  console.log('Verified native runtime downloaded. Its source is not part of the MIT interface repository.');
}
