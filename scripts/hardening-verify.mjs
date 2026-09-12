import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { FuseV1Options, FuseVersion, getCurrentFuseWire } from '@electron/fuses';

// Use the PE and ASAR parsers belonging to the pinned packaging toolchain.
const builderRequire = createRequire(import.meta.resolve('app-builder-lib/package.json'));
const { NtExecutable, NtExecutableResource } = builderRequire('resedit');
const { readAsarHeader } = builderRequire('./out/asar/asar.js');

export const requiredFuses = Object.freeze({
  [FuseV1Options.RunAsNode]: false,
  [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
  [FuseV1Options.EnableNodeCliInspectArguments]: false,
  [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
  [FuseV1Options.OnlyLoadAppFromAsar]: true,
});

export function verifyFuseValues(wire) {
  if (wire.version !== FuseVersion.V1) throw new Error('Unexpected Electron fuse version.');
  for (const [option, enabled] of Object.entries(requiredFuses)) {
    // @electron/fuses returns ASCII byte values: 0x30 disabled, 0x31 enabled.
    if (wire[option] !== (enabled ? 0x31 : 0x30)) {
      throw new Error(`Required Electron fuse is incorrect: ${FuseV1Options[Number(option)]}`);
    }
  }
}

export function verifyIntegrityRecord(records, header) {
  if (!Array.isArray(records)) throw new Error('Invalid embedded ASAR integrity records.');
  const appRecords = records.filter(record => record.file?.replaceAll('/', '\\').toLowerCase() === 'resources\\app.asar');
  const hash = createHash('sha256').update(header).digest('hex');
  if (appRecords.length !== 1 || appRecords[0].alg?.toLowerCase() !== 'sha256' || appRecords[0].value !== hash) {
    throw new Error('The executable does not authenticate the packaged app.asar header.');
  }
  const files = JSON.parse(header).files;
  for (const parts of [['desktop', 'main.cjs'], ['desktop', 'preload.cjs'], ['desktop', 'lifecycle.cjs'], ['desktop', 'native-runtime.json'], ['dist', 'index.html']]) {
    let entry = { files };
    for (const part of parts) entry = entry?.files?.[part];
    if (!entry || entry.unpacked || entry.integrity?.algorithm !== 'SHA256' || !/^[a-f0-9]{64}$/.test(entry.integrity.hash)) {
      throw new Error(`Packaged code is missing ASAR integrity: ${parts.join('/')}`);
    }
  }
  return hash;
}

export async function verifyPackagedHardening(executablePath, { fuses = true } = {}) {
  const executable = NtExecutable.from(await readFile(executablePath), { ignoreCert: true });
  const resources = NtExecutableResource.from(executable);
  const entries = resources.entries.filter(entry => entry.type === 'INTEGRITY' && entry.id === 'ELECTRONASAR');
  if (entries.length !== 1) throw new Error('Missing or ambiguous executable ASAR integrity resource.');
  const archive = path.join(path.dirname(executablePath), 'resources', 'app.asar');
  const { header } = await readAsarHeader(archive);
  const headerSha256 = verifyIntegrityRecord(JSON.parse(Buffer.from(entries[0].bin).toString('utf8')), header);
  if (fuses) verifyFuseValues(await getCurrentFuseWire(executablePath));
  return { executable: path.basename(executablePath), asarHeaderSha256: headerSha256, fusesVerified: fuses };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  if (process.argv.length !== 3) throw new Error('Usage: node scripts/hardening-verify.mjs <packaged Limen.exe>');
  console.log(JSON.stringify(await verifyPackagedHardening(path.resolve(process.argv[2]))));
}
