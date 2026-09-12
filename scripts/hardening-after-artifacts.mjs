import path from 'node:path';
import { verifyPackagedHardening } from './hardening-verify.mjs';

export default async function afterAllArtifactBuild(context) {
  const windows = [...context.platformToTargets.keys()].some(platform => platform.nodeName === 'win32');
  if (!windows) return [];
  // This project deliberately supports Windows x64 and a fixed product name.
  const result = await verifyPackagedHardening(path.join(context.outDir, 'win-unpacked', 'Limen.exe'));
  console.log(`  • verified Windows package hardening: ${result.asarHeaderSha256}`);
  return [];
}
