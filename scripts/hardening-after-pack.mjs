import path from 'node:path';
import { verifyPackagedHardening } from './hardening-verify.mjs';

export default async function afterPack(context) {
  if (context.electronPlatformName !== 'win32') return;
  // electron-builder flips the configured fuses after this hook, immediately
  // before signing. Its embedded header must already match the finished ASAR.
  await verifyPackagedHardening(path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.exe`), { fuses: false });
}
