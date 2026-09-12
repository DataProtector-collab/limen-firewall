import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { spawn } from "node:child_process";

async function testsIn(dir) {
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  const nested = await Promise.all(entries.map(entry => entry.isDirectory()
    ? testsIn(join(dir, entry.name))
    : /\.test\.(mjs|cjs|ts)$/.test(entry.name) ? [join(dir, entry.name)] : []));
  return nested.flat();
}
const files = (await Promise.all(["scripts", "src/lib", "desktop"].map(testsIn))).flat().sort();
const child = spawn(process.execPath, ["--import", "tsx", "--test", ...files], { stdio: "inherit", shell: false });
child.once("error", error => { console.error(error); process.exitCode = 1; });
child.once("exit", code => { process.exitCode = code ?? 1; });
