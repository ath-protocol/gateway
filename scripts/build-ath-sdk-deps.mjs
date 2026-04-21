import { mkdtempSync, rmSync, cpSync, realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const run = (command, args, cwd) => {
  const result = spawnSync(command, args, { stdio: "inherit", cwd });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
};

const cloneAndBuildSdk = (tmpRoot) => {
  const sdkDir = path.join(tmpRoot, "typescript-sdk");
  run("git", ["clone", "--depth", "1", "https://github.com/ath-protocol/typescript-sdk.git", sdkDir], process.cwd());
  run("pnpm", ["install"], sdkDir);
  run("pnpm", ["--filter", "@ath-protocol/types", "build"], sdkDir);
  run("pnpm", ["--filter", "@ath-protocol/server", "build"], sdkDir);
  return sdkDir;
};

const copyBuiltDist = (sdkDir) => {
  const installedTypesDir = realpathSync(path.join(process.cwd(), "node_modules/@ath-protocol/types"));
  const installedServerDir = realpathSync(path.join(process.cwd(), "node_modules/@ath-protocol/server"));
  cpSync(path.join(sdkDir, "packages/types/dist"), path.join(installedTypesDir, "dist"), { recursive: true });
  cpSync(path.join(sdkDir, "packages/server/dist"), path.join(installedServerDir, "dist"), { recursive: true });
};

const tmpRoot = mkdtempSync(path.join(os.tmpdir(), "ath-sdk-build-"));
try {
  const sdkDir = cloneAndBuildSdk(tmpRoot);
  copyBuiltDist(sdkDir);
} finally {
  rmSync(tmpRoot, { recursive: true, force: true });
}
