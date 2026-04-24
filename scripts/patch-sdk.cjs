/**
 * Adapts the git-submodule SDK packages for local dev:
 *  - workspace:* → file: (npm can't resolve pnpm workspace protocol)
 *  - exports point at src/ so vitest/tsx can import TypeScript directly
 *
 * This is only needed while the SDK repo uses pnpm workspaces internally.
 * Once the SDK publishes to npm, this script can be removed.
 */
const fs = require("fs");
const path = require("path");

const SDK = path.join(__dirname, "..", "vendor", "ath-sdk", "packages");

function patch(dir) {
  const file = path.join(SDK, dir, "package.json");
  if (!fs.existsSync(file)) return;
  const pkg = JSON.parse(fs.readFileSync(file, "utf8"));

  if (pkg.dependencies?.["@ath-protocol/types"]?.startsWith("workspace:")) {
    pkg.dependencies["@ath-protocol/types"] = "file:../types";
  }
  pkg.main = "./src/index.ts";
  pkg.types = "./src/index.ts";
  pkg.exports = { ".": { types: "./src/index.ts", import: "./src/index.ts", default: "./src/index.ts" } };

  fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");
}

patch("types");
patch("server");
patch("client");
