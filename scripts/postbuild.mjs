// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Post-build step: make the compiled entry points executable.
 *
 * `tsc` does not emit a shebang, so a compiled entry point would fail with
 * "SyntaxError: Unexpected token '#'" when invoked through the `railgun` bin
 * symlink. This script prepends the shebang and sets the executable bit on
 * every declared binary entry point.
 *
 * It runs with plain Node (no dependencies) so that `npm run build` stays
 * hermetic and works in a standalone checkout.
 */
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHEBANG = "#!/usr/bin/env node";

/** The entry points declared in the package manifest's `bin` field. */
function declaredBinaries() {
  const manifest = JSON.parse(
    readFileSync(path.join(packageRoot, "package.json"), "utf8"),
  );
  const bin = manifest.bin;
  if (!bin || typeof bin !== "object") return [];
  return Object.values(bin)
    .filter((value) => typeof value === "string")
    .map((value) => value.replace(/^\.\//, ""));
}

/** The entry points to make executable: the declared binaries plus `bin.js`. */
const entryPoints = new Set([
  ...declaredBinaries(),
  "dist/bin.js",
  "dist/health-main.js",
]);

let failures = 0;
for (const relative of entryPoints) {
  const target = path.join(packageRoot, relative);
  if (!existsSync(target)) {
    console.error(`postbuild: expected ${relative} to exist after tsc.`);
    failures += 1;
    continue;
  }
  const source = readFileSync(target, "utf8");
  if (!source.startsWith("#!")) {
    writeFileSync(target, `${SHEBANG}\n${source}`, "utf8");
  }
  chmodSync(target, 0o755);
}

if (failures > 0) {
  process.exit(1);
}
