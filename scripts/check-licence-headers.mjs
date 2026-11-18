// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Verify the licence hygiene of the RailGun package.
 *
 * Three things are checked:
 *   1. every source file under `src/`, `test/`, `tests/` and `scripts/`
 *      carries an SPDX `GPL-3.0-or-later` header;
 *   2. `LICENSE` contains the GNU General Public License version 3 text;
 *   3. `package.json` declares `license: "GPL-3.0-or-later"`.
 *
 * The check is a plain Node script with no dependencies, so a standalone user
 * can run it after `npm install` without a workspace root.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SPDX = "SPDX-License-Identifier: GPL-3.0-or-later";

/** Directories whose files must carry the SPDX header. */
const SCANNED_DIRS = ["src", "test", "tests", "scripts"];

/** Extensions that carry the header as a `//` or `#` comment. */
const COMMENTED_EXTENSIONS = new Set([".ts", ".mts", ".cts", ".js", ".mjs", ".cjs", ".yaml", ".yml", ".sh"]);

function walk(directory) {
  const found = [];
  let entries;
  try {
    entries = readdirSync(directory);
  } catch {
    return found;
  }
  for (const entry of entries) {
    const full = path.join(directory, entry);
    const stats = statSync(full);
    if (stats.isDirectory()) {
      found.push(...walk(full));
    } else if (stats.isFile()) {
      found.push(full);
    }
  }
  return found;
}

const failures = [];

// --- 1. SPDX headers --------------------------------------------------------
for (const directory of SCANNED_DIRS) {
  const absolute = path.join(packageRoot, directory);
  for (const file of walk(absolute)) {
    const extension = path.extname(file);
    if (!COMMENTED_EXTENSIONS.has(extension)) continue;
    const head = readFileSync(file, "utf8").slice(0, 400);
    if (!head.includes(SPDX)) {
      failures.push(`${path.relative(packageRoot, file)}: missing "${SPDX}" header`);
    }
  }
}

// --- 2. LICENSE --------------------------------------------------------------
try {
  const license = readFileSync(path.join(packageRoot, "LICENSE"), "utf8");
  if (!license.includes("GNU GENERAL PUBLIC LICENSE") || !license.includes("Version 3")) {
    failures.push("LICENSE: does not contain the GNU General Public License version 3 text");
  }
} catch {
  failures.push("LICENSE: file is missing");
}

// --- 3. package.json licence -------------------------------------------------
try {
  const manifest = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  if (manifest.license !== "GPL-3.0-or-later") {
    failures.push(`package.json: license is "${manifest.license}", expected "GPL-3.0-or-later"`);
  }
} catch {
  failures.push("package.json: file is missing or not valid JSON");
}

if (failures.length > 0) {
  console.error("Licence check failed:");
  for (const failure of failures) {
    console.error(`  - ${failure}`);
  }
  process.exit(1);
}

console.log("Licence check passed: SPDX headers, LICENSE and package.json licence are all GPL-3.0-or-later.");
