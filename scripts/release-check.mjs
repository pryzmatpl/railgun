#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The single release-check command.
 *
 * Usage:
 *
 *   node scripts/release-check.mjs            # every release check
 *   node scripts/release-check.mjs --only standalone-install
 *   node scripts/release-check.mjs --skip docker
 *
 * Each check is independently runnable and exits non-zero on failure. The
 * live-delivery check is never part of this command: T5 can only be started
 * explicitly by an operator.
 *
 * Contract: `docs/design/481de2b7-e002-4cdc-95e0-0adc9068e2c4.md` §5.4.
 */

import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Parse the command-line arguments. */
const args = process.argv.slice(2);
const only = args.includes("--only") ? args[args.indexOf("--only") + 1] : undefined;
const skip = new Set(
  args.includes("--skip") ? args[args.indexOf("--skip") + 1].split(",").map((entry) => entry.trim()) : [],
);

/** Run a command and return its exit code. */
function run(command, options = {}) {
  const result = spawnSync(command[0], command.slice(1), {
    stdio: "inherit",
    cwd: options.cwd ?? packageRoot,
    env: { ...process.env, ...options.env },
  });
  return result.status ?? 1;
}

/**
 * The environment for a nested npm invocation.
 *
 * A CI image may set `NODE_ENV=production` or `npm_config_omit=dev`, which
 * would skip the development dependencies the build needs. The nested install
 * therefore always asks for the development dependencies explicitly.
 *
 * The cache lives inside the throwaway work directory: a shared, root-owned
 * cache in the host image makes the nested install fail with a permission
 * error that has nothing to do with the package.
 */
function nestedNpmEnv(workDir) {
  return {
    ...process.env,
    NODE_ENV: "development",
    npm_config_omit: "",
    npm_config_production: "",
    npm_config_cache: path.join(workDir, "npm-cache"),
  };
}

/** Copy the package into a clean directory outside the monorepo. */
function stageStandaloneCopy(destination) {
  const ignored = new Set(["node_modules", ".git", "dist", "data", "coverage"]);
  const copy = (from, to) => {
    cpSync(from, to, {
      recursive: true,
      filter: (source) => {
        const relative = path.relative(packageRoot, source);
        if (relative === "") return true;
        const first = relative.split(path.sep)[0];
        return !ignored.has(first) && !first.startsWith(".railgun-probe");
      },
    });
  };
  copy(packageRoot, destination);
  return destination;
}

/** The standalone install + build check. */
function standaloneInstall() {
  const workDir = mkdtempSync(path.join(tmpdir(), "railgun-standalone-"));
  try {
    stageStandaloneCopy(path.join(workDir, "railgun"));
    const code = run(["npm", "install", "--include=dev", "--no-audit", "--no-fund"], {
      cwd: path.join(workDir, "railgun"),
      env: nestedNpmEnv(workDir),
    });
    if (code !== 0) return code;
    return run(["npm", "run", "--silent", "build"], { cwd: path.join(workDir, "railgun") });
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

/** The npm pack + self-install check. */
function npmPack() {
  const workDir = mkdtempSync(path.join(tmpdir(), "railgun-pack-"));
  try {
    const packageDir = path.join(workDir, "railgun");
    stageStandaloneCopy(packageDir);
    // The `prepack` hook builds the package, so the staged copy needs the
    // development dependencies before `npm pack` runs.
    const deps = spawnSync("npm", ["install", "--include=dev", "--no-audit", "--no-fund"], {
      cwd: packageDir,
      encoding: "utf8",
      env: nestedNpmEnv(workDir),
    });
    if (deps.status !== 0) {
      process.stderr.write(deps.stderr ?? "");
      return deps.status ?? 1;
    }
    const pack = spawnSync("npm", ["pack", "--json"], {
      cwd: packageDir,
      encoding: "utf8",
      env: nestedNpmEnv(workDir),
    });
    if (pack.status !== 0) {
      process.stderr.write(pack.stderr ?? "");
      return pack.status ?? 1;
    }
    const metadata = JSON.parse(pack.stdout || "[]");
    const tarball = path.join(packageDir, metadata[0]?.filename ?? "");
    if (!metadata[0]?.filename) {
      process.stderr.write("npm pack did not produce a tarball\n");
      return 1;
    }
    const consumer = path.join(workDir, "consumer");
    const install = spawnSync(
      "npm",
      ["install", "--no-audit", "--no-fund", "--prefix", consumer, tarball],
      { cwd: workDir, encoding: "utf8", env: nestedNpmEnv(workDir) },
    );
    if (install.status !== 0) {
      process.stderr.write(install.stderr ?? "");
      return install.status ?? 1;
    }
    const binary = path.join(consumer, "node_modules", ".bin", "railgun");
    if (!readFileSync(binary, "utf8").includes("railgun")) {
      process.stderr.write("The packed tarball did not install a `railgun` binary\n");
      return 1;
    }
    return 0;
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

/** The Docker build + health check. */
function dockerCheck() {
  const image = "railgun-release-check:latest";
  const build = run(["docker", "build", "-t", image, "."]);
  if (build !== 0) return build;

  const containerName = "railgun-release-check";
  const remove = () => {
    spawnSync("docker", ["rm", "-f", containerName], { stdio: "ignore" });
  };
  remove();

  const runResult = spawnSync(
    "docker",
    ["run", "-d", "--name", containerName, "-p", "127.0.0.1::2526", image],
    { stdio: "inherit" },
  );
  if (runResult.status !== 0) {
    remove();
    return runResult.status ?? 1;
  }

  // Poll the container health until the Docker health check reports healthy,
  // then confirm the endpoint itself answers.
  let healthy = false;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const status = spawnSync(
      "docker",
      ["inspect", "--format", "{{.State.Health.Status}}", containerName],
      { encoding: "utf8" },
    );
    const value = (status.stdout ?? "").trim();
    if (value === "healthy") {
      healthy = true;
      break;
    }
    if (value === "unhealthy") {
      spawnSync("docker", ["logs", containerName], { stdio: "inherit" });
      break;
    }
    spawnSync("sleep", ["2"]);
  }

  remove();
  if (!healthy) {
    process.stderr.write("The container did not become healthy.\n");
    return 1;
  }
  process.stdout.write("The container reported a healthy health check.\n");
  return 0;
}

/** The checks, in order. */
const checks = [
  { id: "typecheck", run: () => run(["npm", "run", "--silent", "typecheck"]) },
  { id: "tests", run: () => run(["npm", "run", "--silent", "test"]) },
  { id: "licence-headers", run: () => run(["npm", "run", "--silent", "lint:licence"]) },
  { id: "standalone-install", run: standaloneInstall },
  { id: "npm-pack", run: npmPack },
  { id: "docker", run: dockerCheck },
];

/** The evidence file, with counts only and no secrets. */
const evidence = { checks: [], passed: 0, failed: 0, skipped: [] };

for (const check of checks) {
  if ((only && only !== check.id) || skip.has(check.id)) {
    evidence.skipped.push(check.id);
    continue;
  }
  process.stdout.write(`\n=== release check: ${check.id} ===\n`);
  const code = check.run();
  evidence.checks.push({ id: check.id, status: code === 0 ? "passed" : "failed" });
  if (code === 0) {
    evidence.passed += 1;
  } else {
    evidence.failed += 1;
  }
}

const evidencePath = path.join(packageRoot, "release-evidence.json");
writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);

process.stdout.write(`\n${JSON.stringify(evidence, null, 2)}\n`);
process.exit(evidence.failed > 0 ? 1 : 0);
