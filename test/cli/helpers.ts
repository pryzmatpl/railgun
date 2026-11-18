// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Shared helpers for the CLI integration tests.
 *
 * The tests exercise the installed executable, not only internal functions:
 * each case spawns the package binary in a child process so the stdout /
 * stderr separation, the exit-code contract and the JSON shape are all
 * observed exactly as an operator or an automation would see them.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

/** The package root (`test/cli` → package root). */
export const packageRoot = path.resolve(here, "..", "..");

/** The compiled CLI entry point. */
export const cliEntry = path.join(packageRoot, "dist", "bin.js");

/** The result of one CLI invocation. */
export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Run the CLI with the given arguments.
 *
 * `env` is merged over the process environment so a test can isolate the
 * configuration overlay without leaking into the parent process.
 */
export function runCli(
  args: readonly string[],
  options: { env?: NodeJS.ProcessEnv; input?: string } = {},
): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliEntry, ...args], {
      cwd: packageRoot,
      env: {
        ...process.env,
        // The tests must never reach a real operator configuration.
        RAILGUN_CONFIG: "",
        RAILGUN_API_KEY: "",
        ...options.env,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ code: code ?? 0, stdout, stderr });
    });

    if (options.input !== undefined) {
      child.stdin.write(options.input);
    }
    child.stdin.end();
  });
}

/** A temporary directory that is removed when the test finishes. */
export function withTempDir<T>(fn: (dir: string) => T | Promise<T>): Promise<T> {
  const dir = mkdtempSync(path.join(tmpdir(), "railgun-cli-"));
  return Promise.resolve(fn(dir)).finally(() => {
    rmSync(dir, { recursive: true, force: true });
  });
}

/**
 * A minimal valid configuration file.
 *
 * It uses a file-backed sqlite store in the temporary directory, so the state
 * an operator command writes is visible to the next invocation — which is
 * what makes the idempotency and persistence assertions meaningful. It also
 * enables local submission so the operator commands that require the `admin`
 * scope are reachable from a test.
 */
export function writeConfig(dir: string, extra: string = ""): string {
  const configPath = path.join(dir, "railgun.yaml");
  const body = `store:
  driver: "sqlite"
  path: "${path.join(dir, "railgun.db").replaceAll("\\", "/")}"
auth:
  allow_local_submission: true
outbound:
  mode: "direct"
${extra}`;
  // The configuration file is written by the test itself; it contains no
  // secret, only the store path and the outbound mode.
  const { writeFileSync } = require("node:fs") as typeof import("node:fs");
  writeFileSync(configPath, body, "utf8");
  return configPath;
}
