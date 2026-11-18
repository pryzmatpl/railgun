// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * CLI integration tests for the serve modes and the output-channel contract.
 *
 * The serve tests exercise mode selection and the readiness of a listener
 * without ever sending mail: no test starts a real delivery.
 */
import { spawn } from "node:child_process";
import { describe, expect, it } from "vitest";

import { cliEntry, runCli, withTempDir, writeConfig } from "./helpers.js";

/**
 * Start `railgun serve` and wait for its readiness line on stderr.
 *
 * The child is killed when the callback returns.
 */
async function withServe(
  args: readonly string[],
  options: { configPath?: string } = {},
  fn: (child: ReturnType<typeof spawn>, stderr: () => string) => Promise<void>,
): Promise<void> {
  const child = spawn(process.execPath, [cliEntry, "serve", ...args], {
    env: { ...process.env, RAILGUN_CONFIG: options.configPath ?? "" },
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stderrText = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderrText += chunk;
  });

  // The child may exit before the listener is attached, so the close
  // notification is captured from the moment the child is spawned.
  let closed = false;
  const closedPromise = new Promise<void>((resolve) => {
    child.on("close", () => {
      closed = true;
      resolve();
    });
  });

  try {
    // Wait for the readiness line, with a bounded timeout.
    const deadline = Date.now() + 10_000;
    while (!stderrText.includes("listening") && !stderrText.includes("ready")) {
      if (closed) {
        throw new Error(`serve exited before becoming ready: ${stderrText}`);
      }
      if (Date.now() > deadline) {
        throw new Error(`serve did not become ready: ${stderrText}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    await fn(child, () => stderrText);
  } finally {
    if (!closed) {
      child.kill("SIGTERM");
    }
    await closedPromise;
  }
}

describe("railgun serve --http", () => {
  it("starts an HTTP listener and reports readiness on stderr", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      await withServe(["--http", "--http-bind", "127.0.0.1:0"], { configPath }, async (_child, stderr) => {
        expect(stderr()).toContain("listening");
      });
    });
  });

  it("keeps stdout free of protocol traffic", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      await withServe(["--http", "--http-bind", "127.0.0.1:0"], { configPath }, async (child) => {
        let stdout = "";
        child.stdout?.setEncoding("utf8");
        child.stdout?.on("data", (chunk: string) => {
          stdout += chunk;
        });
        await new Promise((resolve) => setTimeout(resolve, 200));
        expect(stdout).toBe("");
      });
    });
  });
});

describe("railgun serve --stdio", () => {
  it("reserves stdout for protocol frames and reports readiness on stderr", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      await withServe(["--stdio"], { configPath }, async (child, stderr) => {
        expect(stderr()).toContain("ready");

        let stdout = "";
        child.stdout?.setEncoding("utf8");
        child.stdout?.on("data", (chunk: string) => {
          stdout += chunk;
        });
        await new Promise((resolve) => setTimeout(resolve, 200));
        // The diagnostics must not have leaked onto stdout.
        expect(stdout).not.toContain("MCP transport ready");
      });
    });
  });
});

describe("railgun CLI — output channels", () => {
  it("writes data to stdout and diagnostics to stderr", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli(["stats", "--config", configPath, "--json"]);
      expect(result.code).toBe(0);
      // The data document is on stdout.
      expect(() => JSON.parse(result.stdout)).not.toThrow();
      // The successful run has no diagnostics.
      expect(result.stderr).toBe("");
    });
  });

  it("writes a failure diagnostic to stderr and nothing to stdout in human mode", async () => {
    const result = await runCli(["messages", "show", "rg_absent"]);
    expect(result.code).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("NOT_FOUND");
  });

  it("writes the failure envelope to stdout in JSON mode", async () => {
    const result = await runCli(["messages", "show", "rg_absent", "--json"]);
    expect(result.code).toBe(1);
    expect(result.stderr).toBe("");
    const parsed = JSON.parse(result.stdout) as { error: { code: string } };
    expect(parsed.error.code).toBe("NOT_FOUND");
  });
});
