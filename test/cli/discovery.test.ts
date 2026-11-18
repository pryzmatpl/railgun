// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * CLI integration tests: command discovery, help, version and the usage /
 * configuration / dependency exit-code contract.
 */
import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { cliEntry, runCli, withTempDir, writeConfig } from "./helpers.js";

/** Every command the stable automation contract requires. */
const REQUIRED_COMMANDS = [
  "serve",
  "doctor",
  "admin create-admin",
  "messages list",
  "messages show",
  "messages retry",
  "messages suppress",
  "stats",
  "bounce list",
  "suppress add",
  "queue stats",
];

describe("railgun CLI — command discovery", () => {
  it("builds the installed executable", () => {
    expect(existsSync(cliEntry)).toBe(true);
  });

  it("lists every required command in the help text", async () => {
    const result = await runCli(["--help"]);
    expect(result.code).toBe(0);
    for (const command of REQUIRED_COMMANDS) {
      expect(result.stdout).toContain(command);
    }
  });

  it("documents the stable exit-code contract", async () => {
    const result = await runCli(["--help"]);
    expect(result.stdout).toContain("Exit codes:");
    expect(result.stdout).toContain("configuration invalid");
    expect(result.stdout).toContain("dependency or readiness failure");
  });

  it("prints the version without needing a configuration", async () => {
    const result = await runCli(["--version"], {
      env: { RAILGUN_CONFIG: "/nonexistent/railgun.yaml" },
    });
    expect(result.code).toBe(0);
    expect(result.stdout.trim()).toMatch(/^railgun \d+\.\d+\.\d+/);
  });

  it("rejects an unknown command with a usage error", async () => {
    const result = await runCli(["not-a-command"]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("USAGE_INVALID");
    expect(result.stderr).not.toContain("at Object.");
  });

  it("rejects an unknown flag with a usage error", async () => {
    const result = await runCli(["doctor", "--not-a-flag"]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("USAGE_INVALID");
  });
});

describe("railgun CLI — exit-code classification", () => {
  it("reports an unreadable configuration as a configuration error", async () => {
    const result = await runCli(["doctor", "--config", "/nonexistent/railgun.yaml"]);
    expect(result.code).toBe(3);
    expect(result.stderr).toContain("CONFIG_");
  });

  it("reports an invalid configuration as a configuration error", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir, "unknown_top_level_key: true\n");
      const result = await runCli(["doctor", "--config", configPath]);
      expect(result.code).toBe(3);
      expect(result.stderr).toContain("CONFIG_INVALID");
    });
  });

  it("emits the stable error envelope in JSON mode", async () => {
    const result = await runCli(["doctor", "--config", "/nonexistent/railgun.yaml", "--json"]);
    expect(result.code).toBe(3);
    // Exactly one JSON document on stdout.
    const parsed = JSON.parse(result.stdout) as {
      error: { code: string; message: string };
    };
    expect(parsed.error.code).toMatch(/^CONFIG_/);
    expect(typeof parsed.error.message).toBe("string");
    // No stack trace.
    expect(result.stdout).not.toContain("at Object.");
    expect(result.stdout).not.toContain(".ts:");
  });

  it("never prints a stack trace on a failure", async () => {
    const result = await runCli(["messages", "show", "missing-id"]);
    expect(result.code).not.toBe(0);
    expect(result.stdout + result.stderr).not.toContain("at Object.");
    expect(result.stdout + result.stderr).not.toContain("node:internal");
  });
});

describe("railgun CLI — serve mode selection", () => {
  it("rejects a serve invocation with no mode", async () => {
    const result = await runCli(["serve"]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("USAGE_INVALID");
    expect(result.stderr).toContain("--stdio");
  });

  it("rejects two incompatible serve modes", async () => {
    const result = await runCli(["serve", "--http", "--smtp"]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("mutually exclusive");
  });

  it("rejects three incompatible serve modes", async () => {
    const result = await runCli(["serve", "--stdio", "--http", "--smtp"]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("mutually exclusive");
  });
});
