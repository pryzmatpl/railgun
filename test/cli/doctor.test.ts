// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * CLI integration tests for `railgun doctor`.
 *
 * The doctor validates configuration, runtime resources and connectivity
 * assumptions without starting a public listener and without ever printing a
 * secret.
 */
import { describe, expect, it } from "vitest";

import { runCli, withTempDir, writeConfig } from "./helpers.js";

describe("railgun doctor — valid configuration", () => {
  it("reports a checklist and exits zero", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli(["doctor", "--config", configPath]);
      expect(result.code).toBe(0);
      expect(result.stdout).toContain("runtime");
      expect(result.stdout).toContain("configuration");
      expect(result.stdout).toContain("store");
      expect(result.stdout).toContain("queue");
      expect(result.stdout).toContain("outbound");
    });
  });

  it("emits a single JSON document with an ordered checks array", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli(["doctor", "--config", configPath, "--json"]);
      expect(result.code).toBe(0);

      const parsed = JSON.parse(result.stdout) as {
        status: string;
        checks: { name: string; status: string; detail: string }[];
      };
      expect(["ok", "warn", "fail"]).toContain(parsed.status);
      expect(Array.isArray(parsed.checks)).toBe(true);
      expect(parsed.checks.length).toBeGreaterThan(0);
      for (const check of parsed.checks) {
        expect(["ok", "warn", "fail"]).toContain(check.status);
        expect(typeof check.detail).toBe("string");
      }
      // The JSON is the only thing on stdout.
      expect(result.stdout.trim().startsWith("{")).toBe(true);
      expect(result.stdout.trim().endsWith("}")).toBe(true);
    });
  });

  it("reports the direct outbound mode as the primary mode", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli(["doctor", "--config", configPath, "--json"]);
      const parsed = JSON.parse(result.stdout) as {
        checks: { name: string; detail: string }[];
      };
      const outbound = parsed.checks.find((check) => check.name === "outbound");
      expect(outbound).toBeDefined();
      expect(outbound!.detail).toContain("direct");
    });
  });
});

describe("railgun doctor — secrets are never disclosed", () => {
  it("reports a configured secret by name only", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(
        dir,
        "audit:\n  salt_env: \"RAILGUN_AUDIT_SALT\"\n",
      );
      const secret = "s3cr3t-audit-salt-value";
      const result = await runCli(["doctor", "--config", configPath, "--json"], {
        env: { RAILGUN_AUDIT_SALT: secret },
      });
      expect(result.stdout).not.toContain(secret);
      expect(result.stdout).toContain("RAILGUN_AUDIT_SALT");
    });
  });

  it("does not print a secret from a DKIM key reference", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(
        dir,
        'dkim:\n  enabled: true\n  selector: "rg1"\n  private_key_env: "RAILGUN_DKIM_KEY"\n',
      );
      const key = "-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----";
      const result = await runCli(["doctor", "--config", configPath, "--json"], {
        env: { RAILGUN_DKIM_KEY: key },
      });
      expect(result.stdout).not.toContain(key);
      expect(result.stdout).not.toContain("BEGIN PRIVATE KEY");
    });
  });
});

describe("railgun doctor — invalid configuration", () => {
  it("fails with the configuration exit code", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir, "unknown_key: 1\n");
      const result = await runCli(["doctor", "--config", configPath]);
      expect(result.code).toBe(3);
    });
  });

  it("rejects a YAML file that does not parse", async () => {
    await withTempDir(async (dir) => {
      const { writeFileSync } = await import("node:fs");
      const path = await import("node:path");
      const configPath = path.join(dir, "broken.yaml");
      writeFileSync(configPath, "server: [unclosed\n", "utf8");
      const result = await runCli(["doctor", "--config", configPath]);
      expect(result.code).toBe(3);
      expect(result.stderr).toContain("CONFIG_INVALID");
    });
  });

  it("rejects a configuration whose required setting is missing", async () => {
    await withTempDir(async (dir) => {
      const { writeFileSync } = await import("node:fs");
      const path = await import("node:path");
      const configPath = path.join(dir, "relay.yaml");
      writeFileSync(configPath, 'outbound:\n  mode: "relay"\n', "utf8");
      const result = await runCli(["doctor", "--config", configPath]);
      expect(result.code).toBe(3);
      expect(result.stderr).toContain("outbound.relay.host");
    });
  });
});
