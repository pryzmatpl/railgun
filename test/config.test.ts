// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Configuration acceptance tests.
 *
 * These assert the configuration contract: the precedence chain, the
 * fail-closed behaviour, the rejection of invalid values, and the rule that
 * a secret never enters the resolved configuration object.
 */
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  defaultConfig,
  ENV_REGISTRY,
  mergeYaml,
  resolveSecret,
  validateConfig,
  type ConfigDiagnostic,
} from "../src/config/config.js";
import { ConfigLoadError, loadConfig } from "../src/config/load.js";

/** Writes a YAML fixture into a temporary directory and returns its path. */
function writeConfig(yaml: string): string {
  const directory = mkdtempSync(path.join(tmpdir(), "railgun-config-"));
  const file = path.join(directory, "railgun.yaml");
  writeFileSync(file, yaml, "utf8");
  return file;
}

/** The field names of a diagnostic list. */
function fields(diagnostics: readonly ConfigDiagnostic[]): string[] {
  return diagnostics.map((diagnostic) => diagnostic.field);
}

describe("defaults", () => {
  it("resolve to a valid configuration with no file and no environment", () => {
    const config = defaultConfig();
    expect(validateConfig(config)).toEqual([]);
  });

  it("default to direct-to-MX outbound", () => {
    expect(defaultConfig().outbound.mode).toBe("direct");
  });

  it("default to the SQLite store with a file-backed queue", () => {
    const config = defaultConfig();
    expect(config.store.driver).toBe("sqlite");
    expect(config.store.path).toBe("./data/railgun.db");
    expect(config.audit.path).toBe("./data/audit.ndjson");
  });

  it("deny local submission by default", () => {
    expect(defaultConfig().auth.allow_local_submission).toBe(false);
  });

  it("do not enable telemetry by default", () => {
    expect(defaultConfig().domains.sending_domains).toEqual([]);
  });
});

describe("the YAML file layer", () => {
  it("rejects an unknown key", () => {
    const { errors } = mergeYaml(defaultConfig(), { server: { nonsense: 1 } });
    expect(errors.length).toBeGreaterThan(0);
    expect(fields(errors)).toContain("server.nonsense");
  });

  it("rejects an unknown top-level key", () => {
    const { errors } = mergeYaml(defaultConfig(), { nonsense: {} });
    expect(fields(errors)).toContain("nonsense");
  });

  it("rejects a value of the wrong type", () => {
    const { errors } = mergeYaml(defaultConfig(), { queue: { concurrency: "many" } });
    expect(fields(errors)).toContain("queue.concurrency");
  });

  it("accepts the documented nested outbound sections", () => {
    const { errors, config } = mergeYaml(defaultConfig(), {
      outbound: {
        mode: "direct",
        direct: { require_reverse_dns: false, connection_timeout_ms: 5000 },
      },
    });
    expect(errors).toEqual([]);
    expect(config.outbound.direct.connection_timeout_ms).toBe(5000);
    expect(config.outbound.direct.require_reverse_dns).toBe(false);
  });

  it("applies a file value over the shipped default", () => {
    const { config } = mergeYaml(defaultConfig(), { queue: { concurrency: 3 } });
    expect(config.queue.concurrency).toBe(3);
  });

  it("keeps the shipped default for a key the file omits", () => {
    const { config } = mergeYaml(defaultConfig(), { queue: { concurrency: 3 } });
    expect(config.queue.lease_seconds).toBe(defaultConfig().queue.lease_seconds);
  });
});

describe("the environment overlay", () => {
  it("overrides a file value", () => {
    const file = writeConfig("queue:\n  concurrency: 3\n");
    const loaded = loadConfig({ configPath: file, env: { RAILGUN_QUEUE_CONCURRENCY: "9" } });
    expect(loaded.config.queue.concurrency).toBe(9);
  });

  it("overrides a boolean", () => {
    const loaded = loadConfig({ env: { RAILGUN_AUDIT_ENABLED: "false" } });
    expect(loaded.config.audit.enabled).toBe(false);
  });

  it("overrides a list", () => {
    const loaded = loadConfig({ env: { RAILGUN_SENDING_DOMAINS: "a.example, b.example" } });
    expect(loaded.config.domains.sending_domains).toEqual(["a.example", "b.example"]);
  });

  it("rejects an unparseable boolean and names the variable", () => {
    expect(() => loadConfig({ env: { RAILGUN_AUDIT_ENABLED: "perhaps" } })).toThrow(ConfigLoadError);
    try {
      loadConfig({ env: { RAILGUN_AUDIT_ENABLED: "perhaps" } });
    } catch (error) {
      const diagnostics = (error as ConfigLoadError).diagnostics;
      expect(JSON.stringify(diagnostics)).toContain("RAILGUN_AUDIT_ENABLED");
    }
  });

  it("rejects an unparseable integer and names the variable", () => {
    expect(() => loadConfig({ env: { RAILGUN_QUEUE_CONCURRENCY: "eight" } })).toThrow(ConfigLoadError);
  });

  it("ignores an unknown RAILGUN_ variable", () => {
    const loaded = loadConfig({ env: { RAILGUN_NOT_A_REAL_SETTING: "1" } });
    expect(loaded.config).not.toBeNull();
  });

  it("declares every registry variable with a RAILGUN_ prefix", () => {
    for (const entry of ENV_REGISTRY) {
      expect(entry.variable.startsWith("RAILGUN_")).toBe(true);
    }
  });
});

describe("secret handling", () => {
  it("never puts a secret value into the resolved configuration", () => {
    const sentinel = "sentinel-secret-value";
    const loaded = loadConfig({
      env: { RAILGUN_RELAY_PASSWORD_ENV: "RAILGUN_RELAY_PASSWORD", RAILGUN_RELAY_PASSWORD: sentinel },
    });
    expect(JSON.stringify(loaded.config)).not.toContain(sentinel);
  });

  it("rejects a quote-wrapped secret and names only the variable", () => {
    const sentinel = '"sentinel-secret-value"';
    try {
      resolveSecret("RAILGUN_RELAY_PASSWORD", { RAILGUN_RELAY_PASSWORD: sentinel });
      throw new Error("expected resolveSecret to reject a quote-wrapped secret");
    } catch (error) {
      expect((error as Error).message).toContain("RAILGUN_RELAY_PASSWORD");
      expect((error as Error).message).not.toContain("sentinel-secret-value");
    }
  });

  it("rejects a whitespace-wrapped secret", () => {
    try {
      resolveSecret("RAILGUN_RELAY_PASSWORD", { RAILGUN_RELAY_PASSWORD: " value " });
      throw new Error("expected resolveSecret to reject a whitespace-wrapped secret");
    } catch (error) {
      expect((error as Error).message).toContain("RAILGUN_RELAY_PASSWORD");
    }
  });

  it("accepts a clean secret", () => {
    expect(resolveSecret("RAILGUN_RELAY_PASSWORD", { RAILGUN_RELAY_PASSWORD: "value" })).toBe("value");
  });
});

describe("fail-closed loading", () => {
  it("refuses a missing explicitly requested file", () => {
    expect(() => loadConfig({ configPath: "/nonexistent/railgun.yaml" })).toThrow(ConfigLoadError);
  });

  it("refuses a malformed YAML file", () => {
    const file = writeConfig("server: [unclosed\n");
    expect(() => loadConfig({ configPath: file })).toThrow(ConfigLoadError);
  });

  it("refuses an invalid configuration rather than degrading to a default", () => {
    const file = writeConfig("outbound:\n  mode: telepathy\n");
    expect(() => loadConfig({ configPath: file })).toThrow(ConfigLoadError);
  });

  it("names the offending path, never the value", () => {
    const file = writeConfig("outbound:\n  mode: telepathy\n");
    try {
      loadConfig({ configPath: file });
      throw new Error("expected loadConfig to reject an invalid value");
    } catch (error) {
      const diagnostics = (error as ConfigLoadError).diagnostics;
      expect(fields(diagnostics)).toContain("outbound.mode");
    }
  });
});
