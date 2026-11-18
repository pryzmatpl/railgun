// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * CLI integration tests for the operator commands: admin creation, message
 * inspection, bounce listing, statistics, suppression and queue status.
 *
 * The commands run against an isolated temporary data directory, so no test
 * ever touches a real store and no test ever sends mail.
 */
import { describe, expect, it } from "vitest";

import { runCli, withTempDir, writeConfig } from "./helpers.js";

describe("railgun admin create-admin", () => {
  it("creates an administrator non-interactively and shows the credential once", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli([
        "admin",
        "create-admin",
        "--config",
        configPath,
        "--name",
        "Operator",
        "--email",
        "operator@example.com",
      ]);
      expect(result.code).toBe(0);
      expect(result.stdout).toContain("Operator");
      expect(result.stdout).toContain("operator@example.com");
      // The generated credential is shown exactly once.
      expect(result.stdout).toContain("credential (shown once)");
    });
  });

  it("returns a one-time secret in JSON mode", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli([
        "admin",
        "create-admin",
        "--config",
        configPath,
        "--json",
      ]);
      expect(result.code).toBe(0);
      const parsed = JSON.parse(result.stdout) as {
        admin: { id: string; credentialFingerprint: string | null };
        created: boolean;
        secret: string | null;
      };
      expect(parsed.created).toBe(true);
      expect(parsed.admin.id).toBeTruthy();
      expect(parsed.secret).toBeTruthy();
      // The fingerprint is a short digest, never the secret itself.
      expect(parsed.admin.credentialFingerprint).not.toBe(parsed.secret);
    });
  });

  it("is idempotent: a second run does not create a second administrator", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const first = await runCli(["admin", "create-admin", "--config", configPath, "--json"]);
      const second = await runCli(["admin", "create-admin", "--config", configPath, "--json"]);
      expect(first.code).toBe(0);
      expect(second.code).toBe(0);
      const firstParsed = JSON.parse(first.stdout) as { admin: { id: string }; secret: string | null };
      const secondParsed = JSON.parse(second.stdout) as {
        admin: { id: string };
        secret: string | null;
        created: boolean;
      };
      expect(secondParsed.admin.id).toBe(firstParsed.admin.id);
      expect(secondParsed.created).toBe(false);
      // No new secret is generated for the existing administrator.
      expect(secondParsed.secret).toBeNull();
    });
  });

  it("accepts a credential from a secret file without echoing it in argv", async () => {
    await withTempDir(async (dir) => {
      const { writeFileSync } = await import("node:fs");
      const path = await import("node:path");
      const secretPath = path.join(dir, "admin.secret");
      const secret = "operator-secret-value";
      writeFileSync(secretPath, `${secret}\n`, "utf8");

      const configPath = writeConfig(dir);
      const result = await runCli([
        "admin",
        "create-admin",
        "--config",
        configPath,
        "--secret-file",
        secretPath,
        "--json",
      ]);
      expect(result.code).toBe(0);
      // A credential supplied through a file is not re-displayed.
      const parsed = JSON.parse(result.stdout) as { secret: string | null };
      expect(parsed.secret).toBeNull();
      expect(result.stdout).not.toContain(secret);
    });
  });

  it("rejects a missing subcommand with a usage error", async () => {
    const result = await runCli(["admin"]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("USAGE_INVALID");
  });
});

describe("railgun messages", () => {
  it("lists messages and reports an empty result honestly", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli(["messages", "list", "--config", configPath, "--json"]);
      expect(result.code).toBe(0);
      const parsed = JSON.parse(result.stdout) as {
        items: unknown[];
        next_cursor: string | null;
        total: number | null;
      };
      expect(Array.isArray(parsed.items)).toBe(true);
      expect(parsed.next_cursor).toBeNull();
    });
  });

  it("reports a missing message with a stable not-found error", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli([
        "messages",
        "show",
        "rg_missing",
        "--config",
        configPath,
        "--json",
      ]);
      expect(result.code).toBe(1);
      const parsed = JSON.parse(result.stdout) as { error: { code: string } };
      expect(parsed.error.code).toBe("NOT_FOUND");
    });
  });

  it("rejects an invalid status filter with a usage error", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli([
        "messages",
        "list",
        "--config",
        configPath,
        "--status",
        "not-a-status",
      ]);
      expect(result.code).toBe(2);
      expect(result.stderr).toContain("USAGE_INVALID");
    });
  });

  it("requires a message id for show, retry and suppress", async () => {
    for (const subcommand of ["show", "retry", "suppress"]) {
      const result = await runCli(["messages", subcommand]);
      expect(result.code).toBe(2);
      expect(result.stderr).toContain("USAGE_INVALID");
    }
  });
});

describe("railgun stats", () => {
  it("reports the canonical counters", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli(["stats", "--config", configPath, "--json"]);
      expect(result.code).toBe(0);
      const parsed = JSON.parse(result.stdout) as Record<string, number>;
      for (const counter of [
        "queued",
        "accepted",
        "delivered",
        "deferred",
        "bounced",
        "suppressed",
        "rejected",
      ]) {
        expect(parsed[counter]).toBe(0);
      }
    });
  });

  it("never presents acceptance as delivery", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli(["stats", "--config", configPath]);
      expect(result.stdout).toContain("confirmed delivery only");
    });
  });
});

describe("railgun bounce list", () => {
  it("reports an empty bounce list", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli(["bounce", "list", "--config", configPath, "--json"]);
      expect(result.code).toBe(0);
      const parsed = JSON.parse(result.stdout) as { items: unknown[] };
      expect(parsed.items).toEqual([]);
    });
  });

  it("rejects an unknown bounce class", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli([
        "bounce",
        "list",
        "--config",
        configPath,
        "--class",
        "nonsense",
      ]);
      expect(result.code).toBe(2);
      expect(result.stderr).toContain("USAGE_INVALID");
    });
  });
});

describe("railgun suppress add", () => {
  it("adds a suppression entry and reports the scope", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli([
        "suppress",
        "add",
        "User@Example.com",
        "--reason",
        "hard_bounce",
        "--config",
        configPath,
        "--json",
      ]);
      expect(result.code).toBe(0);
      const parsed = JSON.parse(result.stdout) as {
        projection: { scope: string; reason: string; permanent: boolean };
        created: boolean;
      };
      expect(parsed.created).toBe(true);
      // The scope is normalized.
      expect(parsed.projection.scope).toBe("user@example.com");
      expect(parsed.projection.reason).toBe("hard_bounce");
      expect(parsed.projection.permanent).toBe(true);
    });
  });

  it("is idempotent for an identical entry", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const args = [
        "suppress",
        "add",
        "user@example.com",
        "--reason",
        "hard_bounce",
        "--config",
        configPath,
        "--json",
      ];
      const first = await runCli(args);
      const second = await runCli(args);
      expect(first.code).toBe(0);
      expect(second.code).toBe(0);
      const firstParsed = JSON.parse(first.stdout) as { created: boolean };
      const secondParsed = JSON.parse(second.stdout) as { created: boolean };
      expect(firstParsed.created).toBe(true);
      expect(secondParsed.created).toBe(false);
    });
  });

  it("requires a reason", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli([
        "suppress",
        "add",
        "user@example.com",
        "--config",
        configPath,
      ]);
      expect(result.code).toBe(2);
      expect(result.stderr).toContain("USAGE_INVALID");
    });
  });

  it("rejects an unknown reason token", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli([
        "suppress",
        "add",
        "user@example.com",
        "--reason",
        "because_i_said_so",
        "--config",
        configPath,
      ]);
      expect(result.code).toBe(2);
      expect(result.stderr).toContain("USAGE_INVALID");
    });
  });

  it("rejects a malformed address", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli([
        "suppress",
        "add",
        "not-an-address",
        "--reason",
        "manual",
        "--config",
        configPath,
      ]);
      expect(result.code).toBe(2);
      expect(result.stderr).toContain("USAGE_INVALID");
    });
  });
});

describe("railgun queue stats", () => {
  it("reports the queue depth", async () => {
    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const result = await runCli(["queue", "stats", "--config", configPath, "--json"]);
      expect(result.code).toBe(0);
      const parsed = JSON.parse(result.stdout) as {
        depth: number;
        due: number;
        leased: number;
        oldestQueuedAgeSeconds: number;
      };
      expect(parsed.depth).toBe(0);
      expect(parsed.due).toBe(0);
      expect(parsed.leased).toBe(0);
    });
  });

  it("rejects an unknown queue subcommand", async () => {
    const result = await runCli(["queue", "cancel"]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("USAGE_INVALID");
  });
});
