// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The credential-hygiene and live-gate verification tests.
 *
 * These cover V-SEC-1 … V-SEC-6 and V-LIVE-1 … V-LIVE-7 of the verification
 * IR: the scanner finds a planted credential, reports counts without echoing
 * the value, and the live gate refuses to run unless every precondition is
 * met.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  DEFAULT_LIVE_CREDENTIAL_VARIABLE,
  DEFAULT_LIVE_OPT_IN_VARIABLE,
  DEFAULT_LIVE_RECIPIENT_VARIABLE,
  REDACTION_SENTINEL,
  assertNoSecretLeak,
  evaluateLiveGate,
  redactSecret,
  releaseCheckTargets,
  resolveLiveGate,
  scanForSecrets,
} from "../../src/verification/index.js";

/** The temporary roots created by a test, removed after the test. */
const temporaryRoots: string[] = [];

/** Create a temporary directory that is removed after the test. */
function tempRoot(): string {
  const root = mkdtempSync(path.join(tmpdir(), "railgun-verify-"));
  temporaryRoots.push(root);
  return root;
}

afterEach(() => {
  while (temporaryRoots.length > 0) {
    const root = temporaryRoots.pop();
    if (root) rmSync(root, { recursive: true, force: true });
  }
});

describe("credential-hygiene scanner", () => {
  it("reports a planted credential without echoing its value", () => {
    const root = tempRoot();
    const secret = "sup3r-secret-value-1234";
    writeFileSync(path.join(root, "app.log"), `connecting with ${secret}\n`);
    writeFileSync(path.join(root, "audit.ndjson"), `{"event":"send"}\n`);

    const result = scanForSecrets({ root, secret });

    expect(result.matches).toBe(1);
    expect(result.files).toBe(1);
    expect(result.findings[0]?.file).toBe("app.log");
    expect(result.findings[0]?.count).toBe(1);
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("reports zero matches for a clean tree", () => {
    const root = tempRoot();
    writeFileSync(path.join(root, "app.log"), "connecting to the relay\n");
    writeFileSync(path.join(root, "audit.ndjson"), '{"event":"send"}\n');

    const result = scanForSecrets({ root, secret: "absent-secret-value" });

    expect(result.matches).toBe(0);
    expect(result.files).toBe(0);
    expect(result.scannedFiles).toBeGreaterThan(0);
  });

  it("ignores the node_modules and dist directories", () => {
    const root = tempRoot();
    const secret = "sup3r-secret-value-1234";
    writeFileSync(path.join(root, "keep.ts"), "export const ok = 1;\n");
    const ignored = path.join(root, "node_modules", "pkg");
    writeFileSync(path.join(root, "package.json"), "{}\n");
    // The ignored directories are created by hand so the test does not need a
    // real dependency tree.
    const { mkdirSync } = require("node:fs") as typeof import("node:fs");
    mkdirSync(ignored, { recursive: true });
    writeFileSync(path.join(ignored, "index.js"), `const secret = "${secret}";\n`);

    const result = scanForSecrets({ root, secret });

    expect(result.matches).toBe(0);
  });

  it("finds a credential in a .env file", () => {
    const root = tempRoot();
    const secret = "sup3r-secret-value-1234";
    writeFileSync(path.join(root, ".env"), `SMTP_PASSWORD=${secret}\n`);

    const result = scanForSecrets({ root, secret });

    expect(result.matches).toBe(1);
    expect(result.findings[0]?.file).toBe(".env");
  });

  it("redacts a credential in arbitrary output", () => {
    const secret = "sup3r-secret-value-1234";
    const output = redactSecret(`the password is ${secret}.`, secret);
    expect(output).not.toContain(secret);
    expect(output).toContain(REDACTION_SENTINEL);
  });

  it("throws on a leak and names the file without repeating the secret", () => {
    const root = tempRoot();
    const secret = "sup3r-secret-value-1234";
    const artefact = path.join(root, "audit.ndjson");
    writeFileSync(artefact, `{"password":"${secret}"}\n`);

    expect(() => assertNoSecretLeak([artefact], secret, "audit log")).toThrowError(/audit log/);
    try {
      assertNoSecretLeak([artefact], secret, "audit log");
    } catch (error) {
      expect((error as Error).message).not.toContain(secret);
    }
  });

  it("returns a clean scan result for artefacts without the credential", () => {
    const root = tempRoot();
    const artefact = path.join(root, "audit.ndjson");
    writeFileSync(artefact, '{"event":"send"}\n');

    const result = assertNoSecretLeak([artefact], "absent-secret-value", "audit log");

    expect(result.matches).toBe(0);
    expect(result.scannedFiles).toBe(1);
  });
});

describe("live delivery gate", () => {
  const base = {
    [DEFAULT_LIVE_OPT_IN_VARIABLE]: "1",
    [DEFAULT_LIVE_CREDENTIAL_VARIABLE]: "correct-horse-battery",
    [DEFAULT_LIVE_RECIPIENT_VARIABLE]: "approved@example.com",
  };

  it("allows the run when every precondition is met", () => {
    const decision = resolveLiveGate(base);
    expect(decision.allowed).toBe(true);
    expect(decision.recipient).toBe("approved@example.com");
    expect(decision.checks.every((check) => check.ok)).toBe(true);
  });

  it("refuses the run without the explicit opt-in", () => {
    const environment = { ...base, [DEFAULT_LIVE_OPT_IN_VARIABLE]: "0" };
    const decision = resolveLiveGate(environment);
    expect(decision.allowed).toBe(false);
    expect(decision.checks.find((check) => check.name === "opt-in")?.ok).toBe(false);
  });

  it("refuses the run without a credential", () => {
    const environment = { ...base, [DEFAULT_LIVE_CREDENTIAL_VARIABLE]: undefined };
    const decision = resolveLiveGate(environment);
    expect(decision.allowed).toBe(false);
    expect(decision.checks.find((check) => check.name === "credential-present")?.ok).toBe(false);
  });

  it("refuses a quote-wrapped credential", () => {
    const environment = { ...base, [DEFAULT_LIVE_CREDENTIAL_VARIABLE]: '"correct-horse-battery"' };
    const decision = resolveLiveGate(environment);
    expect(decision.allowed).toBe(false);
    expect(decision.checks.find((check) => check.name === "credential-well-formed")?.ok).toBe(false);
  });

  it("refuses a padded credential", () => {
    const environment = { ...base, [DEFAULT_LIVE_CREDENTIAL_VARIABLE]: " correct-horse-battery " };
    const decision = resolveLiveGate(environment);
    expect(decision.allowed).toBe(false);
  });

  it("refuses the run without an approved recipient", () => {
    const environment = { ...base, [DEFAULT_LIVE_RECIPIENT_VARIABLE]: undefined };
    const decision = resolveLiveGate(environment);
    expect(decision.allowed).toBe(false);
  });

  it("refuses a recipient list", () => {
    const environment = { ...base, [DEFAULT_LIVE_RECIPIENT_VARIABLE]: "a@example.com,b@example.com" };
    const decision = resolveLiveGate(environment);
    expect(decision.allowed).toBe(false);
  });

  it("refuses a recipient with surrounding whitespace", () => {
    const environment = { ...base, [DEFAULT_LIVE_RECIPIENT_VARIABLE]: " approved@example.com " };
    const decision = resolveLiveGate(environment);
    expect(decision.allowed).toBe(false);
  });

  it("never echoes the credential in a refusal", () => {
    const environment = { ...base, [DEFAULT_LIVE_CREDENTIAL_VARIABLE]: '"correct-horse-battery"' };
    expect(() => evaluateLiveGate(environment)).toThrowError();
    try {
      evaluateLiveGate(environment);
    } catch (error) {
      expect((error as Error).message).not.toContain("correct-horse-battery");
    }
  });
});

describe("release checks", () => {
  it("never includes the live delivery run", () => {
    const targets = releaseCheckTargets();
    expect(targets.map((target) => target.id)).not.toContain("live");
    expect(targets.map((target) => target.id)).not.toContain("live-delivery");
  });

  it("covers the standalone install, pack, docker and licence gates", () => {
    const ids = releaseCheckTargets().map((target) => target.id);
    expect(ids).toContain("standalone-install");
    expect(ids).toContain("npm-pack");
    expect(ids).toContain("docker");
    expect(ids).toContain("licence-headers");
    expect(ids).toContain("tests");
  });
});

describe("package verification assets", () => {
  const packageRoot = path.resolve(import.meta.dirname, "..", "..");

  it("ships the live delivery script with the GPL header", () => {
    const source = readFileSync(path.join(packageRoot, "scripts", "live-delivery.mjs"), "utf8");
    expect(source).toContain("SPDX-License-Identifier: GPL-3.0-or-later");
  });

  it("keeps the live script free of credential literals", () => {
    const source = readFileSync(path.join(packageRoot, "scripts", "live-delivery.mjs"), "utf8");
    // The script may only reference the credential through the environment
    // variable; it may not contain a credential-shaped literal.
    expect(source).not.toMatch(/password\s*=\s*["'][^"']{8,}["']/i);
    expect(source).not.toMatch(/["'][A-Za-z0-9+/]{24,}={0,2}["']/);
  });

  it("ships the DNS setup guidance", () => {
    const guide = readFileSync(path.join(packageRoot, "docs", "DNS-SETUP.md"), "utf8");
    expect(guide).toContain("_dmarc");
    expect(guide).toContain("_domainkey");
    expect(guide).toContain("dig +short");
    expect(guide).toContain("port 25");
  });

  it("ships the release-check command", () => {
    const source = readFileSync(path.join(packageRoot, "scripts", "release-check.mjs"), "utf8");
    expect(source).toContain("standalone-install");
    expect(source).toContain("npm");
    expect(source).toContain("docker");
  });
});
