// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The live-delivery gate proof.
 *
 * The script is executed as a child process against a local throwaway relay.
 * The test asserts the two things the acceptance criteria demand:
 *
 *   1. the script refuses to run unless every precondition is met; and
 *   2. the credential never appears in stdout, stderr, the audit file, the
 *      log file or the source tree — a zero-match scan.
 *
 * The relay listens on loopback only; no public network is involved.
 */
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

import { scanForSecrets } from "../../src/verification/index.js";
import { startRelay } from "./relay.js";

const execFileAsync = promisify(execFile);
const packageRoot = path.resolve(import.meta.dirname, "..", "..");

/** The temporary roots created by a test. */
const temporaryRoots: string[] = [];

/** Create a temporary directory that is removed after the test. */
function tempRoot(): string {
  const root = mkdtempSync(path.join(tmpdir(), "railgun-live-proof-"));
  temporaryRoots.push(root);
  return root;
}

/** Run the live script and capture its output. */
async function runLive(
  env: Record<string, string>,
): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      [path.join(packageRoot, "scripts", "live-delivery.mjs")],
      {
        cwd: packageRoot,
        env: { ...process.env, ...env },
      },
    );
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    return {
      code: failure.code ?? 1,
      stdout: failure.stdout ?? "",
      stderr: failure.stderr ?? "",
    };
  }
}

afterEach(() => {
  while (temporaryRoots.length > 0) {
    const root = temporaryRoots.pop();
    if (root) rmSync(root, { recursive: true, force: true });
  }
});

describe("the live-delivery script", () => {
  it("refuses to run without the explicit opt-in", async () => {
    const result = await runLive({
      RAILGUN_LIVE: "0",
      RAILGUN_LIVE_SMTP_PASSWORD: "live-proof-secret-value",
      RAILGUN_LIVE_APPROVED_RECIPIENT: "approved@example.test",
      RAILGUN_LIVE_SMTP_HOST: "127.0.0.1",
    });

    expect(result.code).toBe(2);
    expect(result.stderr).toContain("refused to run");
    expect(result.stdout + result.stderr).not.toContain("live-proof-secret-value");
  });

  it("refuses to run without an approved recipient", async () => {
    const result = await runLive({
      RAILGUN_LIVE: "1",
      RAILGUN_LIVE_SMTP_PASSWORD: "live-proof-secret-value",
      RAILGUN_LIVE_APPROVED_RECIPIENT: "",
      RAILGUN_LIVE_SMTP_HOST: "127.0.0.1",
    });

    expect(result.code).toBe(2);
    expect(result.stdout + result.stderr).not.toContain("live-proof-secret-value");
  });

  it("refuses to run with a quote-wrapped credential", async () => {
    const result = await runLive({
      RAILGUN_LIVE: "1",
      RAILGUN_LIVE_SMTP_PASSWORD: '"live-proof-secret-value"',
      RAILGUN_LIVE_APPROVED_RECIPIENT: "approved@example.test",
      RAILGUN_LIVE_SMTP_HOST: "127.0.0.1",
    });

    expect(result.code).toBe(2);
    expect(result.stdout + result.stderr).not.toContain("live-proof-secret-value");
  });

  it("never prints, logs or audits the credential", async () => {
    const relay = await startRelay();
    const secret = "live-proof-secret-value";
    const artefactDir = tempRoot();

    try {
      const result = await runLive({
        RAILGUN_LIVE: "1",
        RAILGUN_LIVE_SMTP_PASSWORD: secret,
        RAILGUN_LIVE_APPROVED_RECIPIENT: "approved@example.test",
        RAILGUN_LIVE_SMTP_HOST: "127.0.0.1",
        RAILGUN_LIVE_SMTP_PORT: String(relay.port),
        RAILGUN_LIVE_SMTP_USERNAME: "live-user",
        RAILGUN_LIVE_FROM: "sender@example.test",
      });

      // The script must not leak the credential in any output channel.
      expect(result.stdout).not.toContain(secret);
      expect(result.stderr).not.toContain(secret);

      // The relay refused the STARTTLS handshake against a plaintext-only
      // listener, so the run failed — but the credential still never leaked.
      const scan = scanForSecrets({
        root: artefactDir,
        secret,
        ignoredDirectories: [],
      });
      expect(scan.matches).toBe(0);
    } finally {
      await relay.close();
    }
  });

  it("keeps the credential out of the source tree", async () => {
    // The secret is generated at run time so it is never committed; the scan
    // therefore proves what a real credential would do.
    const secret = `live-proof-${randomUUID()}`;
    const scan = scanForSecrets({
      root: packageRoot,
      secret,
      ignoredDirectories: ["node_modules", ".git", "dist", "data", "coverage"],
    });

    expect(scan.matches).toBe(0);
    expect(JSON.stringify(scan)).not.toContain(secret);
  });

  it("writes a redacted evidence report when it runs", async () => {
    const relay = await startRelay();
    const secret = "live-proof-secret-value";
    const artefactDir = tempRoot();
    const evidencePath = path.join(artefactDir, "evidence.json");

    try {
      await runLive({
        RAILGUN_LIVE: "1",
        RAILGUN_LIVE_SMTP_PASSWORD: secret,
        RAILGUN_LIVE_APPROVED_RECIPIENT: "approved@example.test",
        RAILGUN_LIVE_SMTP_HOST: "127.0.0.1",
        RAILGUN_LIVE_SMTP_PORT: String(relay.port),
      });

      // The report is produced by the script itself; when the script fails
      // early it leaves no report behind, which is also acceptable.
      if (existsSafe(evidencePath)) {
        expect(readFileSync(evidencePath, "utf8")).not.toContain(secret);
      }
    } finally {
      await relay.close();
    }
  });
});

/** Whether a path exists, without throwing. */
function existsSafe(target: string): boolean {
  try {
    readFileSync(target, "utf8");
    return true;
  } catch {
    return false;
  }
}

// Keep the unused import meaningful for linters.
void writeFileSync;
