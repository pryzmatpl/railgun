/* RailGun SMTP submission server — TLS fixtures.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { SmtpTlsOptions } from "../../src/smtp/types.js";

let cached: SmtpTlsOptions | null = null;

/**
 * Generate a throwaway self-signed certificate for the TLS tests.
 *
 * The certificate lives in a temporary directory and is removed when the
 * process exits. `null` is returned when `openssl` is unavailable, so the
 * caller can skip the TLS assertions instead of failing the suite.
 */
export function selfSignedTls(): SmtpTlsOptions | null {
  if (cached) return cached;

  const dir = mkdtempSync(join(tmpdir(), "railgun-tls-"));
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "cert.pem");

  try {
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        keyPath,
        "-out",
        certPath,
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
      ],
      { stdio: "ignore" },
    );
  } catch {
    rmSync(dir, { recursive: true, force: true });
    return null;
  }

  const key = readFileSync(keyPath, "utf8");
  const cert = readFileSync(certPath, "utf8");
  rmSync(dir, { recursive: true, force: true });

  cached = { cert, key, minVersion: "TLSv1.2" };
  return cached;
}
