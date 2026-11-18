/* RailGun direct-to-MX delivery engine — STARTTLS tests.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import tls from "node:tls";

import { describe, expect, it } from "vitest";

import { MIN_TLS_VERSION, SmtpClient } from "../../src/outbound/smtp-client.js";

/** A throwaway certificate for the TLS tests. */
interface TlsFixture {
  readonly cert: string;
  readonly key: string;
}

/**
 * Generate a self-signed certificate.
 *
 * `null` is returned when `openssl` is unavailable, so the caller can skip
 * the TLS assertions instead of failing the suite.
 */
function selfSigned(): TlsFixture | null {
  const dir = mkdtempSync(join(tmpdir(), "railgun-mx-tls-"));
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
        "/CN=mx.fake.test",
        "-addext",
        "subjectAltName=DNS:mx.fake.test,IP:127.0.0.1",
      ],
      { stdio: "ignore" },
    );
  } catch {
    rmSync(dir, { recursive: true, force: true });
    return null;
  }
  const fixture = {
    cert: readFileSync(certPath, "utf8"),
    key: readFileSync(keyPath, "utf8"),
  };
  rmSync(dir, { recursive: true, force: true });
  return fixture;
}

/**
 * Start a fake MX that advertises STARTTLS and upgrades the connection.
 *
 * The server records whether the upgrade happened and which TLS parameters
 * were negotiated.
 */
async function startStarttlsMx(
  fixture: TlsFixture,
): Promise<{
  port: number;
  upgraded: () => boolean;
  protocol: () => string | null;
  close: () => Promise<void>;
}> {
  let upgraded = false;
  let negotiatedProtocol: string | null = null;

  const server = net.createServer((socket) => {
    socket.write("220 fake.mx.test ESMTP\r\n");
    let pending = "";
    socket.on("data", (chunk) => {
      pending += chunk.toString("utf8");
      let index = pending.indexOf("\r\n");
      while (index !== -1) {
        const line = pending.slice(0, index);
        pending = pending.slice(index + 2);
        const verb = line.split(" ")[0]!.toUpperCase();
        if (verb === "EHLO") {
          socket.write("250-fake.mx.test\r\n250-STARTTLS\r\n250 8BITMIME\r\n");
        } else if (verb === "STARTTLS") {
          upgraded = true;
          socket.removeAllListeners("data");
          // The `220` reply is flushed before the TLS socket is created:
          // creating the TLS socket in the same tick interleaves the
          // handshake bytes with the plaintext reply.
          socket.write("220 2.0.0 Ready to start TLS\r\n", () => {
            const secure = new tls.TLSSocket(socket, {
              isServer: true,
              cert: fixture.cert,
              key: fixture.key,
              minVersion: "TLSv1.2",
            });
            secure.on("secure", () => {
              negotiatedProtocol = secure.getProtocol();
            });
            secure.on("data", (secureChunk: Buffer) => {
              const text = secureChunk.toString("utf8");
              for (const secureLine of text.split("\r\n")) {
                if (secureLine === "") continue;
                const secureVerb = secureLine.slice(0, 4).toUpperCase();
                if (secureVerb === "EHLO") {
                  secure.write("250-fake.mx.test\r\n250 8BITMIME\r\n");
                } else if (secureVerb === "MAI") {
                  secure.write("250 2.1.0 Sender ok\r\n");
                } else if (secureVerb === "RCPT") {
                  secure.write("250 2.1.5 Recipient ok\r\n");
                } else if (secureVerb === "DATA") {
                  secure.write("354 End data\r\n");
                } else if (secureVerb === "QUIT") {
                  secure.write("221 2.0.0 Bye\r\n");
                  secure.end();
                }
              }
            });
            secure.on("error", () => undefined);
          });
        } else if (verb === "QUIT") {
          socket.write("221 2.0.0 Bye\r\n");
          socket.end();
        }
        index = pending.indexOf("\r\n");
      }
    });
    socket.on("error", () => undefined);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("The STARTTLS fake MX did not bind a TCP port");
  }
  return {
    port: address.port,
    upgraded: () => upgraded,
    protocol: () => negotiatedProtocol,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("STARTTLS negotiation and verification (R-TLS-2 … R-TLS-8)", () => {
  const fixture = selfSigned();

  it("attempts STARTTLS when the peer advertises it", async () => {
    if (!fixture) return;
    const mx = await startStarttlsMx(fixture);
    try {
      const client = new SmtpClient({
        host: "mx.fake.test",
        port: mx.port,
        address: "127.0.0.1",
        localDomain: "example.test",
        connectionTimeoutMs: 2000,
        commandTimeoutMs: 2000,
        tlsMode: "required",
        allowPlaintext: false,
      });
      await client.connect();
      const ehlo = await client.command("EHLO", "example.test");
      expect(ehlo.code).toBe(250);
      expect(client.capabilities?.starttls).toBe(true);

      const starttls = await client.command("STARTTLS");
      expect(starttls.code).toBe(220);

      // The handshake must fail: the self-signed certificate is untrusted
      // and the hostname does not match the trust store (R-TLS-4).
      await expect(client.upgradeToTls()).rejects.toThrow(/handshake failed/);
      expect(mx.upgraded()).toBe(true);
    } finally {
      await mx.close();
    }
  }, 20_000);

  it("never falls back to plaintext after a failed handshake (R-TLS-4)", async () => {
    if (!fixture) return;
    const mx = await startStarttlsMx(fixture);
    try {
      const client = new SmtpClient({
        host: "mx.fake.test",
        port: mx.port,
        address: "127.0.0.1",
        localDomain: "example.test",
        connectionTimeoutMs: 2000,
        commandTimeoutMs: 2000,
        // Opportunistic mode, but plaintext is NOT allowed: the failure must
        // be permanent and the session must not continue in the clear.
        tlsMode: "opportunistic",
        allowPlaintext: false,
      });
      await client.connect();
      await client.command("EHLO", "example.test");
      const starttls = await client.command("STARTTLS");
      expect(starttls.code).toBe(220);

      await expect(client.upgradeToTls()).rejects.toThrow();
      // The session is abandoned: no further command may be sent.
      expect(client.tlsMode).toBe("none");
    } finally {
      await mx.close();
    }
  }, 20_000);

  it("enforces TLS 1.2 as the minimum version", () => {
    // The constant is part of the contract: a TLS 1.0 or 1.1 peer must not
    // be accepted (R-TLS-3).
    expect(MIN_TLS_VERSION).toBe("TLSv1.2");
  });
});
