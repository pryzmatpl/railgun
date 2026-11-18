// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * CLI integration tests for `railgun dkim new`.
 *
 * The command is the operator's entry point for self-hosting a sending
 * domain: it generates the keypair and prints the DNS records to publish.
 * The tests therefore check three things that matter operationally:
 *
 * 1. The private key is written with `0600` and is never printed.
 * 2. The published `p=` value is a **valid** RFC 6376 public key. A `p=`
 *    value that no receiving verifier accepts is worse than no record at
 *    all, because it makes every message look DKIM-signed and fail.
 * 3. The SPF record lists exactly the supplied addresses and appears once.
 */
import { createPublicKey } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { runCli, withTempDir } from "./helpers.js";

/**
 * Parse a DKIM `p=` value into its DER components.
 *
 * RFC 6376 §3.6.2 defines `p=` as the base64 of the DER-encoded public
 * key. For RSA that is `RSAPublicKey`, which is a SEQUENCE of an INTEGER
 * modulus and an INTEGER public exponent — *not* the `SubjectPublicKeyInfo`
 * that `openssl pkey -pubout` emits.
 */
function parseRsaPublicKey(base64Value: string): { modulus: Buffer; exponent: Buffer } {
  const der = Buffer.from(base64Value, "base64");
  expect(der[0]).toBe(0x30); // SEQUENCE

  /** Read a DER length at `offset`, honouring the long form. */
  const readLength = (buffer: Buffer, at: number): { length: number; next: number } => {
    const first = buffer[at];
    if ((first & 0x80) === 0) {
      return { length: first, next: at + 1 };
    }
    const count = first & 0x7f;
    let value = 0;
    for (let index = 1; index <= count; index += 1) {
      value = value * 256 + buffer[at + index];
    }
    return { length: value, next: at + 1 + count };
  };

  let offset = readLength(der, 1).next;

  expect(der[offset]).toBe(0x02); // INTEGER modulus
  const modulusLength = readLength(der, offset + 1);
  const modulus = der.subarray(modulusLength.next, modulusLength.next + modulusLength.length);
  offset = modulusLength.next + modulusLength.length;

  expect(der[offset]).toBe(0x02); // INTEGER exponent
  const exponentLength = readLength(der, offset + 1);
  const exponent = der.subarray(
    exponentLength.next,
    exponentLength.next + exponentLength.length,
  );

  return { modulus, exponent };
}

describe("railgun dkim new", () => {
  it("generates a keypair and prints every record to publish", async () => {
    await withTempDir(async (dir) => {
      const privateKeyPath = path.join(dir, "dkim.pem");
      const publicKeyPath = path.join(dir, "dkim.pub.pem");
      const result = await runCli([
        "dkim",
        "new",
        "--domain",
        "example.com",
        "--selector",
        "mail",
        "--ipv4",
        "203.0.113.10",
        "--private-key-path",
        privateKeyPath,
        "--public-key-path",
        publicKeyPath,
      ]);

      expect(result.code).toBe(0);
      expect(result.stdout).toContain("example.com");
      // The MX record.
      expect(result.stdout).toContain("MX");
      expect(result.stdout).toContain("10 mail.example.com.");
      // The SPF record.
      expect(result.stdout).toContain("v=spf1 ip4:203.0.113.10 ~all");
      // The DKIM record.
      expect(result.stdout).toContain("mail._domainkey.example.com");
      expect(result.stdout).toContain("v=DKIM1; k=rsa; p=");
      // The DMARC record.
      expect(result.stdout).toContain("_dmarc.example.com");
      expect(result.stdout).toContain("v=DMARC1; p=none;");
    });
  });

  it("writes the private key with 0600 and never prints it", async () => {
    await withTempDir(async (dir) => {
      const privateKeyPath = path.join(dir, "dkim.pem");
      const publicKeyPath = path.join(dir, "dkim.pub.pem");
      const result = await runCli([
        "dkim",
        "new",
        "--domain",
        "example.com",
        "--selector",
        "mail",
        "--private-key-path",
        privateKeyPath,
        "--public-key-path",
        publicKeyPath,
      ]);

      expect(result.code).toBe(0);
      const mode = statSync(privateKeyPath).mode & 0o777;
      expect(mode).toBe(0o600);

      // The private key body must not appear anywhere in the output.
      const privatePem = readFileSync(privateKeyPath, "utf8");
      const body = privatePem
        .replace(/-----[^-]+-----/g, "")
        .replace(/\s+/g, "")
        .slice(0, 40);
      expect(result.stdout).not.toContain(body);
      expect(result.stderr).not.toContain(body);
    });
  });

  it("publishes a p= value that reconstructs a valid RSA public key", async () => {
    await withTempDir(async (dir) => {
      const privateKeyPath = path.join(dir, "dkim.pem");
      const publicKeyPath = path.join(dir, "dkim.pub.pem");
      const result = await runCli([
        "dkim",
        "new",
        "--domain",
        "example.com",
        "--selector",
        "mail",
        "--private-key-path",
        privateKeyPath,
        "--public-key-path",
        publicKeyPath,
      ]);

      const match = /p=([A-Za-z0-9+/=]+)/.exec(result.stdout);
      expect(match).not.toBeNull();
      const pValue = match![1];

      // The value must decode as an RSAPublicKey: a SEQUENCE holding a
      // 2048-bit modulus and a small public exponent.
      const { modulus, exponent } = parseRsaPublicKey(pValue);
      expect(modulus.length).toBe(257); // 256 bytes plus the DER sign byte
      expect(modulus[0]).toBe(0x00); // DER keeps the modulus positive
      expect(exponent.length).toBe(3);
      expect(exponent.toString("hex")).toBe("010001"); // 65537

      // And the published key must be the one in the generated public key
      // file: wrap the RSAPublicKey back into an SPKI and load it.
      const der = Buffer.from(pValue, "base64");
      const algorithm = Buffer.from("300d06092a864886f70d0101010500", "hex");
      // BIT STRING: tag, content length, the unused-bits count, then the
      // payload. The length covers the unused-bits byte as well, and an RSA
      // key needs the DER long form.
      const bitStringContent = Buffer.concat([Buffer.from([0x00]), der]);
      const bitString = Buffer.concat([
        Buffer.from([0x03, 0x82, (bitStringContent.length >> 8) & 0xff, bitStringContent.length & 0xff]),
        bitStringContent,
      ]);
      const spkiBody = Buffer.concat([algorithm, bitString]);
      const spki = Buffer.concat([
        Buffer.from([0x30]),
        // The outer length needs the long form whenever the body exceeds 127
        // bytes, which an RSA key always does.
        Buffer.from([0x82, (spkiBody.length >> 8) & 0xff, spkiBody.length & 0xff]),
        spkiBody,
      ]);
      const key = createPublicKey({ key: spki, format: "der", type: "spki" });
      expect(key.asymmetricKeyType).toBe("rsa");
      const details = key.asymmetricKeyDetails;
      expect(details?.modulusLength).toBe(2048);
    });
  });

  it("lists every SPF-authorized address and emits a single SPF record", async () => {
    await withTempDir(async (dir) => {
      const result = await runCli([
        "dkim",
        "new",
        "--domain",
        "example.com",
        "--selector",
        "mail",
        "--ipv4",
        "203.0.113.10",
        "--ipv6",
        "2001:db8::10",
        "--private-key-path",
        path.join(dir, "dkim.pem"),
        "--public-key-path",
        path.join(dir, "dkim.pub.pem"),
      ]);

      expect(result.stdout).toContain("v=spf1 ip4:203.0.113.10 ip6:2001:db8::10 ~all");
      // Exactly one SPF *record*. The explanatory prose also mentions
      // `v=spf1`, so count only the record lines, which start with the
      // record value itself.
      const spfRecords = result.stdout
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.startsWith("v=spf1 "));
      expect(spfRecords).toHaveLength(1);
    });
  });

  it("refuses a missing domain and an invalid address", async () => {
    await withTempDir(async (dir) => {
      const missing = await runCli(["dkim", "new", "--selector", "mail"]);
      expect(missing.code).toBe(2);

      const invalid = await runCli([
        "dkim",
        "new",
        "--domain",
        "example.com",
        "--selector",
        "mail",
        "--ipv4",
        "999.1.1.1",
        "--private-key-path",
        path.join(dir, "a.pem"),
        "--public-key-path",
        path.join(dir, "a.pub.pem"),
      ]);
      expect(invalid.code).toBe(2);
    });
  });

  it("refuses to overwrite an existing private key", async () => {
    await withTempDir(async (dir) => {
      const privateKeyPath = path.join(dir, "dkim.pem");
      const publicKeyPath = path.join(dir, "dkim.pub.pem");
      const args = [
        "dkim",
        "new",
        "--domain",
        "example.com",
        "--selector",
        "mail",
        "--private-key-path",
        privateKeyPath,
        "--public-key-path",
        publicKeyPath,
      ];
      const first = await runCli(args);
      expect(first.code).toBe(0);

      const second = await runCli(args);
      expect(second.code).toBe(2);
      expect(second.stderr).toContain("already exists");
    });
  });

  it("emits a single JSON document with the records", async () => {
    await withTempDir(async (dir) => {
      const result = await runCli([
        "--json",
        "dkim",
        "new",
        "--domain",
        "example.com",
        "--selector",
        "mail",
        "--private-key-path",
        path.join(dir, "dkim.pem"),
        "--public-key-path",
        path.join(dir, "dkim.pub.pem"),
      ]);

      expect(result.code).toBe(0);
      const parsed = JSON.parse(result.stdout) as {
        domain: string;
        selector: string;
        algorithm: string;
        records: { name: string; type: string; value: string }[];
      };
      expect(parsed.domain).toBe("example.com");
      expect(parsed.selector).toBe("mail");
      expect(parsed.algorithm).toBe("rsa-sha256");
      // Without an address there is no A record, so three records remain:
      // MX, the DKIM public key and DMARC.
      expect(parsed.records.map((record) => record.type)).toEqual(["MX", "TXT", "TXT"]);
      expect(parsed.records.some((record) => record.type === "TXT")).toBe(true);
    });
  });
});
