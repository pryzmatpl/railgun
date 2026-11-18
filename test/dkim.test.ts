// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// DKIM signing and independent verification (V-1, V-2, V-3).

import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  DEFAULT_SIGN_HEADERS,
  bodyHash,
  keyFingerprint,
  signDkim,
  validateKey,
  verifyDkim,
  type DkimSignInput,
} from "../src/signer/dkim.js";
import {
  canonicalizeBody,
  canonicalizeHeaderSet,
  parseHeaderBlock,
} from "../src/signer/canonicalization.js";

const RSA_KEY = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const ED25519_KEY = generateKeyPairSync("ed25519", {
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const HEADERS = [
  { name: "From", value: "Alice <alice@example.com>" },
  { name: "To", value: "bob@example.org" },
  { name: "Subject", value: "Hello" },
  { name: "Date", value: "Tue, 18 Nov 2026 11:00:00 +0000" },
  { name: "Message-ID", value: "<abc123@example.com>" },
];

function signInput(overrides: Partial<DkimSignInput> = {}): DkimSignInput {
  return {
    headers: HEADERS,
    body: "Hello there.\r\n",
    domain: "example.com",
    selector: "railgun1",
    algorithm: "rsa-sha256",
    private_key_pem: RSA_KEY.privateKey,
    canonicalization: { header: "relaxed", body: "relaxed" },
    timestamp: 1_800_000_000,
    sign_headers: DEFAULT_SIGN_HEADERS,
    ...overrides,
  };
}

describe("DKIM signing", () => {
  it("signs and independently verifies an RSA-SHA256 message (V-1)", () => {
    const result = signDkim(signInput());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.algorithm).toBe("rsa-sha256");
    expect(result.signature_header).toContain("DKIM-Signature:");
    expect(result.signature_header).toContain("a=rsa-sha256");
    expect(result.signature_header).toContain("d=example.com");
    expect(result.signature_header).toContain("s=railgun1");

    const raw = `${result.signature_header}\r\n${HEADERS.map((h) => `${h.name}: ${h.value}`).join("\r\n")}\r\n\r\nHello there.\r\n`;
    const verified = verifyDkim(raw, RSA_KEY.publicKey);
    expect(verified.ok).toBe(true);
  });

  it("signs and independently verifies an ed25519 message (V-1)", () => {
    const result = signDkim(
      signInput({
        algorithm: "ed25519",
        private_key_pem: ED25519_KEY.privateKey,
      }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.algorithm).toBe("ed25519");

    const raw = `${result.signature_header}\r\n${HEADERS.map((h) => `${h.name}: ${h.value}`).join("\r\n")}\r\n\r\nHello there.\r\n`;
    const verified = verifyDkim(raw, ED25519_KEY.publicKey);
    expect(verified.ok).toBe(true);
  });

  it("fails to verify when the body is modified (V-1)", () => {
    const result = signDkim(signInput());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const raw = `${result.signature_header}\r\n${HEADERS.map((h) => `${h.name}: ${h.value}`).join("\r\n")}\r\n\r\nTampered.\r\n`;
    const verified = verifyDkim(raw, RSA_KEY.publicKey);
    expect(verified.ok).toBe(false);
    if (!verified.ok) {
      expect(verified.reason).toBe("body_hash_mismatch");
    }
  });

  it("fails to verify against the wrong public key (V-1)", () => {
    const other = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const result = signDkim(signInput());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const raw = `${result.signature_header}\r\n${HEADERS.map((h) => `${h.name}: ${h.value}`).join("\r\n")}\r\n\r\nHello there.\r\n`;
    const verified = verifyDkim(raw, other.publicKey);
    expect(verified.ok).toBe(false);
  });

  it("is deterministic: the same message re-signed yields an identical signature (V-3)", () => {
    const first = signDkim(signInput());
    const second = signDkim(signInput());
    expect(first.ok && second.ok).toBe(true);
    if (!first.ok || !second.ok) {
      return;
    }
    expect(first.signature).toBe(second.signature);
    expect(first.signature_header).toBe(second.signature_header);
  });

  it("rejects an RSA key below 2048 bits (R-7.1.1)", () => {
    const weak = generateKeyPairSync("rsa", {
      modulusLength: 1024,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const validation = validateKey(weak.privateKey, "rsa-sha256");
    expect(validation.ok).toBe(false);
    const result = signDkim(signInput({ private_key_pem: weak.privateKey }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason_code).toBe("DKIM_KEY_UNAVAILABLE");
    }
  });

  it("reports DKIM_SIGN_FAILED when no header can be signed (R-7.1.7)", () => {
    const result = signDkim(signInput({ sign_headers: ["x-nonexistent"] }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason_code).toBe("DKIM_SIGN_FAILED");
    }
  });

  it("never exposes the private key in the signature header (R-7.1.3)", () => {
    const result = signDkim(signInput());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.signature_header).not.toContain("PRIVATE KEY");
    expect(result.key_fingerprint).toMatch(/^[0-9a-f]{40}$/);
  });

  it("produces a stable public-key fingerprint (R-7.1.3)", () => {
    const a = keyFingerprint(RSA_KEY.publicKey);
    const b = keyFingerprint(RSA_KEY.publicKey);
    expect(a).toBe(b);
    expect(a).not.toContain("PRIVATE");
  });
});

describe("DKIM canonicalization (V-2)", () => {
  it("relaxed header canonicalization lowercases the name and collapses whitespace", () => {
    const canonical = canonicalizeHeaderSet(
      [{ name: "Subject", value: "  Hello   there  " }],
      "relaxed",
    );
    expect(canonical).toBe("subject:Hello there");
  });

  it("simple header canonicalization preserves the original spelling", () => {
    const canonical = canonicalizeHeaderSet(
      [{ name: "Subject", value: "  Hello   there  " }],
      "simple",
    );
    expect(canonical).toBe("Subject:  Hello   there  ");
  });

  it("unfolds a folded header before canonicalizing (V-2)", () => {
    const headers = parseHeaderBlock("Subject: Hello\r\n there\r\nTo: bob@example.org\r\n");
    expect(headers).toHaveLength(2);
    expect(headers[0]?.value).toBe("Hello there");
  });

  it("relaxed body canonicalization strips trailing whitespace and ends with one CRLF", () => {
    const canonical = canonicalizeBody("line one   \r\nline two\t\r\n\r\n", "relaxed");
    expect(canonical).toBe("line one\r\nline two\r\n");
  });

  it("simple body canonicalization preserves the bytes", () => {
    const canonical = canonicalizeBody("line one   \r\n", "simple");
    expect(canonical).toBe("line one   ");
  });

  it("relaxed body canonicalization of an empty body is a single CRLF", () => {
    expect(canonicalizeBody("", "relaxed")).toBe("\r\n");
  });

  it("computes a stable body hash (V-2)", () => {
    const a = bodyHash("hello\r\n", { header: "relaxed", body: "relaxed" });
    const b = bodyHash("hello\r\n", { header: "relaxed", body: "relaxed" });
    expect(a).toBe(b);
    expect(a).not.toBe(bodyHash("hello2\r\n", { header: "relaxed", body: "relaxed" }));
  });

  it("signs and verifies a message with trailing whitespace and a folded header (V-2)", () => {
    const headers = parseHeaderBlock(
      "From: alice@example.com\r\nTo: bob@example.org\r\nSubject: a folded\r\n subject line\r\nDate: Tue, 18 Nov 2026 11:00:00 +0000\r\nMessage-ID: <x@example.com>\r\n",
    );
    const result = signDkim(
      signInput({ headers, body: "trailing spaces   \r\n" }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const raw = `${result.signature_header}\r\n${headers.map((h) => `${h.name}: ${h.value}`).join("\r\n")}\r\n\r\ntrailing spaces   \r\n`;
    expect(verifyDkim(raw, RSA_KEY.publicKey).ok).toBe(true);
  });

  it("signs and verifies with simple/simple canonicalization (V-2)", () => {
    const result = signDkim(
      signInput({ canonicalization: { header: "simple", body: "simple" } }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const raw = `${result.signature_header}\r\n${HEADERS.map((h) => `${h.name}: ${h.value}`).join("\r\n")}\r\n\r\nHello there.\r\n`;
    expect(verifyDkim(raw, RSA_KEY.publicKey).ok).toBe(true);
  });
});
