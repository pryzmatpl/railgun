// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// DKIM signing and independent verification (RFC 6376).
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §7.1
// (R-7.1.1 – R-7.1.9) and verification obligations V-1, V-2, V-3.
//
// Signing is fail-closed: a missing key yields `DKIM_KEY_UNAVAILABLE` and a
// signing error yields `DKIM_SIGN_FAILED`. There is no path that emits an
// unsigned message (IR R-7.1.7).

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSign,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import {
  canonicalizeBody,
  canonicalizeHeaderSet,
  type Canonicalization,
  type RawHeader,
} from "./canonicalization.js";

/** The algorithms RailGun supports (IR R-7.1.1). */
export type DkimAlgorithm = "rsa-sha256" | "ed25519";

/** The minimum RSA key size RailGun accepts (IR R-7.1.1). */
export const RSA_MIN_BITS = 2048;

/** The result of a DKIM signing attempt. */
export type DkimSignResult =
  | {
      readonly ok: true;
      /** The complete `DKIM-Signature:` header value, without a trailing CRLF. */
      readonly signature_header: string;
      /** The signature body (base64), for tests and audit correlation. */
      readonly signature: string;
      /** SHA-256 of the public key — safe to log, never the key itself. */
      readonly key_fingerprint: string;
      readonly algorithm: DkimAlgorithm;
    }
  | {
      readonly ok: false;
      /** `DKIM_KEY_UNAVAILABLE` or `DKIM_SIGN_FAILED` (IR R-7.1.7). */
      readonly reason_code: "DKIM_KEY_UNAVAILABLE" | "DKIM_SIGN_FAILED";
      readonly error: string;
    };

/** The result of an independent DKIM verification. */
export type DkimVerifyResult =
  | { readonly ok: true; readonly algorithm: DkimAlgorithm }
  | {
      readonly ok: false;
      /** Short, stable reason for the failure. */
      readonly reason:
        | "missing_signature"
        | "malformed_signature"
        | "unsupported_algorithm"
        | "body_hash_mismatch"
        | "signature_mismatch"
        | "bad_public_key";
      readonly detail?: string;
    };

/** The inputs to a signing operation. */
export interface DkimSignInput {
  /** The raw header block of the message, in transmission order. */
  readonly headers: readonly RawHeader[];
  /** The raw body of the message. */
  readonly body: string;
  /** The signing domain (`d=`). */
  readonly domain: string;
  /** The selector (`s=`). */
  readonly selector: string;
  /** The algorithm to use. */
  readonly algorithm: DkimAlgorithm;
  /** The private key PEM (RSA) or base64 raw key (ed25519). */
  readonly private_key_pem: string;
  /** The canonicalization pair. */
  readonly canonicalization: Canonicalization;
  /** The signing timestamp, in seconds since the epoch. */
  readonly timestamp: number;
  /**
   * The headers to sign, lower-cased. Must include at least `from`, `to`,
   * `subject`, `date` and `message-id` (IR R-7.1.5).
   */
  readonly sign_headers: readonly string[];
}

/**
 * The default signed header set (IR R-7.1.5). `bcc` is never signed.
 */
export const DEFAULT_SIGN_HEADERS: readonly string[] = Object.freeze([
  "from",
  "to",
  "subject",
  "date",
  "message-id",
  "reply-to",
]);

/**
 * Computes the public-key fingerprint used for audit and `doctor` output.
 * This is a hash of the **public** key, so it is safe to print (IR R-7.1.3).
 */
export function keyFingerprint(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  const der = key.export({ type: "spki", format: "der" }) as Buffer;
  return createHash("sha256").update(der).digest("hex").slice(0, 40);
}

/**
 * Checks that a private key is usable: RSA keys must be at least
 * `RSA_MIN_BITS` (IR R-7.1.1), and the key type must match the algorithm.
 */
export function validateKey(
  privateKeyPem: string,
  algorithm: DkimAlgorithm,
): { ok: true } | { ok: false; error: string } {
  let key;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch (error) {
    return { ok: false, error: `unreadable_private_key: ${(error as Error).message}` };
  }
  if (algorithm === "rsa-sha256") {
    if (key.asymmetricKeyType !== "rsa") {
      return { ok: false, error: `expected_rsa_key_got_${key.asymmetricKeyType}` };
    }
    const details = key.asymmetricKeyDetails;
    const bits = details?.modulusLength ?? 0;
    if (bits < RSA_MIN_BITS) {
      return { ok: false, error: `rsa_key_too_small_${bits}` };
    }
    return { ok: true };
  }
  if (key.asymmetricKeyType !== "ed25519") {
    return { ok: false, error: `expected_ed25519_key_got_${key.asymmetricKeyType}` };
  }
  return { ok: true };
}

/**
 * Builds the DKIM `h=` tag: the lower-cased names of the headers actually
 * signed, in the order they are signed.
 */
function buildHeaderTag(
  headers: readonly RawHeader[],
  signHeaders: readonly string[],
): { tag: string; selected: RawHeader[] } {
  const byName = new Map<string, RawHeader[]>();
  for (const header of headers) {
    const name = header.name.toLowerCase();
    const list = byName.get(name);
    if (list) {
      list.push(header);
    } else {
      byName.set(name, [header]);
    }
  }

  const selected: RawHeader[] = [];
  const names: string[] = [];
  for (const requested of signHeaders) {
    const name = requested.toLowerCase();
    const candidates = byName.get(name);
    if (candidates === undefined || candidates.length === 0) {
      continue;
    }
    // Sign the bottom-most occurrence of a repeated header.
    const picked = candidates[candidates.length - 1];
    if (picked !== undefined) {
      selected.push(picked);
      names.push(name);
    }
  }
  return { tag: names.join(":"), selected };
}

/**
 * Computes the body hash for the `b=` tag.
 */
export function bodyHash(body: string, canonicalization: Canonicalization): string {
  const canonical = canonicalizeBody(body, canonicalization.body);
  return createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("base64");
}

/**
 * Signs a message, producing the `DKIM-Signature:` header.
 *
 * Signing is deterministic for a given (canonical MIME, key, domain,
 * selector, timestamp) — the timestamp is supplied by the caller so that a
 * crash-and-retry reuses the stored value and produces an identical
 * signature (IR R-7.1.6, V-3).
 */
export function signDkim(input: DkimSignInput): DkimSignResult {
  const validation = validateKey(input.private_key_pem, input.algorithm);
  if (!validation.ok) {
    return {
      ok: false,
      reason_code: "DKIM_KEY_UNAVAILABLE",
      error: validation.error,
    };
  }

  const { tag: hTag, selected } = buildHeaderTag(input.headers, input.sign_headers);
  if (selected.length === 0) {
    return {
      ok: false,
      reason_code: "DKIM_SIGN_FAILED",
      error: "no_headers_selected_for_signing",
    };
  }

  const bTag = bodyHash(input.body, input.canonicalization);

  const tagList = [
    "v=1",
    `a=${input.algorithm}`,
    `c=${input.canonicalization.header}/${input.canonicalization.body}`,
    `d=${input.domain.toLowerCase()}`,
    `s=${input.selector}`,
    `t=${input.timestamp}`,
    `h=${hTag}`,
    `bh=${bTag}`,
  ];

  // The `b=` value is empty while the signature is computed. The tag order and
  // spelling here MUST match the verifier's reconstruction exactly.
  const signatureBase = `${tagList.join("; ")}; b=`;

  const headerCanonical = canonicalizeHeaderSet(selected, input.canonicalization.header);
  const bodyCanonical = canonicalizeBody(input.body, input.canonicalization.body);
  // RFC 6376 §3.7: the signed data is the DKIM-Signature header (with an
  // empty `b=` value), a CRLF, the canonicalized signed headers, a CRLF, and
  // the canonicalized body.
  const signedData = Buffer.concat([
    Buffer.from(`${signatureBase}\r\n`, "utf8"),
    Buffer.from(`${headerCanonical}\r\n`, "utf8"),
    Buffer.from(bodyCanonical, "utf8"),
  ]);

  let signature: string;
  try {
    const key = createPrivateKey(input.private_key_pem);
    if (input.algorithm === "rsa-sha256") {
      const signer = createSign("sha256");
      signer.update(signedData);
      signer.end();
      signature = signer.sign(key, "base64");
    } else {
      // Node's Ed25519 `sign` already emits the raw 64-byte signature that
      // RFC 6376 §3.3.2 expects, so no DER unwrapping is needed. It is
      // base64-encoded here because the `b=` tag carries base64 text.
      const raw = cryptoSign(null, signedData, { key }) as unknown as Buffer;
      signature = raw.toString("base64");
    }
  } catch (error) {
    return {
      ok: false,
      reason_code: "DKIM_SIGN_FAILED",
      error: `signing_failed: ${(error as Error).message}`,
    };
  }

  const fullTagList = [...tagList, `b=${signature}`];
  const signatureHeader = `DKIM-Signature: ${fullTagList.join("; ")}`;

  let fingerprint = "";
  try {
    const publicKey = createPublicKey(createPrivateKey(input.private_key_pem));
    fingerprint = keyFingerprint(publicKey.export({ type: "spki", format: "pem" }) as string);
  } catch {
    fingerprint = "";
  }

  return {
    ok: true,
    signature_header: signatureHeader,
    signature,
    key_fingerprint: fingerprint,
    algorithm: input.algorithm,
  };
}

/**
 * Independently verifies a `DKIM-Signature` against the raw message and the
 * published public key (IR R-7.1.9, V-1).
 *
 * The verifier re-derives the body hash and the signed header set from the
 * raw bytes; it never trusts a digest stored elsewhere.
 */
export function verifyDkim(
  rawMessage: string,
  publicKeyPem: string,
): DkimVerifyResult {
  const separator = rawMessage.indexOf("\r\n\r\n");
  const headerBlock = separator >= 0 ? rawMessage.slice(0, separator) : rawMessage;
  const body = separator >= 0 ? rawMessage.slice(separator + 4) : "";

  const headers = parseHeaderBlockSafe(headerBlock);
  const signatureHeader = headers.find(
    (h) => h.name.toLowerCase() === "dkim-signature",
  );
  if (signatureHeader === undefined) {
    return { ok: false, reason: "missing_signature" };
  }

  const tags = parseTags(signatureHeader.value);
  const bValue = tags.get("b");
  if (bValue === undefined || bValue.length === 0) {
    return { ok: false, reason: "malformed_signature" };
  }

  const algorithm = tags.get("a") ?? "rsa-sha256";
  if (algorithm !== "rsa-sha256" && algorithm !== "ed25519") {
    return { ok: false, reason: "unsupported_algorithm" };
  }

  const canonicalization = parseCanonicalization(tags.get("c"));
  const hList = (tags.get("h") ?? "")
    .split(":")
    .map((n) => n.trim().toLowerCase())
    .filter((n) => n.length > 0);
  if (hList.length === 0) {
    return { ok: false, reason: "malformed_signature" };
  }

  const expectedBodyHash = bodyHash(body, canonicalization);
  if (expectedBodyHash !== tags.get("bh")) {
    return { ok: false, reason: "body_hash_mismatch" };
  }

  const selected = selectSignedHeaders(headers, hList);
  if (selected === null) {
    return { ok: false, reason: "malformed_signature" };
  }

  // Rebuild the signed data: the DKIM-Signature header with an empty `b=`
  // value, then the canonicalized signed headers, then the canonical body.
  const tagEntries = parseTagEntries(signatureHeader.value);
  const baseTags = tagEntries.filter((entry) => entry.name !== "b");
  const baseTagString = baseTags.map((entry) => `${entry.name}=${entry.value}`).join("; ");
  const signatureBase = `${baseTagString}; b=`;

  const headerCanonical = canonicalizeHeaderSet(selected, canonicalization.header);
  const bodyCanonical = canonicalizeBody(body, canonicalization.body);
  const signedData = Buffer.concat([
    Buffer.from(`${signatureBase}\r\n`, "utf8"),
    Buffer.from(`${headerCanonical}\r\n`, "utf8"),
    Buffer.from(bodyCanonical, "utf8"),
  ]);

  let key;
  try {
    key = createPublicKey(publicKeyPem);
  } catch (error) {
    return {
      ok: false,
      reason: "bad_public_key",
      detail: (error as Error).message,
    };
  }

  let valid = false;
  try {
    if (algorithm === "rsa-sha256") {
      valid = cryptoVerify("sha256", signedData, key, Buffer.from(bValue, "base64"));
    } else {
      valid = cryptoVerify(null, signedData, key, Buffer.from(bValue, "base64"));
    }
  } catch {
    valid = false;
  }

  if (!valid) {
    return { ok: false, reason: "signature_mismatch" };
  }
  return { ok: true, algorithm };
}

/**
 * Parses a raw header block without importing the signer's module-level
 * helpers, so the verifier stays independent of the signer's internals
 * (IR R-7.1.9).
 */
function parseHeaderBlockSafe(raw: string): RawHeader[] {
  const headers: RawHeader[] = [];
  let current: string[] = [];
  const flush = (): void => {
    if (current.length === 0) {
      return;
    }
    const joined = current.join("").replace(/\r?\n[ \t]+/g, "");
    const idx = joined.indexOf(":");
    if (idx > 0) {
      headers.push({ name: joined.slice(0, idx), value: joined.slice(idx + 1).trim() });
    }
    current = [];
  };
  for (const line of raw.split(/\r?\n/)) {
    if (line.length === 0) {
      break;
    }
    if (/^[ \t]/.test(line) && current.length > 0) {
      current.push(line);
      continue;
    }
    flush();
    current = [line];
  }
  flush();
  return headers;
}

/** Parses a `name=value` tag list into a map. */
function parseTags(value: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const entry of parseTagEntries(value)) {
    map.set(entry.name, entry.value);
  }
  return map;
}

/** Parses a `name=value` tag list into ordered entries. */
function parseTagEntries(value: string): { name: string; value: string }[] {
  const entries: { name: string; value: string }[] = [];
  for (const part of value.split(";")) {
    const trimmed = part.trim();
    if (trimmed.length === 0) {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq <= 0) {
      continue;
    }
    entries.push({
      name: trimmed.slice(0, eq).trim().toLowerCase(),
      value: trimmed.slice(eq + 1).trim(),
    });
  }
  return entries;
}

/** Parses the `c=` tag into a canonicalization pair. */
function parseCanonicalization(value: string | undefined): Canonicalization {
  const [headerRaw, bodyRaw] = (value ?? "relaxed/relaxed").split("/");
  const header = headerRaw === "simple" ? "simple" : "relaxed";
  const body = bodyRaw === "simple" ? "simple" : "relaxed";
  return { header, body };
}

/**
 * Selects the headers named in the `h=` tag, bottom-up for repeats.
 */
function selectSignedHeaders(
  headers: readonly RawHeader[],
  hList: readonly string[],
): RawHeader[] | null {
  const byName = new Map<string, RawHeader[]>();
  for (const header of headers) {
    const name = header.name.toLowerCase();
    const list = byName.get(name);
    if (list) {
      list.push(header);
    } else {
      byName.set(name, [header]);
    }
  }
  const selected: RawHeader[] = [];
  for (const name of hList) {
    const candidates = byName.get(name);
    if (candidates === undefined || candidates.length === 0) {
      return null;
    }
    const picked = candidates[candidates.length - 1];
    if (picked !== undefined) {
      selected.push(picked);
    }
  }
  return selected;
}
