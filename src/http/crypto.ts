// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * Cryptographic helpers used by the HTTP surface: canonical request digests,
 * HMAC-signed pagination cursors, constant-time credential comparison and
 * tenant-scoped recipient pseudonymization.
 *
 * Only `node:crypto` is used — the package stays dependency-free.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

/** Lowercase hex SHA-256 digest. */
export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/**
 * Canonical SHA-256 digest of a JSON request body.
 *
 * The canonicalization sorts object keys recursively so that two bodies that
 * differ only in field ordering hash identically (§5.1 "Comparison").
 */
export function canonicalDigest(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}

/** Deterministic JSON serialization with sorted object keys. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value ?? null);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entry]) => entry !== undefined)
    .toSorted(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
    .join(",")}}`;
}

/** HMAC-SHA256 hex digest. */
export function hmacHex(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

/**
 * Constant-time string comparison. Returns `false` for differing lengths
 * without leaking the length through an early return of the comparison.
 */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    // Still perform a comparison so the timing does not depend on the content.
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

/** URL-safe base64 encoding without padding. */
export function base64UrlEncode(input: string): string {
  return Buffer.from(input, "utf8").toString("base64url");
}

/** URL-safe base64 decoding without padding. */
export function base64UrlDecode(input: string): string {
  return Buffer.from(input, "base64url").toString("utf8");
}

export interface SignedCursorPayload {
  /** ISO timestamp of the row the cursor points at. */
  ts: string;
  /** Row identifier. */
  id: string;
  /** Hash of the filter set the cursor is bound to. */
  f: string;
}

/**
 * Encode a signed, opaque pagination cursor.
 *
 * The cursor is bound to its filter set (§6.1): reusing it with different
 * filters yields `400 INVALID_CURSOR`.
 */
export function encodeCursor(secret: string, payload: SignedCursorPayload): string {
  const body = base64UrlEncode(JSON.stringify(payload));
  const signature = hmacHex(secret, body).slice(0, 32);
  return `${body}.${signature}`;
}

/** Decode and verify a signed cursor. Returns `null` for tampered payloads. */
export function decodeCursor(
  secret: string,
  cursor: string,
): { ts: string; id: string; f: string } | null {
  const parts = cursor.split(".");
  if (parts.length !== 2) {
    return null;
  }
  const [body, signature] = parts;
  if (!body || !signature) {
    return null;
  }
  const expected = hmacHex(secret, body).slice(0, 32);
  if (!safeEqual(expected, signature)) {
    return null;
  }
  try {
    const parsed = JSON.parse(base64UrlDecode(body)) as Partial<SignedCursorPayload>;
    if (typeof parsed.ts !== "string" || typeof parsed.id !== "string" || typeof parsed.f !== "string") {
      return null;
    }
    return { ts: parsed.ts, id: parsed.id, f: parsed.f };
  } catch {
    return null;
  }
}

/**
 * Tenant-scoped pseudonymization of a recipient address (anti-spam IR §13).
 *
 * The HMAC key is tenant-scoped, so the same address hashes differently for
 * different tenants and the hash cannot be reversed with a global word list.
 */
export function recipientHash(tenantSecret: string, email: string): string {
  return `sha256:${hmacHex(tenantSecret, email.trim().toLowerCase())}`;
}
