// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * Authentication and principal resolution (§3).
 *
 * Three mutually exclusive credential presentations are accepted:
 *
 * 1. API key — `Authorization: Bearer <api-key>` or `x-api-key: <api-key>`.
 * 2. JWT — `Authorization: Bearer <jwt>`, audience MUST be `/railgun`.
 * 3. Webhook HMAC — `X-RailGun-Signature` + `X-RailGun-Timestamp`, only on
 *    `POST /v1/events`.
 *
 * Resolution order is normative: ambiguity is rejected before verification, an
 * `x-api-key` header wins over a simultaneous `Authorization: Bearer` header
 * (the exact shape the frozen Jaisiu client sends), and the presented
 * credential is never echoed back.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { HttpError, unauthenticated } from "./errors.js";
import { normalizeScopes, type Principal } from "./types.js";

/** A stored API-key record. The plaintext key is never retained. */
export interface ApiKeyRecord {
  /** Stable identifier, e.g. `key_01J8…`. */
  id: string;
  tenant_id: string;
  /** Lookup prefix, e.g. `rgk_ab12`. */
  key_prefix: string;
  /** SHA-256 hash of the full key (constant-time comparable). */
  key_hash: string;
  scopes: string[];
  roles: string[];
  allowed_senders: string[];
  allowed_domains: string[];
  active: boolean;
  expires_at?: string | null;
}

/** The credential store port. */
export interface CredentialStore {
  /** Look up the candidate API-key record by its key-id prefix. */
  findByPrefix(prefix: string): Promise<ApiKeyRecord | null>;
}

/** JWT verification configuration. */
export interface JwtVerifier {
  /** Shared secret for HS256 tokens. */
  secret: string;
  /** Required audience. */
  audience: string;
  /** Clock skew tolerance in seconds. */
  clockToleranceSeconds?: number;
}

export interface AuthInput {
  headers: Record<string, string | string[] | undefined>;
  /** Raw request body — required for HMAC verification. */
  body: Buffer;
  method: string;
  path: string;
}

export interface AuthResult {
  principal: Principal;
  /** How the principal was authenticated. */
  kind: "api_key" | "jwt" | "hmac";
}

/** Header lookup helper (case-insensitive, first value). */
export function headerValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== lower) {
      continue;
    }
    if (Array.isArray(value)) {
      return value[0];
    }
    return value;
  }
  return undefined;
}

/** Shape classification of a bearer credential (§3.1 "Bearer disambiguation"). */
export function classifyBearer(credential: string): "jwt" | "api_key" | "unknown" {
  const parts = credential.split(".");
  if (parts.length === 3 && parts.every((part) => part.length > 0)) {
    return "jwt";
  }
  if (credential.startsWith("rgk_")) {
    return "api_key";
  }
  return "unknown";
}

/** Extract the API-key prefix used for record lookup. */
export function keyPrefix(credential: string): string {
  // `rgk_<id>_<secret>` — the id part is the lookup prefix.
  const withoutScheme = credential.startsWith("rgk_") ? credential.slice(4) : credential;
  const separator = withoutScheme.indexOf("_");
  return separator === -1 ? withoutScheme.slice(0, 12) : withoutScheme.slice(0, separator);
}

/** SHA-256 hex hash of an API key (the stored verifier). */
export function hashApiKey(credential: string): string {
  return createHash("sha256").update(credential, "utf8").digest("hex");
}

/** Constant-time comparison of two hex digests. */
export function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) {
    timingSafeEqual(Buffer.from(a), Buffer.from(a));
    return false;
  }
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Resolve the principal for an authenticated request.
 *
 * @throws {HttpError} `401 UNAUTHENTICATED` for a missing/invalid credential,
 * `400 AMBIGUOUS_AUTH` when both an API key and a JWT are presented.
 */
export async function authenticate(
  input: AuthInput,
  store: CredentialStore,
  jwt: JwtVerifier | null,
  now: Date,
): Promise<AuthResult> {
  const authorization = headerValue(input.headers, "authorization");
  const apiKeyHeader = headerValue(input.headers, "x-api-key");
  const bearer = extractBearer(authorization);

  // The `x-api-key` header wins when both are present: the frozen Jaisiu
  // client sends exactly that shape.
  if (apiKeyHeader) {
    const principal = await resolveApiKey(apiKeyHeader, store, now);
    return { principal, kind: "api_key" };
  }

  if (!bearer) {
    throw unauthenticated();
  }

  const shape = classifyBearer(bearer);
  if (shape === "unknown") {
    throw unauthenticated();
  }

  if (shape === "jwt") {
    if (!jwt) {
      throw unauthenticated();
    }
    const principal = verifyJwt(bearer, jwt, now);
    return { principal, kind: "jwt" };
  }

  const principal = await resolveApiKey(bearer, store, now);
  return { principal, kind: "api_key" };
}

/** Extract the credential from an `Authorization: Bearer …` header. */
export function extractBearer(authorization: string | undefined): string | undefined {
  if (!authorization) {
    return undefined;
  }
  const match = /^bearer\s+(.+)$/i.exec(authorization.trim());
  return match?.[1]?.trim() || undefined;
}

/** Resolve an API key to its principal. */
export async function resolveApiKey(
  credential: string,
  store: CredentialStore,
  now: Date,
): Promise<Principal> {
  const prefix = keyPrefix(credential);
  const record = await store.findByPrefix(prefix);
  if (!record) {
    throw unauthenticated();
  }
  if (!safeEqualHex(hashApiKey(credential), record.key_hash)) {
    throw unauthenticated();
  }
  if (!record.active) {
    throw unauthenticated();
  }
  if (record.expires_at && Date.parse(record.expires_at) <= now.getTime()) {
    throw unauthenticated();
  }
  return {
    id: record.id,
    tenant_id: record.tenant_id,
    kind: "api_key",
    scopes: normalizeScopes(record.scopes),
    roles: record.roles,
    allowed_senders: record.allowed_senders,
    allowed_domains: record.allowed_domains,
    active: record.active,
  };
}

interface JwtClaims {
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  tenant_id?: string;
  scopes?: string[];
  roles?: string[];
  allowed_senders?: string[];
}

/**
 * Verify an HS256 JWT.
 *
 * Only HS256 is accepted (algorithm allow-list). The audience MUST be
 * `/railgun`; a Jaisiu `/mcp` token is rejected with `401 UNAUTHENTICATED`.
 */
export function verifyJwt(token: string, verifier: JwtVerifier, now: Date): Principal {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw unauthenticated();
  }
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  let header: { alg?: string; typ?: string };
  try {
    header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8")) as {
      alg?: string;
    };
  } catch {
    throw unauthenticated();
  }
  if (header.alg !== "HS256") {
    throw unauthenticated();
  }
  const expected = createHmac("sha256", verifier.secret)
    .update(`${headerPart}.${payloadPart}`)
    .digest();
  const provided = Buffer.from(signaturePart, "base64url");
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    throw unauthenticated();
  }
  let claims: JwtClaims;
  try {
    claims = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8")) as JwtClaims;
  } catch {
    throw unauthenticated();
  }
  const tolerance = verifier.clockToleranceSeconds ?? 30;
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (typeof claims.exp === "number" && claims.exp + tolerance <= nowSeconds) {
    throw unauthenticated();
  }
  if (typeof claims.nbf === "number" && claims.nbf - tolerance > nowSeconds) {
    throw unauthenticated();
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
  if (!audiences.includes(verifier.audience)) {
    throw unauthenticated();
  }
  if (!claims.sub) {
    throw unauthenticated();
  }
  const tenant = claims.tenant_id;
  if (!tenant) {
    throw unauthenticated();
  }
  return {
    id: `jwt:${claims.sub}`,
    tenant_id: tenant,
    kind: "jwt",
    scopes: normalizeScopes(claims.scopes ?? []),
    roles: claims.roles ?? [],
    allowed_senders: claims.allowed_senders ?? [],
    allowed_domains: [],
    active: true,
  };
}

/**
 * Verify the webhook HMAC used by `POST /v1/events` (§7).
 *
 * The signature is `sha256=<hex>` over the raw request body; the timestamp
 * must be inside the replay window.
 */
export function verifyWebhookHmac(
  headers: Record<string, string | string[] | undefined>,
  body: Buffer,
  secret: string,
  now: Date,
  replayWindowSeconds = 300,
): void {
  const signature = headerValue(headers, "x-railgun-signature");
  const timestamp = headerValue(headers, "x-railgun-timestamp");
  if (!signature || !timestamp) {
    throw unauthenticated();
  }
  const timestampSeconds = Number(timestamp);
  if (!Number.isFinite(timestampSeconds)) {
    throw unauthenticated();
  }
  if (Math.abs(now.getTime() / 1000 - timestampSeconds) > replayWindowSeconds) {
    throw unauthenticated();
  }
  const provided = signature.startsWith("sha256=") ? signature.slice("sha256=".length) : signature;
  const expected = createHmac("sha256", secret).update(body).digest("hex");
  if (provided.length !== expected.length) {
    timingSafeEqual(Buffer.from(expected), Buffer.from(expected));
    throw unauthenticated();
  }
  if (!timingSafeEqual(Buffer.from(expected), Buffer.from(provided))) {
    throw unauthenticated();
  }
}

/** Build the error used when both an API key and a JWT are presented. */
export function ambiguousAuth(): HttpError {
  return new HttpError(400, "AMBIGUOUS_AUTH", "Present either an API key or a JWT, not both.");
}
