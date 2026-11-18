// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * Principal/tenant model and authorization for the RailGun MCP surface
 * (IR §7).
 *
 * - Exactly one credential path per request; an ambiguous bearer is rejected
 *   with `AMBIGUOUS_AUTH` rather than silently picking one.
 * - Missing / malformed / expired / unknown credentials fail closed with
 *   `UNAUTHENTICATED` and never disclose whether the account exists.
 * - The effective tenant is derived only from the authenticated principal. A
 *   request can never select or override another tenant.
 * - Scopes are additive; `admin` does not imply `send`.
 */

import { createHash, timingSafeEqual } from "node:crypto";

import { RailGunError } from "./errors.js";

export const RAILGUN_SCOPES = ["send", "read", "admin", "feedback"] as const;
export type RailGunScope = (typeof RAILGUN_SCOPES)[number];

export const RAILGUN_ROLES = ["admin", "operator", "sender", "auditor"] as const;
export type RailGunRole = (typeof RAILGUN_ROLES)[number];

export interface Principal {
  readonly principalId: string;
  readonly tenantId: string;
  readonly roles: readonly RailGunRole[];
  readonly scopes: readonly RailGunScope[];
  /** Admin-only capability permitting a `from` override. */
  readonly senderOverride: boolean;
  /** Explicit grant permitting message-body reads. Default deny. */
  readonly bodyRead: boolean;
  /** Addresses the principal may send as. Empty means "no restriction". */
  readonly allowedSenders: readonly string[];
}

export interface McpRequestContext {
  readonly principalId: string;
  readonly tenantId: string;
  readonly roles: readonly RailGunRole[];
  readonly scopes: readonly RailGunScope[];
  readonly transport: "stdio" | "http";
  readonly requestId: string | null;
  /** Addresses the principal may send as; empty means "no restriction". */
  readonly allowedSenders?: readonly string[];
  /** Explicit grant permitting message-body reads. Default deny. */
  readonly bodyRead?: boolean;
}

/** Credential material presented by a client. */
export type Credential =
  | { readonly kind: "apiKey"; readonly value: string }
  | { readonly kind: "jwt"; readonly value: string }
  | { readonly kind: "local"; readonly value: string };

/**
 * Resolves a presented credential to a principal. Implementations live in the
 * config/auth layer; the MCP surface only depends on this port.
 */
export interface PrincipalResolver {
  resolveApiKey(apiKey: string): Promise<Principal | null>;
  resolveJwt(token: string): Promise<Principal | null>;
  resolveLocal(label: string): Promise<Principal | null>;
}

/**
 * Extract exactly one credential from request headers.
 *
 * Returns `null` when no credential is present. Throws `AMBIGUOUS_AUTH` when
 * more than one credential path is presented.
 */
export function extractCredential(headers: {
  get(name: string): string | undefined | null;
}): Credential | null {
  const authorization = headers.get("authorization") ?? undefined;
  const apiKeyHeader = headers.get("x-api-key") ?? undefined;

  const bearer = parseBearer(authorization);
  const hasApiKeyHeader = typeof apiKeyHeader === "string" && apiKeyHeader.trim().length > 0;

  if (bearer && hasApiKeyHeader) {
    throw new RailGunError(
      "AMBIGUOUS_AUTH",
      "Present exactly one credential; both a bearer token and an API key were supplied.",
    );
  }
  if (bearer) {
    return bearer.isJwt
      ? { kind: "jwt", value: bearer.value }
      : { kind: "apiKey", value: bearer.value };
  }
  if (hasApiKeyHeader) return { kind: "apiKey", value: apiKeyHeader.trim() };

  return null;
}

interface BearerCredential {
  readonly value: string;
  readonly isJwt: boolean;
}

/**
 * Parse an `Authorization: Bearer <value>` header. A compact three-segment
 * value is treated as a JWT candidate; anything else as an API key.
 */
export function parseBearer(authorization: string | undefined): BearerCredential | null {
  if (!authorization) return null;
  const trimmed = authorization.trim();
  const match = /^Bearer\s+(.+)$/i.exec(trimmed);
  if (!match) return null;
  const value = match[1]?.trim();
  if (!value) return null;
  return { value, isJwt: value.split(".").length === 3 };
}

/** Credential kind resolved from a raw bearer/header value. */
export type ResolvedCredentialKind = "apiKey" | "jwt";

/**
 * Resolve the credential into a principal, enforcing the single-credential
 * rule and failing closed.
 */
export async function authenticate(
  credential: Credential | null,
  resolver: PrincipalResolver,
): Promise<Principal> {
  if (!credential) {
    throw new RailGunError("UNAUTHENTICATED", "Authentication is required.");
  }

  let principal: Principal | null = null;
  if (credential.kind === "local") {
    principal = await resolver.resolveLocal(credential.value);
  } else if (credential.kind === "jwt") {
    principal = await resolver.resolveJwt(credential.value);
  } else {
    principal = await resolver.resolveApiKey(credential.value);
  }

  if (!principal) {
    throw new RailGunError("UNAUTHENTICATED", "Authentication is required.");
  }
  return principal;
}

/**
 * Resolve a bearer token or API key header value into a principal, deciding
 * between the JWT and API-key paths.
 */
export async function authenticateHeader(
  credential: Credential | null,
  resolver: PrincipalResolver,
): Promise<Principal> {
  if (!credential) {
    throw new RailGunError("UNAUTHENTICATED", "Authentication is required.");
  }
  if (credential.kind === "local") {
    const principal = await resolver.resolveLocal(credential.value);
    if (!principal) {
      throw new RailGunError("UNAUTHENTICATED", "Authentication is required.");
    }
    return principal;
  }
  if (credential.kind === "jwt") {
    const principal = await resolver.resolveJwt(credential.value);
    if (!principal) {
      throw new RailGunError("UNAUTHENTICATED", "Authentication is required.");
    }
    return principal;
  }
  const principal = await resolver.resolveApiKey(credential.value);
  if (!principal) {
    throw new RailGunError("UNAUTHENTICATED", "Authentication is required.");
  }
  return principal;
}

/** True when the principal holds the given scope. */
export function hasScope(principal: Principal, scope: RailGunScope): boolean {
  return principal.scopes.includes(scope);
}

/**
 * Assert that the principal holds `scope`, otherwise fail with `FORBIDDEN`
 * naming the missing scope.
 */
export function requireScope(principal: Principal, scope: RailGunScope): void {
  if (!hasScope(principal, scope)) {
    throw new RailGunError(
      "FORBIDDEN",
      `Insufficient scope for this operation. Required scope: ${scope}.`,
      { requiredScope: scope },
    );
  }
}

/**
 * Assert the requested sender identity is allowed for this principal.
 * The `sender_override` capability (admin only) bypasses the allow-list.
 */
export function requireAllowedSender(principal: Principal, from: string | undefined): void {
  if (!from) return;
  if (principal.senderOverride) return;
  const allowed = principal.allowedSenders.map((entry) => entry.toLowerCase());
  if (allowed.length === 0) return;
  if (!allowed.includes(from.toLowerCase())) {
    throw new RailGunError(
      "POLICY_REJECTED",
      "The requested sender address is not permitted for this principal.",
      { field: "from" },
    );
  }
}

/**
 * Tenant-scoped salted hash of a recipient address.
 *
 * Raw addresses are never returned through MCP; only this hash is exposed.
 * The salt is per-tenant so hashes are not comparable across tenants.
 */
export function hashRecipient(
  address: string,
  tenantId: string,
  salt: string,
): string {
  const digest = createHash("sha256")
    .update(`${salt}\u0000${tenantId}\u0000${address.toLowerCase()}`)
    .digest("hex");
  return `h_${digest.slice(0, 32)}`;
}

/** Hash of an idempotency key; the raw key is never audited by default. */
export function hashIdempotencyKey(requestId: string, tenantId: string, salt: string): string {
  const digest = createHash("sha256")
    .update(`${salt}\u0000${tenantId}\u0000${requestId}`)
    .digest("hex");
  return `k_${digest.slice(0, 32)}`;
}

/** Constant-time comparison of two secrets of equal expected length. */
export function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    // Still perform a comparison to keep the timing profile flat.
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

/** Build the request context derived from an authenticated principal. */
export function buildRequestContext(
  principal: Principal,
  transport: "stdio" | "http",
  requestId: string | null = null,
): McpRequestContext {
  return {
    principalId: principal.principalId,
    tenantId: principal.tenantId,
    roles: principal.roles,
    scopes: principal.scopes,
    transport,
    requestId,
    allowedSenders: principal.allowedSenders,
    bodyRead: principal.bodyRead,
  };
}
