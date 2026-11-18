// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * Authorization: scope checks, tenant isolation and sender authorization
 * (§3.2–§3.4).
 */

import { actionNotPermitted, insufficientScope, invalidRequest } from "./errors.js";
import { normalizeScope, type Principal, type Scope } from "./types.js";

/** Assert that the principal holds the required scope. */
export function requireScope(principal: Principal, required: string): void {
  const scope = normalizeScope(required);
  if (!scope) {
    throw actionNotPermitted();
  }
  if (!principal.scopes.includes(scope)) {
    throw insufficientScope(scope);
  }
}

/**
 * Reject a client-supplied tenant that conflicts with the principal's tenant.
 *
 * The tenant is derived from the credential and is never client-selectable
 * (§3.2). A conflicting body field is rejected, never silently honored.
 */
export function assertNoTenantOverride(
  principal: Principal,
  body: Record<string, unknown> | undefined,
): void {
  if (!body) {
    return;
  }
  const supplied = body.tenant_id ?? body.tenantId;
  if (typeof supplied !== "string") {
    return;
  }
  if (supplied !== principal.tenant_id) {
    throw invalidRequest("tenant_id", "The request may not select a tenant.");
  }
}

/** Extract the domain part of an address. */
export function domainOf(address: string): string {
  const at = address.lastIndexOf("@");
  if (at === -1) {
    return "";
  }
  return address.slice(at + 1).trim().toLowerCase();
}

/**
 * Assert that the principal may use `from` as the envelope sender (§3.4).
 *
 * The sender domain must be in the principal's `allowed_senders` or in the
 * tenant's verified sender-domain set; otherwise `403 INSUFFICIENT_SCOPE` with
 * `details.reason = "SENDER_NOT_ALLOWED"`.
 */
export function assertSenderAllowed(
  principal: Principal,
  from: string,
  verifiedDomains: readonly string[] = [],
): void {
  const domain = domainOf(from);
  if (!domain) {
    throw invalidRequest("from", "The sender address is invalid.");
  }
  const allowed = principal.allowed_senders.some(
    (entry) => entry.trim().toLowerCase() === domain,
  );
  const verified = verifiedDomains.some((entry) => entry.trim().toLowerCase() === domain);
  if (!allowed && !verified) {
    throw insufficientScope("send", "SENDER_NOT_ALLOWED");
  }
}

/** Scope required to read a message body (§9.2). */
export const BODY_SCOPE: Scope = "body:read";

/** True when the principal may receive the message body. */
export function canReadBody(principal: Principal): boolean {
  return principal.scopes.includes(BODY_SCOPE);
}
