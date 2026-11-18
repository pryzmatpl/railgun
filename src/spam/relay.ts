// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Relay authorization — the open-relay prohibition (INV-1).
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §8 and
// verification obligations V-16, V-17.
//
// The gate is identical on the submission path and on the direct-to-MX path.
// `outbound.mode` MUST NOT change authorization semantics (IR R-8.2.3).

import { isDomainWithin } from "../security/address.js";
import type { Principal, RecipientScope } from "../domain/policy.js";
import type { RelayConfig } from "./config.js";

/** The result of a relay authorization check. */
export interface RelayAuthorization {
  readonly allowed: boolean;
  /** `RECIPIENT_SCOPE_DENIED` when denied. */
  readonly reason_code: string;
  /** The rule id recorded on the decision. */
  readonly rule_id: string;
  /** A short, non-revealing explanation for the operator. */
  readonly detail: string;
}

const DENIED: RelayAuthorization = Object.freeze({
  allowed: false,
  reason_code: "RECIPIENT_SCOPE_DENIED",
  rule_id: "relay.scope.denied",
  detail: "recipient domain outside the authorized scope",
});

/**
 * Resolves the effective recipient scope of a principal.
 *
 * The principal's own scope wins; a principal with no scope falls back to the
 * configured default, which is `none` (IR R-8.1.1: the set of domains a
 * principal may send to is empty unless explicitly configured).
 */
export function effectiveScope(principal: Principal, config: RelayConfig): RecipientScope {
  if (principal.recipient_scope !== undefined && principal.recipient_scope !== null) {
    return principal.recipient_scope;
  }
  return config.default_scope;
}

/**
 * The domains a principal may send to under an `allowlist` scope.
 */
export function allowedDomains(
  principal: Principal,
  config: RelayConfig,
): readonly string[] {
  const own = principal.recipient_allowlist ?? [];
  return own.length > 0 ? own : config.allowlist;
}

/**
 * Decides whether a principal may send to a recipient domain (INV-1).
 *
 * This is the single gate consulted by:
 * - the SMTP submission path at `RCPT TO`,
 * - the HTTP `POST /v1/email/send` path,
 * - the MCP `email_send` tool, and
 * - the direct-to-MX outbound path immediately before the first `RCPT TO`.
 */
export function authorizeRelay(
  principal: Principal,
  targetDomain: string,
  config: RelayConfig,
  options: {
    /** The principal's own verified sending domains. */
    readonly sending_domains?: readonly string[];
    /** Whether the recipient is in the tenant's verified-recipient set. */
    readonly recipient_verified?: boolean;
  } = {},
): RelayAuthorization {
  const scope = effectiveScope(principal, config);
  const domain = targetDomain.toLowerCase().replace(/\.$/, "");

  switch (scope) {
    case "none":
      // The default for a freshly created principal: no recipients at all.
      return { ...DENIED, detail: "principal has no recipient scope" };

    case "allowlist": {
      const domains = allowedDomains(principal, config);
      const includeSubdomains =
        principal.allowlist_includes_subdomains || config.allowlist_includes_subdomains;
      const hit = domains.some((allowed) => {
        const candidate = allowed.toLowerCase().replace(/\.$/, "");
        if (candidate === domain) {
          return true;
        }
        return includeSubdomains && isDomainWithin(domain, candidate);
      });
      if (!hit) {
        return { ...DENIED, detail: "recipient domain is not on the allowlist" };
      }
      return {
        allowed: true,
        reason_code: "QUEUED",
        rule_id: "relay.scope.allowlist",
        detail: "recipient domain is on the allowlist",
      };
    }

    case "same_domain_only": {
      const own = options.sending_domains ?? principal.sending_domains;
      const hit = own.some((allowed) => isDomainWithin(domain, allowed.toLowerCase()));
      if (!hit) {
        return { ...DENIED, detail: "recipient domain is outside the tenant's sending domains" };
      }
      return {
        allowed: true,
        reason_code: "QUEUED",
        rule_id: "relay.scope.same_domain_only",
        detail: "recipient domain is one of the tenant's sending domains",
      };
    }

    case "verified_recipients_only": {
      if (options.recipient_verified !== true) {
        return {
          allowed: false,
          reason_code: "RECIPIENT_NOT_VERIFIED",
          rule_id: "relay.scope.verified_recipients_only",
          detail: "recipient is not in the verified-recipient set",
        };
      }
      return {
        allowed: true,
        reason_code: "QUEUED",
        rule_id: "relay.scope.verified_recipients_only",
        detail: "recipient is verified",
      };
    }

    case "all": {
      // `all` is NOT an open relay: the sender domain remains restricted, the
      // principal remains authenticated and scoped, and every other abuse
      // control remains in force (IR §8.1.3).
      return {
        allowed: true,
        reason_code: "QUEUED",
        rule_id: "relay.scope.all",
        detail: "principal holds the audited all-recipients scope",
      };
    }

    default:
      // An unknown scope is treated as the most restrictive value.
      return { ...DENIED, detail: "unknown recipient scope" };
  }
}

/**
 * Decides whether a principal may send **from** a given domain (IR §8.3.1).
 *
 * A `From` domain that is not authorized MUST NOT be "laundered" by setting
 * the envelope sender to an authorized domain.
 */
export function authorizeSenderDomain(
  principal: Principal,
  domain: string,
  options: { readonly authorized_subdomains?: readonly string[] } = {},
): RelayAuthorization {
  const candidate = domain.toLowerCase().replace(/\.$/, "");
  const own = principal.sending_domains.map((d) => d.toLowerCase());
  const subdomains = (options.authorized_subdomains ?? []).map((d) => d.toLowerCase());

  const hit =
    own.includes(candidate) ||
    own.some((allowed) => isDomainWithin(candidate, allowed)) ||
    subdomains.some((allowed) => isDomainWithin(candidate, allowed));
  if (!hit) {
    return {
      allowed: false,
      reason_code: "SENDER_NOT_ALLOWED",
      rule_id: "sender.domain.not_allowed",
      detail: "sender domain is not assigned to the principal",
    };
  }
  return {
    allowed: true,
    reason_code: "QUEUED",
    rule_id: "sender.domain.allowed",
    detail: "sender domain is assigned to the principal",
  };
}
