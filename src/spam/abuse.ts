// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Suppression, blocklist, role-address and trap-recipient checks.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §10.1, §10.2,
// §10.3 and verification obligations V-12, V-13, V-14.
//
// Suppression is checked **before enqueue** and **again immediately before the
// outbound transaction** (IR R-10.1.4, R-8.2.1). A newly-suppressed
// recipient terminates as `suppressed` without an SMTP transaction (INV-3).

import { parseAddress } from "../security/address.js";
import type { RoleAddressConfig } from "../domain/identity.js";
import type { PolicyDecision } from "../domain/policy.js";
import type {
  BlocklistStore,
  BlocklistSubject,
  RemoteBlocklistClient,
  SuppressionStore,
  VerifiedRecipientStore,
} from "../ports/index.js";
import type { BlocklistConfig } from "./config.js";

/** The result of a per-recipient abuse check. */
export interface AbuseCheckResult {
  readonly decision: PolicyDecision;
  readonly reason_code: string;
  readonly rule_id: string;
  /** Non-revealing context for the operator. */
  readonly detail: string;
  /** The suppression reason class, when the denial came from suppression. */
  readonly suppression_reason?: string;
  /** The matched blocklist entry kind, when the denial came from a blocklist. */
  readonly blocklist_kind?: string;
}

const ALLOWED: AbuseCheckResult = Object.freeze({
  decision: "allow" as PolicyDecision,
  reason_code: "QUEUED",
  rule_id: "abuse.allowed",
  detail: "",
});

/**
 * Checks the suppression list for a recipient (IR §10.1).
 *
 * A suppression denial returns `SUPPRESSED` plus the **reason class only** —
 * it never discloses internal notes, evidence or the origin of the feedback
 * beyond the reason class (IR R-10.1.6).
 */
export async function checkSuppression(
  store: SuppressionStore,
  tenantId: string,
  sendingDomain: string,
  recipient: string,
  nowMs: number,
): Promise<AbuseCheckResult> {
  const global = await store.find(tenantId, null, recipient, nowMs);
  // The store is expected to honour the tenant, but the check is defensive:
  // a global entry belonging to another tenant must never suppress this one.
  if (global !== null && global.tenant_id === tenantId) {
    return {
      decision: "deny",
      reason_code: "SUPPRESSED",
      rule_id: "suppression.global",
      detail: "recipient is suppressed",
      suppression_reason: global.reason,
    };
  }
  const scoped = await store.find(tenantId, sendingDomain, recipient, nowMs);
  if (scoped !== null && scoped.tenant_id === tenantId) {
    return {
      decision: "deny",
      reason_code: "SUPPRESSED",
      rule_id: "suppression.domain",
      detail: "recipient is suppressed for this sending domain",
      suppression_reason: scoped.reason,
    };
  }
  return ALLOWED;
}

/**
 * Checks the local and remote blocklists (IR §10.2).
 *
 * A blocklist is a **negative** signal: its absence is never treated as
 * authorization (IR R-10.2.3). A remote-list fetch failure follows that
 * list's own fail policy and MUST NOT block all mail unless the list is
 * explicitly `fail_closed` (IR R-10.2.2).
 */
export async function checkBlocklist(
  localStore: BlocklistStore,
  remoteClient: RemoteBlocklistClient | null,
  config: BlocklistConfig,
  subject: BlocklistSubject,
): Promise<AbuseCheckResult> {
  const localHits = await localStore.match(subject);
  const hit = localHits[0];
  if (hit !== undefined) {
    return {
      decision: "deny",
      reason_code: "BLOCKED",
      rule_id: "blocklist.local",
      detail: "subject matched a local blocklist entry",
      blocklist_kind: hit.kind,
    };
  }

  if (remoteClient !== null) {
    for (const list of config.remote) {
      const result = await remoteClient.isListed(list.name, subject);
      if (result.listed) {
        return {
          decision: "deny",
          reason_code: "BLOCKED",
          rule_id: `blocklist.remote.${list.name}`,
          detail: "subject matched a remote blocklist",
          blocklist_kind: "remote",
        };
      }
      if (result.failed) {
        // A failed fetch follows the per-list fail policy.
        const policy = config.remote_fail_policy;
        if (policy === "fail_closed") {
          return {
            decision: "deny",
            reason_code: "BLOCKED",
            rule_id: `blocklist.remote.${list.name}.unavailable`,
            detail: "remote blocklist unavailable and configured to fail closed",
            blocklist_kind: "remote",
          };
        }
        // fail_open: the fetch failure does not block the message.
      }
    }
  }

  return ALLOWED;
}

/**
 * Checks a recipient against the role-address and trap-recipient rules
 * (IR §10.3).
 *
 * - A trap recipient is denied **unconditionally** and records a spam-trap
 *   signal for the reputation counters.
 * - A role address is governed by the configured protection mode.
 * - `require_verified` is the default for cold tenants.
 */
export async function checkRoleAddress(
  config: RoleAddressConfig,
  recipient: string,
  options: {
    readonly recipient_verified: boolean;
    readonly protect_enabled: boolean;
    /** The low cap applied in `throttle` mode. */
    readonly role_address_hourly_cap?: number;
  },
): Promise<AbuseCheckResult> {
  const parsed = parseAddress(recipient);
  if (parsed === null) {
    return ALLOWED;
  }
  const local = parsed.local;

  const traps = new Set(config.trap_recipients.map((t) => t.toLowerCase()));
  if (traps.has(local) || traps.has(recipient.toLowerCase())) {
    // Denied unconditionally, and the caller records the trap signal.
    return {
      decision: "deny",
      reason_code: "ROLE_ADDRESS_PROTECTED",
      rule_id: "role_address.trap_recipient",
      detail: "recipient is a configured trap recipient",
    };
  }

  if (!options.protect_enabled) {
    return ALLOWED;
  }

  const protectedLocals = new Set(config.list.map((l) => l.toLowerCase()));
  if (!protectedLocals.has(local)) {
    return ALLOWED;
  }

  switch (config.mode) {
    case "allow":
      return {
        decision: "allow",
        reason_code: "QUEUED",
        rule_id: "role_address.allowed",
        detail: "role addresses are permitted",
      };
    case "deny":
      return {
        decision: "deny",
        reason_code: "ROLE_ADDRESS_PROTECTED",
        rule_id: "role_address.denied",
        detail: "role address is protected",
      };
    case "throttle":
      return {
        decision: "throttle",
        reason_code: "ROLE_ADDRESS_PROTECTED",
        rule_id: "role_address.throttled",
        detail: "role address is rate limited",
      };
    case "require_verified":
      if (!options.recipient_verified) {
        return {
          decision: "deny",
          reason_code: "ROLE_ADDRESS_PROTECTED",
          rule_id: "role_address.require_verified",
          detail: "role address requires a verified recipient",
        };
      }
      return {
        decision: "allow",
        reason_code: "QUEUED",
        rule_id: "role_address.verified",
        detail: "role address is verified",
      };
    default:
      return {
        decision: "deny",
        reason_code: "ROLE_ADDRESS_PROTECTED",
        rule_id: "role_address.unknown_mode",
        detail: "unknown role-address protection mode",
      };
  }
}

/**
 * Returns true when **every** recipient of a message is a role address.
 * Such a message is a bulk-to-role pattern and MUST still be scored
 * (IR R-10.3.4).
 */
export function isBulkToRole(
  recipients: readonly string[],
  roleAddresses: readonly string[],
): boolean {
  if (recipients.length === 0) {
    return false;
  }
  const protectedLocals = new Set(roleAddresses.map((l) => l.toLowerCase()));
  return recipients.every((recipient) => {
    const parsed = parseAddress(recipient);
    return parsed !== null && protectedLocals.has(parsed.local);
  });
}

/**
 * Checks whether a recipient is in the tenant's verified-recipient set
 * (IR R-9.3.4).
 */
export async function isVerifiedRecipient(
  store: VerifiedRecipientStore,
  tenantId: string,
  recipient: string,
): Promise<boolean> {
  return store.isVerified(tenantId, recipient.toLowerCase());
}
