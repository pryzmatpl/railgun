// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The cheap-gate phase: suppression, blocklist, role-address and relay
// authorization, evaluated per recipient without touching the MIME body.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §6.3.1,
// §6.3.2, §6.4.1 and §8.
//
// The SMTP surface calls this at `MAIL FROM` / `RCPT TO` so that an
// unauthorized recipient is **rejected at `RCPT TO`**, never silently
// dropped (SECURITY.md).

import {
  isAtLeastAsRestrictive,
  REASON_CODES,
  type PolicyDecision,
  type Principal,
  type RecipientDecision,
  type SubmissionRequest,
} from "../domain/policy.js";
import type {
  BlocklistStore,
  Clock,
  RemoteBlocklistClient,
  SuppressionStore,
  VerifiedRecipientStore,
} from "../ports/index.js";
import { checkBlocklist, checkRoleAddress, checkSuppression } from "./abuse.js";
import type { PolicyConfig } from "./config.js";
import { authorizeRelay, authorizeSenderDomain } from "./relay.js";

/**
 * The result of the cheap pre-check.
 */
export interface PrecheckResult {
  readonly decision: PolicyDecision;
  readonly reason_code: string;
  readonly rule_ids: readonly string[];
  /** Per-recipient outcomes. */
  readonly recipients: readonly RecipientDecision[];
}

/** The stores the cheap phase needs. */
export interface CheapGateDeps {
  readonly clock: Clock;
  readonly config: PolicyConfig;
  readonly suppression: SuppressionStore;
  readonly blocklist: BlocklistStore;
  readonly remoteBlocklist?: RemoteBlocklistClient | null;
  readonly verifiedRecipients: VerifiedRecipientStore;
}

/**
 * Runs the cheap gates for one request.
 *
 * Gates 5–8 of the normative order (IR §6.1): suppression, blocklist,
 * role-address / trap protection, and the relay-authorization gate.
 */
export async function runCheapGates(
  deps: CheapGateDeps,
  request: Pick<SubmissionRequest, "principal" | "envelope" | "source_ip">,
): Promise<PrecheckResult> {
  const { principal, envelope } = request;
  const config = deps.config;
  const now = deps.clock.now();

  const senderDomain = envelope.sender.split("@")[1]?.toLowerCase() ?? "";
  const senderAuth = authorizeSenderDomain(principal, senderDomain, {
    authorized_subdomains: config.identity.authorized_subdomains,
  });
  if (!senderAuth.allowed) {
    return {
      decision: "deny",
      reason_code: senderAuth.reason_code,
      rule_ids: [senderAuth.rule_id],
      recipients: [],
    };
  }

  const recipients: RecipientDecision[] = [];
  let effective: PolicyDecision = "allow";
  let reasonCode: string = REASON_CODES.QUEUED;
  const ruleIds: string[] = [];

  for (const recipient of envelope.recipients) {
    const verified = await deps.verifiedRecipients.isVerified(
      principal.tenant_id,
      recipient.address,
    );

    // Gate 5 — suppression.
    const suppression = await checkSuppression(
      deps.suppression,
      principal.tenant_id,
      senderDomain,
      recipient.address,
      now,
    );
    if (suppression.decision !== "allow") {
      recipients.push({
        recipient,
        decision: suppression.decision,
        reason_code: suppression.reason_code,
        rule_ids: [suppression.rule_id],
        ...(suppression.suppression_reason !== undefined
          ? { evidence: { suppression_reason: suppression.suppression_reason } }
          : {}),
      });
      ruleIds.push(suppression.rule_id);
      if (isAtLeastAsRestrictive(suppression.decision, effective)) {
        effective = suppression.decision;
        reasonCode = suppression.reason_code;
      }
      continue;
    }

    // Gate 6 — blocklist (local + remote).
    const blocked = await checkBlocklist(
      deps.blocklist,
      deps.remoteBlocklist ?? null,
      config.spam.blocklist,
      {
        recipient_address: recipient.address,
        recipient_domain: recipient.domain,
        sender_address: envelope.sender,
        sender_domain: senderDomain,
        tenant_id: principal.tenant_id,
        ...(request.source_ip !== undefined ? { source_ip: request.source_ip } : {}),
      },
    );
    if (blocked.decision !== "allow") {
      recipients.push({
        recipient,
        decision: blocked.decision,
        reason_code: blocked.reason_code,
        rule_ids: [blocked.rule_id],
      });
      ruleIds.push(blocked.rule_id);
      if (isAtLeastAsRestrictive(blocked.decision, effective)) {
        effective = blocked.decision;
        reasonCode = blocked.reason_code;
      }
      continue;
    }

    // Gate 7 — role-address and trap-recipient protection.
    const roleCheck = await checkRoleAddress(config.spam.role_addresses, recipient.address, {
      recipient_verified: verified,
      protect_enabled: config.spam.protect_role_addresses,
      role_address_hourly_cap: config.rate_limit.new_recipients_per_hour,
    });
    if (roleCheck.decision !== "allow") {
      recipients.push({
        recipient,
        decision: roleCheck.decision,
        reason_code: roleCheck.reason_code,
        rule_ids: [roleCheck.rule_id],
      });
      ruleIds.push(roleCheck.rule_id);
      if (isAtLeastAsRestrictive(roleCheck.decision, effective)) {
        effective = roleCheck.decision;
        reasonCode = roleCheck.reason_code;
      }
      continue;
    }

    // Gate 8 — relay authorization (INV-1).
    const relayAuth = authorizeRelay(principal, recipient.domain, config.relay, {
      sending_domains: principal.sending_domains,
      recipient_verified: verified,
    });
    if (!relayAuth.allowed) {
      recipients.push({
        recipient,
        decision: "deny",
        reason_code: relayAuth.reason_code,
        rule_ids: [relayAuth.rule_id],
      });
      ruleIds.push(relayAuth.rule_id);
      if (isAtLeastAsRestrictive("deny", effective)) {
        effective = "deny";
        reasonCode = relayAuth.reason_code;
      }
      continue;
    }

    recipients.push({
      recipient,
      decision: "allow",
      reason_code: REASON_CODES.QUEUED,
      rule_ids: [relayAuth.rule_id],
    });
    ruleIds.push(relayAuth.rule_id);
  }

  return { decision: effective, reason_code: reasonCode, rule_ids: ruleIds, recipients };
}

/**
 * The effective scope of a principal, exposed for the surfaces that report
 * the operator's relay scope.
 */
export function principalScope(
  principal: Principal,
  config: PolicyConfig,
): string {
  return principal.recipient_scope ?? config.relay.default_scope;
}
