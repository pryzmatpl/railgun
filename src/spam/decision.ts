// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The decision-record builder.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §5.2 and §14.1.
//
// The record is immutable, carries every matched rule id, and is written to
// the audit chain **before** the decision is reported as final
// (IR R-5.2.3, R-14.1.7). It never contains the subject, the body, the MIME
// parts, a credential or a raw recipient address.

import { createHash } from "node:crypto";

import {
  REASON_CODES,
  type PolicyDecision,
  type PolicyDecisionRecord,
  type RecipientDecision,
  type SubmissionRequest,
} from "../domain/policy.js";
import type { AuditSink } from "../ports/index.js";
import type { PolicyConfig } from "./config.js";

/**
 * A salted hash of a recipient address, used for correlation in audit records
 * without storing the raw address (IR R-14.1.6).
 */
export function hashRecipient(recipient: string, salt: string): string {
  return createHash("sha256").update(`${salt}:${recipient.toLowerCase()}`).digest("hex");
}

/** The extra fields a decision may carry. */
export interface DecisionExtras {
  readonly evidence?: {
    readonly features?: readonly string[];
    readonly dimension?: string;
    readonly suppression_reason?: string;
  };
  readonly matched_limit?: number;
  readonly limit_value?: number;
  readonly reset_at?: string;
  readonly retry_at?: string;
  readonly spam_score?: number;
  readonly spam_model_version?: string;
}

/**
 * Builds the immutable decision record for an outcome.
 */
export function buildDecisionRecord(
  request: SubmissionRequest,
  config: PolicyConfig,
  decision: PolicyDecision,
  reasonCode: string,
  ruleIds: readonly string[],
  recipients: readonly RecipientDecision[],
  extras: DecisionExtras = {},
): PolicyDecisionRecord {
  const salt = config.audit.salt_env;
  return {
    decision,
    reason_code: reasonCode,
    rule_ids: [...new Set(ruleIds)].toSorted(),
    principal_id: request.principal.principal_id,
    tenant_id: request.principal.tenant_id,
    auth_method: request.principal.auth_method,
    sender_domain: request.envelope.sender.split("@")[1]?.toLowerCase() ?? "",
    envelope_sender: request.envelope.sender,
    recipient_hashes: recipients.map((r) => hashRecipient(r.recipient.address, salt)),
    policy_version: config.policy_version,
    correlation_id: request.correlation_id,
    ...(extras.spam_score !== undefined ? { spam_score: extras.spam_score } : {}),
    ...(extras.spam_model_version !== undefined
      ? { spam_model_version: extras.spam_model_version }
      : {}),
    ...(extras.matched_limit !== undefined ? { matched_limit: extras.matched_limit } : {}),
    ...(extras.limit_value !== undefined ? { limit_value: extras.limit_value } : {}),
    ...(extras.reset_at !== undefined ? { reset_at: extras.reset_at } : {}),
    ...(extras.retry_at !== undefined ? { retry_at: extras.retry_at } : {}),
    ...(extras.evidence !== undefined ? { evidence: extras.evidence } : {}),
  };
}

/**
 * Writes the decision to the audit chain.
 *
 * Returns `null` when the write succeeded, or the reason the audit is
 * unavailable. In `strict` mode the caller must fail closed; in `warn` mode
 * the send proceeds and the failure is itself recorded on the next
 * successful write (IR R-5.2.3).
 */
export async function appendAudit(
  audit: AuditSink,
  record: PolicyDecisionRecord,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  try {
    await audit.append(record);
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: (error as Error).message };
  }
}

/**
 * The decision record produced when the audit write fails in strict mode.
 */
export function auditFailureRecord(
  record: PolicyDecisionRecord,
): PolicyDecisionRecord {
  return {
    ...record,
    decision: "deny",
    reason_code: REASON_CODES.AUDIT_UNAVAILABLE,
    rule_ids: [...new Set([...record.rule_ids, "audit.write_failed"])].toSorted(),
  };
}
