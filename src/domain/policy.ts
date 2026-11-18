// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Policy decision vocabulary and the immutable decision record.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §1.3, §5.2, §12.1
// (anti-spam / identity / relay-authorization IR) and
// packages/railgun/docs/CONTRACT-IMPLEMENTATION-CHECKLIST.md §7.2 (A-9, A-10, A-11).
//
// This module is pure: it imports nothing, not even a Node builtin, so that
// `domain/` and `ports/` stay free of runtime dependencies (IR R-4.1).

/**
 * The five policy decisions. A policy decision is strictly distinct from a
 * delivery outcome (`queued`, `sent`, `deferred`, `bounced`, `suppressed`).
 */
export type PolicyDecision = "allow" | "deny" | "throttle" | "quarantine" | "reject";

/**
 * Restrictiveness precedence (IR R-5.2.2):
 *
 *     reject > deny > quarantine > throttle > allow
 */
const DECISION_RANK: Readonly<Record<PolicyDecision, number>> = Object.freeze({
  allow: 0,
  throttle: 1,
  quarantine: 2,
  deny: 3,
  reject: 4,
});

/** Returns true when `candidate` is at least as restrictive as `current`. */
export function isAtLeastAsRestrictive(
  candidate: PolicyDecision,
  current: PolicyDecision,
): boolean {
  return DECISION_RANK[candidate] >= DECISION_RANK[current];
}

/**
 * Combines two decisions into the more restrictive one (IR R-5.2.2).
 */
export function mostRestrictive(
  a: PolicyDecision,
  b: PolicyDecision,
): PolicyDecision {
  return DECISION_RANK[a] >= DECISION_RANK[b] ? a : b;
}

/**
 * Stable machine-readable reason codes. These are part of the cross-surface
 * contract: the same condition yields the same code over HTTP, MCP and SMTP
 * (IR R-12.1.1). The checklist records `IDEMPOTENCY_KEY_REUSED` and
 * `RATE_LIMITED_BY_POLICY` as canonical with `IDEMPOTENCY_CONFLICT` /
 * `RATE_LIMITED` as accepted aliases, so both spellings exist here.
 */
export const REASON_CODES = Object.freeze({
  UNAUTHORIZED: "UNAUTHORIZED",
  FORBIDDEN: "FORBIDDEN",
  VALIDATION_FAILED: "VALIDATION_FAILED",
  INVALID_REQUEST: "INVALID_REQUEST",
  HEADER_INJECTION: "HEADER_INJECTION",
  PAYLOAD_TOO_LARGE: "PAYLOAD_TOO_LARGE",
  SENDER_NOT_ALLOWED: "SENDER_NOT_ALLOWED",
  IDEMPOTENCY_CONFLICT: "IDEMPOTENCY_CONFLICT",
  IDEMPOTENCY_KEY_REUSED: "IDEMPOTENCY_KEY_REUSED",
  SUPPRESSED: "SUPPRESSED",
  BLOCKED: "BLOCKED",
  ROLE_ADDRESS_PROTECTED: "ROLE_ADDRESS_PROTECTED",
  RECIPIENT_SCOPE_DENIED: "RECIPIENT_SCOPE_DENIED",
  RECIPIENT_NOT_VERIFIED: "RECIPIENT_NOT_VERIFIED",
  QUOTA_EXCEEDED: "QUOTA_EXCEEDED",
  RATE_LIMITED: "RATE_LIMITED",
  RATE_LIMITED_BY_POLICY: "RATE_LIMITED_BY_POLICY",
  WARMUP_LIMITED: "WARMUP_LIMITED",
  DKIM_KEY_UNAVAILABLE: "DKIM_KEY_UNAVAILABLE",
  DKIM_SIGN_FAILED: "DKIM_SIGN_FAILED",
  DMARC_POLICY_MISMATCH: "DMARC_POLICY_MISMATCH",
  SPF_NOT_ALIGNED: "SPF_NOT_ALIGNED",
  SPAM_POLICY_DENIED: "SPAM_POLICY_DENIED",
  QUARANTINED: "QUARANTINED",
  ACCEPTED_THROTTLED: "ACCEPTED_THROTTLED",
  QUEUED: "QUEUED",
  STORE_UNAVAILABLE: "STORE_UNAVAILABLE",
  AUDIT_UNAVAILABLE: "AUDIT_UNAVAILABLE",
  GLOBAL_PAUSED: "GLOBAL_PAUSED",
  SENDING_DOMAIN_DISABLED: "SENDING_DOMAIN_DISABLED",
} as const);

export type ReasonCode = (typeof REASON_CODES)[keyof typeof REASON_CODES];

/**
 * The authenticated identity behind a request. `tenant_id` is derived from the
 * credential, never from the request body (IR R-6.2.1, checklist A-7).
 */
export interface Principal {
  readonly principal_id: string;
  readonly tenant_id: string;
  readonly auth_method: "api_key" | "jwt" | "mtls" | "local" | "system";
  readonly roles: readonly string[];
  /** Sender domains this principal may send from. */
  readonly sending_domains: readonly string[];
  /** Recipient scope of this principal (IR §8.1.2). */
  readonly recipient_scope: RecipientScope;
  /** Recipient domains explicitly allowed when scope is `allowlist`. */
  readonly recipient_allowlist: readonly string[];
  /** Whether subdomain matching applies to the allowlist. */
  readonly allowlist_includes_subdomains: boolean;
}

/** Roles recognized by the policy engine. */
export const ROLE_ADMIN = "admin";
export const ROLE_OPERATOR = "operator";
export const ROLE_SENDER = "sender";
export const ROLE_AUDITOR = "auditor";

/**
 * The recipient scope of a principal (IR §8.1.2).
 *
 * `all` is not an open relay: it still requires the `admin` role to set, is
 * audited, keeps the sender domain restricted, and leaves every other abuse
 * control in force (IR §8.1.3).
 */
export type RecipientScope =
  | "none"
  | "allowlist"
  | "same_domain_only"
  | "verified_recipients_only"
  | "all";

export const RECIPIENT_SCOPES: readonly RecipientScope[] = Object.freeze([
  "none",
  "allowlist",
  "same_domain_only",
  "verified_recipients_only",
  "all",
]);

/** One envelope recipient, normalized by the caller. */
export interface Recipient {
  /** Full normalized address, `local@domain`. */
  readonly address: string;
  /** Lower-cased domain part of the address. */
  readonly domain: string;
}

/** The envelope of a submission, before MIME construction. */
export interface Envelope {
  /** Envelope sender (`MAIL FROM`). Null reverse-path is never accepted. */
  readonly sender: string;
  /** Envelope recipients (`RCPT TO`). */
  readonly recipients: readonly Recipient[];
}

/** Header map of the message. Keys are lower-cased. */
export type HeaderMap = Readonly<Record<string, string>>;

/** A message under policy evaluation. */
export interface MessageUnderPolicy {
  readonly headers: HeaderMap;
  /** Plain-text body; may be empty when only HTML is supplied. */
  readonly text_body: string;
  /** HTML body; may be empty. */
  readonly html_body: string;
  /** Attachment file names (metadata only — content is never inspected here). */
  readonly attachment_names: readonly string[];
}

/** A submission request as presented to the policy engine. */
export interface SubmissionRequest {
  readonly principal: Principal;
  readonly envelope: Envelope;
  readonly message: MessageUnderPolicy;
  readonly request_id: string;
  /** Total transmitted size in bytes, used for byte quotas. */
  readonly size_bytes: number;
  /** Correlation id shared across surfaces. */
  readonly correlation_id: string;
  /** Source IP of the SMTP connection, when known. */
  readonly source_ip?: string;
}

/** Evidence attached to a decision — never raw content. */
export interface DecisionEvidence {
  /** Feature names that fired (content scoring). Never the matched text. */
  readonly features?: readonly string[];
  /** Dimension token for rate/quota outcomes, e.g. `tenant.messages_per_day`. */
  readonly dimension?: string;
  /** Stable reason class for suppression, e.g. `hard_bounce`. */
  readonly suppression_reason?: string;
  /** Salted hashes of the recipients involved. */
  readonly recipient_hashes?: readonly string[];
  /** Additional non-secret context. */
  readonly detail?: Readonly<Record<string, string | number | boolean>>;
}

/**
 * The immutable decision record (IR §5.2). Every evaluation returns one, and
 * exactly one primary audit event is emitted for it (IR R-14.1.1).
 */
export interface PolicyDecisionRecord {
  readonly decision: PolicyDecision;
  readonly reason_code: ReasonCode | string;
  /** Every matched rule id, ordered deterministically (IR R-5.2.1). */
  readonly rule_ids: readonly string[];
  readonly principal_id: string;
  readonly tenant_id: string;
  readonly auth_method: string;
  readonly sender_domain: string;
  readonly envelope_sender: string;
  /** Correlatable recipient evidence; never raw addresses. */
  readonly recipient_hashes: readonly string[];
  readonly policy_version: string;
  readonly spam_score?: number;
  readonly spam_model_version?: string;
  readonly matched_limit?: number;
  readonly limit_value?: number;
  readonly reset_at?: string;
  readonly retry_at?: string;
  readonly exception_id?: string;
  readonly correlation_id: string;
  readonly evidence?: DecisionEvidence;
}

/** Result of evaluating one recipient. */
export interface RecipientDecision {
  readonly recipient: Recipient;
  readonly decision: PolicyDecision;
  readonly reason_code: ReasonCode | string;
  readonly rule_ids: readonly string[];
  readonly retry_at?: string;
  readonly evidence?: DecisionEvidence;
}

/** Outcome of a full submission evaluation. */
export interface SubmissionDecision {
  /** The effective message-level decision. */
  readonly decision: PolicyDecision;
  /** Per-recipient outcomes; the message is partially accepted on a mixture. */
  readonly recipients: readonly RecipientDecision[];
  readonly record: PolicyDecisionRecord;
}

/** Per-recipient decisions that may proceed to enqueue. */
export function allowedRecipients(
  decision: SubmissionDecision,
): readonly RecipientDecision[] {
  return decision.recipients.filter((r) => r.decision === "allow");
}

/** Per-recipient decisions that were refused. */
export function deniedRecipients(
  decision: SubmissionDecision,
): readonly RecipientDecision[] {
  return decision.recipients.filter((r) => r.decision !== "allow");
}
