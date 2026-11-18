/* RailGun SMTP submission server — protocol types.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Wire-protocol contracts for the RFC 5321 submission subset.
 *
 * This module deliberately contains no I/O. Everything here is a pure data
 * contract that the session state machine, the policy ports, and the durable
 * queue port all agree on. See
 * `docs/design/84df18ec-8e87-47cb-9d64-b804c4205cb3-railgun-smtp-submission-server-ir.md`.
 */

/** Stable, machine-readable reason codes (IR Rule R-3). */
export const SMTP_REASON_CODES = {
  authFailed: "auth.failed",
  authRateLimited: "auth.rate_limited",
  authRequired: "auth.required",
  authMechanismUnsupported: "auth.mechanism_unsupported",
  commandSyntax: "command.syntax",
  commandNotImplemented: "command.not_implemented",
  commandOutOfSequence: "command.out_of_sequence",
  commandLineTooLong: "command.line_too_long",
  policySenderNotAllowed: "policy.sender_not_allowed",
  policyRecipientNotAllowed: "policy.recipient_not_allowed",
  policyRejected: "policy.rejected",
  policyQuarantined: "policy.quarantined",
  policyDegraded: "policy.degraded",
  policyHeaderInjection: "policy.header_injection",
  policyMissingContext: "policy.missing_context",
  policyMalformedMessage: "policy.malformed_message",
  limitMessageSize: "limit.message_size",
  limitRecipientsPerTransaction: "limit.recipients_per_transaction",
  limitRecipientsPerMessage: "limit.recipients_per_message",
  limitHeaderCount: "limit.header_count",
  limitHeaderSize: "limit.header_size",
  limitCommandRate: "limit.command_rate",
  limitCommandLineBytes: "limit.command_line_bytes",
  rateTenantMessagesPerHour: "rate.tenant.messages_per_hour",
  rateTenantRecipientsPerMessage: "rate.tenant.recipients_per_message",
  rateRecipientWarmup: "rate.recipient.warmup",
  suppressionRecipient: "suppression.recipient",
  blocklistRecipient: "blocklist.recipient",
  roleAddressProtected: "policy.role_address_protected",
  storeUnavailable: "store.unavailable",
  internalError: "internal.error",
  accepted: "submission.accepted",
} as const;

export type SmtpReasonCode = (typeof SMTP_REASON_CODES)[keyof typeof SMTP_REASON_CODES];

/** Session states (IR §3.1). */
export type SmtpSessionState =
  | "GREETING_SENT"
  | "GREETED"
  | "TLS_ACTIVE"
  | "AUTHENTICATED"
  | "MAIL_RECEIVED"
  | "RCPT_RECEIVED"
  | "DATA_RECEIVED"
  | "CLOSED";

/** Policy hook outcomes (IR Rule H-7). Absence of a decision is an error. */
export type PolicyHookOutcome =
  | { readonly action: "allow" }
  | {
      readonly action: "reject";
      readonly code: number;
      readonly reason: string;
      readonly retryAfterSeconds?: number;
    }
  | {
      readonly action: "defer";
      readonly code: number;
      readonly reason: string;
      readonly retryAfterSeconds?: number;
    }
  | {
      readonly action: "quarantine";
      readonly code: number;
      readonly reason: string;
    };

export type PolicyHookResult = PolicyHookOutcome;

export interface PolicyDecisionContext {
  readonly tenantId: string;
  readonly principalId: string;
  readonly sourceIp: string;
  readonly tls: boolean;
  readonly envelopeSender: string | null;
  readonly recipient: string | null;
  readonly declaredSize: number | null;
  readonly receivedSize: number | null;
  readonly rawMessage: Uint8Array | null;
  readonly headers: readonly SmtpHeader[];
  readonly correlationId: string;
}

/**
 * H1–H9 policy hooks (IR §7.1). Each hook is optional; an absent hook means
 * "no opinion" and is treated as `allow` by the session, but a hook that
 * *throws* is handled per Rule H-6 (fail-closed / fail-open).
 */
export interface SmtpPolicyHooks {
  /** H2 — fires on each `MAIL FROM`. */
  authorizeSender?(context: PolicyDecisionContext): Promise<PolicyHookResult>;
  /** H1 — fires on each `RCPT TO`, evaluated independently. */
  authorizeRecipient?(context: PolicyDecisionContext): Promise<PolicyHookResult>;
  /** H3 — fires on each `RCPT TO` and at `MAIL FROM`. */
  checkRateLimit?(context: PolicyDecisionContext): Promise<PolicyHookResult>;
  /** H4 — fires on each `RCPT TO`. */
  checkSuppression?(context: PolicyDecisionContext): Promise<PolicyHookResult>;
  /** H5 — fires on each `RCPT TO`. */
  checkBlocklist?(context: PolicyDecisionContext): Promise<PolicyHookResult>;
  /** H6 — fires on each `RCPT TO`. */
  checkRoleAddress?(context: PolicyDecisionContext): Promise<PolicyHookResult>;
  /** H7 — fires after `DATA`, before queueing. */
  scoreContent?(context: PolicyDecisionContext): Promise<PolicyHookResult>;
  /** H8 — fires after `DATA` (headers, size, MIME). */
  validateShape?(context: PolicyDecisionContext): Promise<PolicyHookResult>;
}

/** A parsed header from the captured raw message (IR Rule M-2). */
export interface SmtpHeader {
  /** Lower-cased header field name, e.g. `from`. */
  readonly name: string;
  /** Unfolded field value (continuation lines joined with a space). */
  readonly value: string;
  /** Raw bytes of the field, including continuations, for Bcc stripping. */
  readonly raw: string;
}

/** Per-recipient acceptance outcome (IR Rules A-7, A-8). */
export interface RecipientOutcome {
  readonly recipient: string;
  readonly accepted: boolean;
  readonly code: number;
  readonly reason: string;
}

/** The message handed to the queue port after all checks pass (H9). */
export interface SmtpSubmission {
  readonly tenantId: string;
  readonly principalId: string;
  readonly correlationId: string;
  readonly envelopeSender: string;
  readonly recipients: readonly string[];
  readonly rejectedRecipients: readonly RecipientOutcome[];
  /** Canonical CRLF-normalized raw message bytes (IR Rules M-1, D-4). */
  readonly raw: Uint8Array;
  readonly headers: readonly SmtpHeader[];
  readonly size: number;
  readonly receivedAt: string;
}

/** H9 — durable enqueue port. Must not throw for business rejections. */
export interface SmtpQueuePort {
  /**
   * Commit the message durably. Throwing means the commit did not happen and
   * the server MUST answer `451` (IR Rules D-9, D-10, D-11).
   */
  enqueue(submission: SmtpSubmission): Promise<{ readonly messageId: string }>;
}

/** Resolved principal identity after a successful authentication. */
export interface SmtpPrincipal {
  readonly id: string;
  readonly tenantId: string;
  /** Exact envelope senders this principal may use. Empty means "any". */
  readonly allowedSenders: readonly string[];
  /** Destination domains this principal may relay to. Empty means "none". */
  readonly allowedRecipientDomains: readonly string[];
  /** Whether the principal may act for an explicit `authzid`. */
  readonly allowAuthzId: boolean;
}

/** Authentication verifier. Implementations MUST NOT log the secret material. */
export interface SmtpAuthenticator {
  /**
   * Verify credentials. MUST return the same failure for "unknown principal"
   * and "wrong password" (IR Rule U-6). MUST use a constant-time comparison
   * over an Argon2id hash or an opaque token lookup.
   */
  verify(
    username: string,
    password: string,
    meta: { readonly sourceIp: string; readonly tenantHint?: string },
  ): Promise<SmtpPrincipal | null>;
  /**
   * Rate-limit gate for authentication attempts (IR Rule U-7). Returning a
   * positive number means the attempt is throttled and MUST yield `451`.
   */
  checkRateLimit?(sourceIp: string, username: string): Promise<number>;
}

/** Per-listener TLS material and behaviour. */
export interface SmtpTlsOptions {
  readonly cert: string | Buffer;
  readonly key: string | Buffer;
  readonly minVersion?: "TLSv1.2" | "TLSv1.3";
  readonly passphrase?: string;
}

/** Server configuration consumed by {@link createSmtpServer}. */
export interface SmtpServerOptions {
  /** Plain listener, e.g. `0.0.0.0:2525`. Port 25 requires `allowPort25`. */
  readonly host?: string;
  readonly port: number;
  readonly hostname?: string;
  /** Implicit-TLS listener. When set, `STARTTLS` is not advertised. */
  readonly implicitTls?: SmtpTlsOptions;
  /** STARTTLS material for the plain listener. */
  readonly startTls?: SmtpTlsOptions;
  /** Explicit operator opt-in required to bind port 25 (IR Rule L-1). */
  readonly allowPort25?: boolean;
  /** Require `AUTH` before `MAIL FROM` (IR Rule U-15). */
  readonly requireAuth?: boolean;
  /** Allow unauthenticated loopback submission via the `local` principal. */
  readonly allowLocalSubmission?: boolean;
  /** Advertise `SMTPUTF8` and accept non-ASCII envelope addresses. */
  readonly smtpUtf8?: boolean;
  /** Advertise `SIZE` and honour a `SIZE=` parameter (IR Rule D-6). */
  readonly advertiseSize?: boolean;
  /** Maximum received message size in bytes. Hard limit → `552`. */
  readonly maxMessageBytes?: number;
  /** Maximum accepted recipients per transaction. Hard limit → `552`. */
  readonly maxRecipientsPerTransaction?: number;
  /** Maximum accepted recipients per message. Hard limit → `552`. */
  readonly maxRecipientsPerMessage?: number;
  /** Maximum command line length in bytes including CRLF. */
  readonly maxCommandLineBytes?: number;
  /** Maximum header count in a message. */
  readonly maxHeaderCount?: number;
  /** Maximum size of a single header field in bytes. */
  readonly maxHeaderBytes?: number;
  /** Maximum accepted credential length in bytes (IR Rule U-12). */
  readonly maxCredentialBytes?: number;
  /** Maximum commands per minute per connection. Soft limit → `451`. */
  readonly maxCommandRatePerMinute?: number;
  /** Connection idle timeout in milliseconds. */
  readonly idleTimeoutMs?: number;
  /** Maximum connection lifetime in milliseconds. */
  readonly connectionLifetimeMs?: number;
  /** Timeout for a multi-step `AUTH` exchange in milliseconds. */
  readonly authTimeoutMs?: number;
  /** Fail closed when a policy hook throws (IR Rule H-6). */
  readonly policyFailClosed?: boolean;
  readonly authenticator?: SmtpAuthenticator;
  readonly policy?: SmtpPolicyHooks;
  readonly queue?: SmtpQueuePort;
  /** Session-scoped event sink. Implementations MUST redact credentials. */
  readonly onEvent?: (event: SmtpServerEvent) => void;
}

export type SmtpServerEvent =
  | {
      readonly type: "auth_failed";
      readonly reason: string;
      readonly sourceIp: string;
      readonly correlationId: string;
    }
  | {
      readonly type: "auth_succeeded";
      readonly principalId: string;
      readonly sourceIp: string;
      readonly correlationId: string;
    }
  | {
      readonly type: "message_accepted";
      readonly messageId: string;
      readonly tenantId: string;
      readonly principalId: string;
      readonly recipients: readonly RecipientOutcome[];
      readonly correlationId: string;
    }
  | {
      readonly type: "message_rejected";
      readonly reason: string;
      readonly tenantId: string;
      readonly principalId: string;
      readonly correlationId: string;
    }
  | {
      readonly type: "tls_established";
      readonly sourceIp: string;
      readonly correlationId: string;
    }
  | {
      readonly type: "session_closed";
      readonly sourceIp: string;
      readonly correlationId: string;
      readonly reason: string;
    };
