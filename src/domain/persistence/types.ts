/* RailGun persistence value contracts. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Durable value contracts for the persistence ports.
 *
 * These types are the persisted representation, distinct from the domain
 * projections the MCP, HTTP and CLI surfaces expose. A persisted record keeps
 * the raw recipient address and the raw body; every operator-facing surface
 * projects a sanitized view instead.
 */

/** The lifecycle state of one envelope recipient. */
export type EnvelopeStatus =
  | "pending"
  | "leased"
  | "deferred"
  | "accepted"
  | "delivered"
  | "bounced"
  | "suppressed"
  | "failed";

/**
 * The lifecycle state of a whole message.
 *
 * A message carries the aggregate state of its recipients, so its vocabulary
 * includes `queued` — the state of a message that has been accepted but not
 * yet handed to an envelope recipient.
 */
export type MessageStatus =
  | "pending"
  | "queued"
  | "leased"
  | "deferred"
  | "accepted"
  | "delivered"
  | "bounced"
  | "suppressed"
  | "failed";

/** The persisted message record. */
export interface Message {
  readonly id: string;
  readonly tenantId: string;
  readonly principalId: string;
  readonly correlationId: string;
  /** The canonical idempotency key; unique per tenant. */
  readonly idempotencyKey: string;
  readonly requestId: string;
  /** The envelope sender address. */
  readonly envelopeSender: string;
  readonly recipients: readonly string[];
  readonly subject: string;
  /** The raw message body. Cleared by retention, never projected to an operator surface. */
  readonly body: Uint8Array | null;
  /** A reference to an externally stored body, when the body is not inline. */
  readonly bodyReference: string | null;
  /** The digest of the raw body, used for content scoring and deduplication. */
  readonly contentDigest: string;
  readonly rawSize: number;
  readonly status: MessageStatus;
  readonly attemptCount: number;
  readonly nextAttemptAt: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly queuedAt: string | null;
  readonly acceptedAt: string | null;
  readonly deliveredAt: string | null;
  readonly lastSmtpCode: number | null;
  readonly lastResponse: string | null;
  readonly errorCode: string | null;
  readonly suppressionReason: string | null;
  readonly metadata: Readonly<Record<string, unknown>>;
  /** Optimistic-concurrency version. */
  readonly version: number;
}

/** The persisted envelope-recipient record. */
export interface EnvelopeRecipient {
  readonly envelopeId: string;
  readonly messageId: string;
  readonly tenantId: string;
  readonly recipient: string;
  /** The envelope role: `to`, `cc` or `bcc`. */
  readonly recipientKind: string;
  readonly status: EnvelopeStatus;
  readonly attemptCount: number;
  readonly nextAttemptAt: string | null;
  readonly leaseOwner: string | null;
  readonly leaseExpiresAt: string | null;
  readonly lastSmtpCode: number | null;
  readonly lastResponse: string | null;
  readonly errorCode: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly lastAttemptAt: string | null;
  readonly acceptedAt: string | null;
  readonly deliveredAt: string | null;
  readonly terminalAt: string | null;
  readonly version: number;
}

/** One delivery attempt against an envelope recipient. */
export interface DeliveryAttempt {
  readonly attemptId: string;
  readonly envelopeId: string;
  readonly messageId: string;
  readonly attempt: number;
  readonly startedAt: string;
  readonly completedAt: string | null;
  readonly outcome: EnvelopeStatus | null;
  readonly smtpCode: number | null;
  readonly response: string | null;
  readonly errorCode: string | null;
  readonly remoteHost: string | null;
}

/** The persisted outbox work item. */
export interface OutboxItem {
  readonly id: string;
  readonly messageId: string;
  readonly envelopeId: string;
  readonly tenantId: string;
  readonly priority: number;
  readonly availableAt: string;
  readonly attemptCount: number;
  readonly maxAttempts: number;
  readonly leaseOwner: string | null;
  readonly leaseExpiresAt: string | null;
  readonly nextAttemptAt: string;
  readonly state: "pending" | "leased" | "completed";
  readonly lastErrorCode: string | null;
  /** Monotonic acceptance sequence; preserves queue order under equal priority. */
  readonly acceptedSequence: number;
}

/** An outbox item before the store assigns its acceptance sequence. */
export type OutboxItemInput = Omit<OutboxItem, "acceptedSequence">;

/** The idempotency reservation and its committed response snapshot. */
export interface IdempotencyRecord {
  readonly key: string;
  readonly tenantId: string;
  /** The logical action the key belongs to, e.g. `email_send`. */
  readonly action: string;
  readonly requestId: string;
  /** Digest of the request payload; a mismatch under one key is a conflict. */
  readonly requestDigest: string;
  readonly messageId: string | null;
  readonly response: unknown;
  readonly state: "reserved" | "committed";
  readonly createdAt: string;
  readonly expiresAt: string;
}

/** The persisted suppression record. */
export interface Suppression {
  readonly id: string;
  readonly tenantId: string;
  /** The suppressed address; `null` means a domain-wide entry. */
  readonly recipient: string | null;
  /** The stable reason code, e.g. `hard_bounce`. */
  readonly reasonCode: string;
  /** What created the suppression, e.g. `hard_bounce` or `manual`. */
  readonly source: string;
  readonly createdAt: string;
  readonly expiresAt: string | null;
  readonly lastHitAt: string | null;
  readonly relatedBounceId: string | null;
  readonly relatedMessageId: string | null;
  readonly active: boolean;
}

/** The persisted bounce record. */
export interface BounceRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly messageId: string | null;
  readonly envelopeId: string | null;
  readonly recipient: string;
  readonly observedAt: string;
  /** The numeric SMTP reply code, e.g. `550`. */
  readonly smtpCode: number | null;
  /** The DSN code, e.g. `5.1.1`. */
  readonly dsnCode: string | null;
  /** The DSN class, e.g. `5`. */
  readonly dsnClass: string | null;
  /** `hard`, `soft` or `complaint`. */
  readonly bounceClass: "hard" | "soft" | "complaint";
  /** A sanitized human-readable diagnostic; never raw remote text. */
  readonly diagnostic: string | null;
  /** The remote MTA's identifier, when it supplied one. */
  readonly remoteId: string | null;
  /** The suppression this bounce created, when it created one. */
  readonly suppressionId: string | null;
}

/** The input accepted by the audit store. */
export interface AuditEventInput {
  readonly actor: string;
  readonly tenantId: string | null;
  readonly action: string;
  readonly subjectType: string;
  readonly subjectId: string | null;
  /**
   * The outcome of the audited action.
   *
   * The vocabulary is open: an operator action may record `allow`, `deny`,
   * `ok`, `deferred` or any other stable reason code. The audit chain
   * records what happened; it does not constrain it to a fixed set.
   */
  readonly outcome: string;
  readonly reasonCode: string | null;
  readonly correlationId: string | null;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/** The persisted, hash-chained audit record. */
export interface AuditRecord {
  readonly schemaVersion: 1;
  readonly sequence: number;
  readonly timestamp: string;
  readonly actor: string;
  readonly tenantId: string | null;
  readonly action: string;
  readonly subjectType: string;
  readonly subjectId: string | null;
  readonly outcome: string;
  readonly reasonCode: string | null;
  readonly correlationId: string | null;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly previousDigest: string;
  readonly digest: string;
}

/** The retention windows applied by {@link RailGunStore.applyRetention}. */
export interface RetentionPolicy {
  readonly messageMetadataDays: number;
  readonly messageBodyDays: number;
  readonly attemptDays: number;
  readonly bounceDays: number;
  readonly idempotencyDays: number;
  readonly auditDays: number;
}
