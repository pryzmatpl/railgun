// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Operator-facing projection contracts.
 *
 * These are the sanitized views the CLI, HTTP and MCP surfaces render. They
 * are deliberately distinct from the persisted records in
 * `domain/persistence/types.ts`: a projection never carries a raw recipient
 * address, a message body or a secret.
 *
 * The status vocabulary is owned by `domain/status.ts`; a projection reuses it
 * so the CLI cannot invent a status the rest of the package does not know.
 */
import type { RailGunStatus } from "./status.js";
import { isDeliveryConfirmed } from "./status.js";

export type { RailGunStatus };

/** The canonical status vocabulary, re-exported for convenience. */
export { RAILGUN_STATUSES, isDeliveryConfirmed, normalizeStatus } from "./status.js";

/** A recipient's delivery state inside one message. */
export interface EnvelopeRecipientProjection {
  id: string;
  /** Hashed or redacted recipient projection — never a raw address. */
  recipient: string;
  status: RailGunStatus;
  attempts: number;
  lastReason: string | null;
  lastAttemptAt: string | null;
}

/** The safe message projection exposed to the CLI. */
export interface MessageProjection {
  id: string;
  tenant: string;
  status: RailGunStatus;
  /** True only for a confirmed delivery, never for acceptance. */
  deliveryConfirmed: boolean;
  /** The deterministic RFC 5322 Message-ID. */
  messageId: string | null;
  subject: string | null;
  from: string | null;
  recipients: EnvelopeRecipientProjection[];
  attempts: number;
  createdAt: string;
  updatedAt: string;
  /** Stable policy reason, e.g. `rate_limited`. */
  policyReason: string | null;
  /** Sanitized last SMTP response. */
  lastResponse: string | null;
}

/** The canonical statistics counters. */
export interface StatsProjection {
  queued: number;
  accepted: number;
  delivered: number;
  deferred: number;
  bounced: number;
  suppressed: number;
  rejected: number;
  windowStart: string | null;
  windowEnd: string | null;
  tenant: string | null;
}

/** The sanitized bounce projection. */
export interface BounceProjection {
  id: string;
  messageId: string | null;
  /** Hashed or redacted address projection. */
  recipient: string;
  /** `permanent` or `temporary`. */
  class: "permanent" | "temporary";
  /** DSN status code, e.g. `5.1.1`. */
  status: string | null;
  /** Sanitized human reason. */
  reason: string | null;
  at: string;
}

/** A suppression entry projection. */
export interface SuppressionProjection {
  id: string;
  /** Normalized address or approved wildcard domain. */
  scope: string;
  reason: string;
  createdAt: string;
  expiresAt: string | null;
  permanent: boolean;
}

/** The durable queue depth projection. */
export interface QueueStatsProjection {
  depth: number;
  due: number;
  leased: number;
  scheduled: number;
  /** Age in seconds of the oldest queued item. */
  oldestQueuedAgeSeconds: number;
  /** Bounded destination breakdown; never a per-recipient label set. */
  destinations: { destination: string; count: number }[];
}

/** A page of results. */
export interface Page<T> {
  items: T[];
  nextCursor: string | null;
  total: number | null;
}

/** The principal the CLI acts as. */
export interface Principal {
  id: string;
  tenant: string;
  scopes: string[];
}

/** A safe admin principal projection. */
export interface AdminProjection {
  id: string;
  displayName: string;
  email: string | null;
  tenant: string;
  scopes: string[];
  /** A non-secret fingerprint of the credential. */
  credentialFingerprint: string | null;
  createdAt: string;
}

/**
 * Project a persisted message into its safe operator view.
 *
 * The body is dropped and the recipient addresses are replaced by the
 * supplied projection function, so a caller cannot leak a raw address by
 * forgetting to redact it.
 */
export function projectMessage(
  message: {
    id: string;
    tenantId: string;
    status: RailGunStatus;
    messageId: string;
    subject?: string | null;
    from?: string | null;
    attempts: number;
    createdAt: string;
    updatedAt: string;
    reason?: string | null;
    lastSmtpCode?: string | null;
    envelope?: { recipients: readonly { address: string; status: RailGunStatus; attempts: number }[] };
  },
  projectRecipient: (address: string) => string,
): MessageProjection {
  return {
    id: message.id,
    tenant: message.tenantId,
    status: message.status,
    deliveryConfirmed: isDeliveryConfirmed(message.status),
    messageId: message.messageId,
    subject: message.subject ?? null,
    from: message.from ?? null,
    recipients: (message.envelope?.recipients ?? []).map((recipient, index) => ({
      id: `${message.id}:${index}`,
      recipient: projectRecipient(recipient.address),
      status: recipient.status,
      attempts: recipient.attempts,
      lastReason: message.reason ?? null,
      lastAttemptAt: null,
    })),
    attempts: message.attempts,
    createdAt: message.createdAt,
    updatedAt: message.updatedAt,
    policyReason: message.reason ?? null,
    lastResponse: message.lastSmtpCode ?? null,
  };
}
