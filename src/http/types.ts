// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * Shared types and ports for the RailGun HTTP API surface.
 *
 * The HTTP layer never talks to a database, an SMTP server or DNS directly. It
 * depends on the narrow ports declared here so that the domain/persistence
 * (unit B), the outbound delivery engine (unit D) and the anti-spam policy
 * engine (unit E) can supply implementations without the HTTP surface knowing
 * about their internals.
 *
 * Contract: `docs/design/railgun-http-api-ir.md` (this file implements §3, §4,
 * §5, §6, §8 and §9).
 */

/* -------------------------------------------------------------------------- */
/* Status vocabulary                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Canonical message status vocabulary (`packages/railgun/docs/ARCHITECTURE.md`
 * §3.1). `accepted` means the upstream MX returned a final `250` after `DATA`;
 * it is NOT proof of mailbox delivery.
 */
export type MessageStatus =
  | "received"
  | "policy_evaluated"
  | "queued"
  | "accepted"
  | "delivered"
  | "deferred"
  | "bounced"
  | "failed"
  | "rejected"
  | "suppressed";

/** Terminal statuses participate in the delivery-rate denominator (§6.4). */
export const TERMINAL_STATUSES: readonly MessageStatus[] = [
  "delivered",
  "deferred",
  "bounced",
  "suppressed",
  "rejected",
];

/** Scope names (§3.3). `body:read` is introduced by IR open item OI-6. */
export type Scope = "send" | "read" | "admin" | "feedback" | "body:read";

/** Aliases accepted during scope resolution (OI-5). */
const SCOPE_ALIASES: Record<string, Scope> = {
  "email.send": "send",
  "email.read": "read",
  "email.admin": "admin",
  "feedback": "feedback",
  "body:read": "body:read",
  "body.read": "body:read",
};

/** Normalize a raw scope string to the canonical spelling. */
export function normalizeScope(raw: string): Scope | undefined {
  const trimmed = raw.trim();
  if (trimmed in SCOPE_ALIASES) {
    return SCOPE_ALIASES[trimmed];
  }
  if (
    trimmed === "send" ||
    trimmed === "read" ||
    trimmed === "admin" ||
    trimmed === "body:read"
  ) {
    return trimmed;
  }
  return undefined;
}

/** Normalize a scope list, dropping unknown entries and de-duplicating. */
export function normalizeScopes(raw: readonly string[]): Scope[] {
  const out = new Set<Scope>();
  for (const entry of raw) {
    const scope = normalizeScope(entry);
    if (scope) {
      out.add(scope);
    }
  }
  return [...out];
}

/**
 * `admin` does NOT imply `send` and `read` does NOT imply `admin` (§3.3).
 * The only implication is `feedback` → nothing; scopes stay explicit.
 */
export function hasScope(scopes: readonly Scope[], required: Scope): boolean {
  return scopes.includes(required);
}

/* -------------------------------------------------------------------------- */
/* Principal                                                                   */
/* -------------------------------------------------------------------------- */

export type PrincipalKind = "api_key" | "jwt" | "local_operator";

export interface Principal {
  /** `key_01J8…` | `jwt:<sub>` | `admin`. Never a raw credential. */
  id: string;
  /** Exactly one tenant per principal; never client-selectable. */
  tenant_id: string;
  kind: PrincipalKind;
  /** Effective, additive scope union. */
  scopes: Scope[];
  roles: string[];
  /** Verified sender domains this principal may use as `from`. */
  allowed_senders: string[];
  /** Domains the principal may read/write. */
  allowed_domains: string[];
  active: boolean;
}

/* -------------------------------------------------------------------------- */
/* Domain records                                                              */
/* -------------------------------------------------------------------------- */

export interface RecipientRecord {
  /** Raw envelope recipient. Never returned by the HTTP surface (except for the
   *  per-recipient breakdown of an accepted send, which the IR mandates). */
  address: string;
  /** Salted (HMAC) pseudonym used for filters and read projections. */
  recipient_hash: string;
}

export interface MessageRecord {
  id: string;
  tenant_id: string;
  request_id: string;
  from_addr: string;
  to_addr: string;
  cc_addrs: string[];
  bcc_addrs: string[];
  recipient_hashes: string[];
  subject: string;
  status: MessageStatus;
  delivery: MessageStatus;
  /** True only when the upstream MX returned a final `250` after `DATA`. */
  deliveryConfirmed: boolean;
  smtp_code: number | null;
  /** Sanitized post-AUTH reply line. Never a full transcript. */
  smtp_response: string | null;
  dkim_signed: boolean;
  mode: "direct" | "relay" | "local";
  attempts: number;
  last_error: { code: string; message: string } | null;
  tags: string[];
  created_at: string;
  queued_at: string | null;
  accepted_at: string | null;
  delivered_at: string | null;
  updated_at: string;
  /** Body content. Only exposed under `body:read` + `include_body=true`. */
  body_text: string | null;
  body_html: string | null;
  /** Set when the operator asked for the message to be requeued. */
  retryable: boolean;
}

export interface BounceRecord {
  id: string;
  tenant_id: string;
  message_id: string;
  request_id: string;
  recipient_hash: string;
  /** DSN enhanced status code, e.g. `5.1.1`. */
  code: string;
  enhanced_code: string;
  class: "hard" | "soft";
  /** Stable reason slug. The raw remote text is never stored in the projection. */
  reason: string;
  remote_mta: string;
  action_taken: "suppressed" | "deferred" | "none";
  occurred_at: string;
}

export interface SuppressionRecord {
  id: string;
  tenant_id: string;
  email: string;
  reason:
    | "manual"
    | "hard_bounce"
    | "soft_bounce"
    | "complaint"
    | "unsubscribe";
  scope: "global" | "domain";
  domain: string | null;
  expires_at: string | null;
  detail: string | null;
  created_at: string;
}

export interface MessageFilter {
  status?: MessageStatus[];
  delivery?: MessageStatus[];
  recipient_hash?: string;
  /** Inclusive lower bound on `created_at` (RFC3339). */
  from?: string;
  /** Exclusive upper bound on `created_at` (RFC3339). */
  to?: string;
  domain?: string;
  request_id?: string;
  tag?: string[];
}

/* -------------------------------------------------------------------------- */
/* Ports                                                                        */
/* -------------------------------------------------------------------------- */

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  has_more: boolean;
  limit: number;
}

/** Durable message journal (§6.1, §6.2). */
export interface MessageStore {
  list(
    tenant_id: string,
    filter: MessageFilter,
    limit: number,
    cursor: { created_at: string; id: string } | null,
  ): Promise<Page<MessageRecord>>;
  get(tenant_id: string, id: string): Promise<MessageRecord | null>;
  /**
   * Look up the message that carries a logical-send identity
   * `(tenant_id, "send", request_id)` — the layer-2 idempotency key (§5.2).
   */
  findByRequestId(tenant_id: string, request_id: string): Promise<MessageRecord | null>;
  insert(message: MessageRecord): Promise<void>;
  update(tenant_id: string, id: string, patch: Partial<MessageRecord>): Promise<MessageRecord | null>;
  /** Messages that are eligible for a requeue. */
  count(tenant_id: string): Promise<number>;
  /** Aggregate buckets for `/v1/stats`. */
  aggregate(
    tenant_id: string,
    window: { from?: string; to?: string; domain?: string },
    group_by: "status" | "domain" | "day" | "tag",
  ): Promise<{ totals: Record<string, number>; buckets: StatsBucket[] }>;
}

export interface StatsBucket {
  key: string;
  sent: number;
  delivered: number;
  deferred: number;
  bounced: number;
  suppressed: number;
  rejected: number;
  delivery_rate: number | null;
}

export interface BounceStore {
  list(
    tenant_id: string,
    filter: {
      from?: string;
      to?: string;
      domain?: string;
      code?: string[];
      recipient_hash?: string;
    },
    limit: number,
    cursor: { occurred_at: string; id: string } | null,
  ): Promise<Page<BounceRecord>>;
  insert(bounce: BounceRecord): Promise<void>;
  /** Idempotent DSN ingestion keyed by `Original-Message-ID` + recipient. */
  hasSeen(tenant_id: string, message_id: string, recipient_hash: string): Promise<boolean>;
}

export interface SuppressionStore {
  get(tenant_id: string, email: string, scope: "global" | "domain", domain?: string | null): Promise<SuppressionRecord | null>;
  upsert(record: SuppressionRecord): Promise<{ record: SuppressionRecord; created: boolean }>;
  count(tenant_id: string): Promise<number>;
}

/**
 * Durable outbox queue. The HTTP surface only *admits* to the queue; the
 * delivery engine (unit D) drains it.
 */
export interface OutboxQueue {
  enqueue(entry: {
    tenant_id: string;
    message_id: string;
    recipient: string;
    request_id: string;
    enqueued_at: string;
  }): Promise<void>;
  depth(): Promise<number>;
}

export interface IdempotencyRecord {
  /** `${principal_id}|${method}|${path_template}|${key}` */
  scope_key: string;
  /** Canonical SHA-256 digest of the normalized request body. */
  body_digest: string;
  status: number;
  headers: Record<string, string>;
  body: unknown;
  created_at: string;
  expires_at: string;
}

export interface IdempotencyStore {
  /** Atomically reserve the key. Returns `null` when the key was free. */
  reserve(record: IdempotencyRecord): Promise<boolean>;
  get(scope_key: string): Promise<IdempotencyRecord | null>;
  complete(
    scope_key: string,
    result: { status: number; headers: Record<string, string>; body: unknown },
  ): Promise<void>;
}

/** Append-only audit stream (§9.3). */
export interface AuditLog {
  append(record: {
    ts: string;
    event: string;
    actor: string;
    resource: string | null;
    tenant_id: string | null;
    request_id: string;
    outcome: "ok" | "denied" | "error";
    detail: Record<string, unknown>;
  }): Promise<void>;
}

/**
 * Policy evaluation performed before a message is queued (unit E owns the
 * internals; the HTTP surface only renders the decision).
 */
export interface PolicyDecision {
  allowed: boolean;
  /** Per-recipient outcome; one entry per envelope recipient. */
  recipients: Array<{
    address: string;
    allowed: boolean;
    status: "queued" | "suppressed" | "rejected" | "deferred";
    reason?: string;
    /** Present when the recipient was rejected by a policy rule. */
    error_code?: string;
    details?: Record<string, unknown>;
  }>;
  /** Message-level rejection (e.g. spam score, policy contradiction). */
  rejection?: {
    code: string;
    details?: Record<string, unknown>;
  };
}

/** The policy engine port used by the send route. */
export interface PolicyEngine {
  evaluate(input: {
    tenant_id: string;
    principal: Principal;
    recipients: string[];
    subject: string;
    text: string | null;
    html: string | null;
    from: string;
    size_bytes: number;
  }): Promise<PolicyDecision>;
}

/** Sender-domain verification state owned by unit E. */
export interface DomainRegistry {
  isVerified(tenant_id: string, domain: string): boolean;
  /**
   * The tenant's verified sending domains. A principal may send from any of
   * them even when its own credential does not enumerate them (e.g. a JWT
   * whose claims carry no `allowed_senders`).
   */
  verifiedSenderDomains(tenant_id: string): string[];
  defaultSender(tenant_id: string): string | null;
}

/** Readiness probes (§6.5). */
export interface ReadinessProbe {
  name: string;
  check(): Promise<{ status: "ok" | "warn" | "error"; detail: string }>;
}

/* -------------------------------------------------------------------------- */
/* Service configuration                                                        */
/* -------------------------------------------------------------------------- */

export interface HttpConfig {
  host: string;
  port: number;
  body_limit_bytes: number;
  request_timeout_ms: number;
  idempotency_ttl_hours: number;
  metrics_public: boolean;
  readiness_public: boolean;
  trust_proxy: boolean;
  cors_allow_origins: string[];
  /** Per-API-key request budget per minute (§8.4). */
  rate_limit_per_minute: number;
  /** Maximum body size accepted by the policy engine (1 MiB default). */
  max_body_bytes: number;
  max_attachment_bytes: number;
  max_recipients_per_message: number;
  /** HMAC secret for signed pagination cursors. */
  cursor_secret: string;
  /** Shared secret for `POST /v1/events` HMAC authentication. */
  webhook_secret: string;
}

/* -------------------------------------------------------------------------- */
/* Clock and ID generation                                                       */
/* -------------------------------------------------------------------------- */

export interface Clock {
  now(): Date;
}

export interface IdGenerator {
  /** Message identifier, e.g. `rg-01J8…`. */
  messageId(tenant_id: string, request_id: string): string;
  /** Correlation identifier, e.g. `rq_01J8…`. */
  requestId(): string;
  /** RFC 5322 `Message-ID` header value. Deterministic per logical send. */
  messageIdHeader(message_id: string): string;
}

export const systemClock: Clock = { now: () => new Date() };
