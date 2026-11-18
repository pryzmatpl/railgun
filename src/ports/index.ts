// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Ports the policy engine depends on. Every port is an interface so that the
// engine never reaches for a Node builtin or a third-party service
// (IR R-4.1, R-4.2).
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §4.3,
// §5.1, §9.1.2, §10.1.5, §14.1.

import type {
  BlocklistEntry,
  DkimKeyRecord,
  ReputationCounters,
  SuppressionEntry,
  SuppressionReason,
  WarmupState,
} from "../domain/identity.js";
import type { PolicyDecisionRecord } from "../domain/policy.js";

/**
 * Injected clock. Time MUST be injected so a decision can be replayed
 * (IR R-4.3).
 */
export interface Clock {
  /** Milliseconds since the Unix epoch. */
  now(): number;
  /** Current instant as an ISO-8601 UTC string. */
  nowIso(): string;
}

/** A system clock. The only place in the policy path that reads real time. */
export const systemClock: Clock = {
  now: () => Date.now(),
  nowIso: () => new Date().toISOString(),
};

/** A fixed clock, for deterministic tests. */
export function fixedClock(at: number | string): Clock {
  const ms = typeof at === "number" ? at : Date.parse(at);
  return {
    now: () => ms,
    nowIso: () => new Date(ms).toISOString(),
  };
}

/**
 * Durable suppression store (IR §10.1.5). Implementations MUST make add and
 * remove atomic and durable.
 */
export interface SuppressionStore {
  /** Returns the active suppression for a recipient, if any. */
  find(
    tenantId: string,
    domain: string | null,
    recipient: string,
    at: number,
  ): Promise<SuppressionEntry | null>;
  /** Adds (or refreshes) a suppression entry. */
  add(entry: SuppressionEntry): Promise<void>;
  /** Removes a suppression entry by id. */
  remove(id: string): Promise<boolean>;
  /** Lists entries, optionally filtered by tenant. */
  list(tenantId?: string): Promise<readonly SuppressionEntry[]>;
}

/** Durable local blocklist store (IR R-10.2.2). */
export interface BlocklistStore {
  /** Returns every active entry matching the supplied subject. */
  match(subject: BlocklistSubject): Promise<readonly BlocklistEntry[]>;
  add(entry: BlocklistEntry): Promise<void>;
  remove(id: string): Promise<boolean>;
  list(tenantId?: string): Promise<readonly BlocklistEntry[]>;
}

/**
 * The subject a blocklist is matched against. A hit on any dimension is a
 * block (IR R-10.2.1).
 */
export interface BlocklistSubject {
  readonly recipient_address?: string;
  readonly recipient_domain?: string;
  readonly sender_address?: string;
  readonly sender_domain?: string;
  readonly tenant_id?: string;
  readonly source_ip?: string;
  readonly feedback_source?: string;
  readonly content_hash?: string;
}

/**
 * Remote blocklist source (URIBL-style). A fetch failure MUST follow the
 * per-list fail policy and MUST NOT block all mail unless the list is
 * explicitly `fail_closed` (IR R-10.2.2).
 */
export interface RemoteBlocklistClient {
  /** Returns true when the remote list reports the subject as listed. */
  isListed(
    listName: string,
    subject: BlocklistSubject,
  ): Promise<{ listed: boolean; failed: boolean }>;
}

/**
 * Durable rate-limit / quota counter store. The state MUST be shareable
 * across replicas (IR R-9.1.2) and durable (IR R-9.2.2).
 */
export interface RateLimitStore {
  /**
   * Atomically consumes one token from a token bucket.
   *
   * Returns `{ allowed, retryAfterSeconds }`. When `allowed` is false the
   * bucket was not charged.
   */
  consume(
    key: string,
    capacity: number,
    refillPerSecond: number,
    cost: number,
    nowMs: number,
  ): Promise<{ allowed: boolean; retryAfterSeconds: number }>;

  /**
   * Atomically reserves quota units. Returns `{ allowed, resetAtMs }`; the
   * reservation is taken only when `allowed` is true (IR R-9.2.3).
   */
  reserveQuota(
    key: string,
    limit: number,
    cost: number,
    windowMs: number,
    nowMs: number,
  ): Promise<{ allowed: boolean; resetAtMs: number; used: number }>;

  /** Reads the current usage of a quota key without charging it. */
  peekQuota(key: string, nowMs: number): Promise<number>;
}

/**
 * The verified-recipient set of a tenant (IR §9.3.4).
 */
export interface VerifiedRecipientStore {
  isVerified(tenantId: string, recipient: string): Promise<boolean>;
  add(tenantId: string, recipient: string): Promise<void>;
  remove(tenantId: string, recipient: string): Promise<boolean>;
}

/**
 * Sending-domain identity registry (IR §7.4).
 */
export interface SendingDomainStore {
  get(tenantId: string, domain: string): Promise<SendingDomainRecord | null>;
  list(tenantId: string): Promise<readonly SendingDomainRecord[]>;
  save(record: SendingDomainRecord): Promise<void>;
}

/** The stored form of a sending domain. */
export interface SendingDomainRecord {
  readonly domain: string;
  readonly tenant_id: string;
  readonly status: "pending" | "verified" | "disabled";
  readonly dkim_selector: string;
  readonly dkim_algorithm: "rsa-sha256" | "ed25519";
  readonly dkim_key_ref: string;
  readonly spf_requirement: "disabled" | "warn" | "required";
  readonly dmarc_posture: "aligned" | "relaxed_only" | "mismatched" | "unknown";
  readonly dmarc_failure_policy: "fail_open" | "fail_closed";
  readonly alignment_mode: "strict" | "relaxed";
  readonly authorized_subdomains: readonly string[];
  readonly warmup_state: WarmupState;
  readonly created_at: string;
}

/**
 * DKIM key registry. Only public material and a **secret reference** are
 * stored; the private key lives outside the database (IR R-7.1.2, R-7.1.3).
 */
export interface DkimKeyStore {
  /** Returns the active key for a domain, or `null`. */
  findActive(domain: string): Promise<DkimKeyRecord | null>;
  list(domain: string): Promise<readonly DkimKeyRecord[]>;
  save(record: DkimKeyRecord): Promise<void>;
  revoke(domain: string, selector: string): Promise<boolean>;
}

/**
 * Loads DKIM private key material from outside the database. The loader is
 * the only component that ever touches private material (IR R-7.1.3).
 */
export interface DkimPrivateKeyLoader {
  /**
   * Returns the private key for a secret reference, or `null` when it cannot
   * be loaded. Implementations MUST NOT log the material.
   */
  load(secretRef: string): Promise<CryptoKeyMaterial | null>;
}

/** Private key material, as handed to the signer. */
export interface CryptoKeyMaterial {
  /** PEM text (RSA) or base64 raw key (ed25519). */
  readonly pem: string;
  readonly algorithm: "rsa-sha256" | "ed25519";
}

/**
 * DNS resolver used for SPF/DMARC/DKIM record verification. DNS is the only
 * permitted network egress in the policy path (IR R-4.2).
 */
export interface DnsResolver {
  /** Resolves TXT records. Returns an empty array when none exist. */
  resolveTxt(name: string): Promise<readonly string[]>;
}

/** The parsed outcome of a DMARC lookup (IR §7.3.2). */
export interface DmarcPostureRecord {
  readonly domain: string;
  readonly posture: "aligned" | "relaxed_only" | "mismatched" | "unknown";
  readonly policy?: "none" | "quarantine" | "reject";
  readonly subdomain_policy?: "none" | "quarantine" | "reject";
  readonly adkim?: "relaxed" | "strict";
  readonly aspf?: "relaxed" | "strict";
  readonly rua?: string;
  readonly ruf?: string;
  readonly pct?: number;
  readonly fo?: string;
  /** Set when the record could not be fetched or parsed. */
  readonly error?: string;
  /** True when several `p=` values conflicted. */
  readonly conflicting_policy?: boolean;
}

/**
 * Duplicate-content detector for the content scorer (IR R-11.1.6). The
 * implementation MUST salt or HMAC the content with a tenant-scoped secret.
 */
export interface DuplicateContentStore {
  /** Records the HMAC of a message; returns true when it was seen recently. */
  recordAndCheck(tenantId: string, hmac: string, windowSeconds: number): Promise<boolean>;
}

/** Reputation counters store (IR §9.4). */
export interface ReputationStore {
  get(subject: string): Promise<ReputationCounters>;
  increment(subject: string, deltas: Partial<ReputationCounters>): Promise<ReputationCounters>;
}

/** Warmup usage counters, keyed by tenant + domain + day (IR §9.3.2). */
export interface WarmupStore {
  /** Current usage for the given warmup day window. */
  usage(tenantId: string, domain: string, dayKey: string): Promise<number>;
  /** Atomically reserves `cost` units against the warmup window. */
  reserve(
    tenantId: string,
    domain: string,
    dayKey: string,
    cost: number,
    limit: number,
  ): Promise<{ allowed: boolean; used: number }>;
}

/**
 * The audit sink. Policy decisions MUST be durably written before they are
 * reported as final (IR R-5.2.3, R-14.1.7).
 */
export interface AuditSink {
  /**
   * Appends one decision event. Must be durable and tamper-evident.
   * Throwing signals that the audit write failed.
   */
  append(record: PolicyDecisionRecord, metadata?: Readonly<Record<string, unknown>>): Promise<void>;
}

/**
 * Feedback ingestion result. Feedback MUST be authenticated before it may
 * change policy state (IR R-10.4.1).
 */
export interface FeedbackOutcome {
  readonly accepted: boolean;
  readonly reason: string;
  /** Suppression entries created by this feedback. */
  readonly created: readonly SuppressionEntry[];
  /** Reason class of the created suppression, if any. */
  readonly suppression_reason?: SuppressionReason;
}

/**
 * Feedback sink — authenticated DSN / FBL ingestion (IR §10.4).
 */
export interface FeedbackSink {
  ingest(
    payload: string,
    secret: string,
    at: number,
  ): Promise<FeedbackOutcome>;
}
