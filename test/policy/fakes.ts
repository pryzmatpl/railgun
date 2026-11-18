// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// In-memory fakes for the policy engine's ports.
//
// These live in the test tree so the production package stays free of test
// doubles. They implement the same contracts as the durable stores, so the
// engine cannot tell the difference — which is what makes the zero-SMTP-
// transaction assertions meaningful.

import type {
  AuditSink,
  BlocklistStore,
  Clock,
  DkimKeyStore,
  DkimPrivateKeyLoader,
  DnsResolver,
  DuplicateContentStore,
  RateLimitStore,
  ReputationStore,
  SendingDomainStore,
  SuppressionStore,
  VerifiedRecipientStore,
  WarmupStore,
} from "../../src/ports/index.js";
import type {
  BlocklistEntry,
  DkimKeyRecord,
  ReputationCounters,
  SuppressionEntry,
} from "../../src/domain/identity.js";
import type { SendingDomainRecord } from "../../src/ports/index.js";
import type { PolicyDecisionRecord } from "../../src/domain/policy.js";

/** A clock the test controls. */
export class TestClock implements Clock {
  #ms: number;
  constructor(at: number | string = "2026-11-18T12:00:00.000Z") {
    this.#ms = typeof at === "number" ? at : Date.parse(at);
  }
  now(): number {
    return this.#ms;
  }
  nowIso(): string {
    return new Date(this.#ms).toISOString();
  }
  advance(ms: number): void {
    this.#ms += ms;
  }
}

/** An in-memory suppression store. */
export class MemorySuppressionStore implements SuppressionStore {
  readonly entries: SuppressionEntry[] = [];
  async find(
    tenantId: string,
    domain: string | null,
    recipient: string,
    at: number,
  ): Promise<SuppressionEntry | null> {
    for (const entry of this.entries) {
      if (entry.recipient.toLowerCase() !== recipient.toLowerCase()) {
        continue;
      }
      // A domain-scoped entry belongs to one tenant's sending domain and
      // MUST NOT apply to another tenant (IR R-10.1.2).
      if (entry.scope === "domain" && entry.tenant_id !== tenantId) {
        continue;
      }
      if (entry.expires_at !== null && Date.parse(entry.expires_at) <= at) {
        continue;
      }
      if (entry.scope === "domain" && entry.domain !== domain) {
        continue;
      }
      return entry;
    }
    return null;
  }
  async add(entry: SuppressionEntry): Promise<void> {
    this.entries.push(entry);
  }
  async remove(id: string): Promise<boolean> {
    const index = this.entries.findIndex((e) => e.id === id);
    if (index < 0) {
      return false;
    }
    this.entries.splice(index, 1);
    return true;
  }
  async list(tenantId?: string): Promise<readonly SuppressionEntry[]> {
    return tenantId === undefined
      ? this.entries
      : this.entries.filter((e) => e.tenant_id === tenantId);
  }
}

/** An in-memory blocklist store. */
export class MemoryBlocklistStore implements BlocklistStore {
  readonly entries: BlocklistEntry[] = [];
  async match(subject: {
    recipient_address?: string;
    recipient_domain?: string;
    sender_address?: string;
    sender_domain?: string;
    tenant_id?: string;
    source_ip?: string;
    feedback_source?: string;
    content_hash?: string;
  }): Promise<readonly BlocklistEntry[]> {
    const hits: BlocklistEntry[] = [];
    for (const entry of this.entries) {
      if (entry.tenant_id !== null && entry.tenant_id !== subject.tenant_id) {
        continue;
      }
      const value = entry.value.toLowerCase();
      const matched =
        (entry.kind === "recipient_address" &&
          subject.recipient_address?.toLowerCase() === value) ||
        (entry.kind === "recipient_domain" &&
          subject.recipient_domain?.toLowerCase() === value) ||
        (entry.kind === "sender_address" &&
          subject.sender_address?.toLowerCase() === value) ||
        (entry.kind === "sender_domain" &&
          subject.sender_domain?.toLowerCase() === value) ||
        (entry.kind === "tenant" && subject.tenant_id?.toLowerCase() === value) ||
        (entry.kind === "source_ip" && subject.source_ip === value) ||
        (entry.kind === "feedback_source" && subject.feedback_source === value) ||
        (entry.kind === "content_hash" && subject.content_hash === value);
      if (matched) {
        hits.push(entry);
      }
    }
    return hits;
  }
  async add(entry: BlocklistEntry): Promise<void> {
    this.entries.push(entry);
  }
  async remove(id: string): Promise<boolean> {
    const index = this.entries.findIndex((e) => e.id === id);
    if (index < 0) {
      return false;
    }
    this.entries.splice(index, 1);
    return true;
  }
  async list(tenantId?: string): Promise<readonly BlocklistEntry[]> {
    return tenantId === undefined
      ? this.entries
      : this.entries.filter((e) => e.tenant_id === null || e.tenant_id === tenantId);
  }
}

/** A token-bucket + quota store, entirely in memory. */
export class MemoryRateLimitStore implements RateLimitStore {
  readonly buckets = new Map<string, { tokens: number; updatedAt: number }>();
  readonly quotas = new Map<string, { used: number; windowStart: number }>();

  async consume(
    key: string,
    capacity: number,
    refillPerSecond: number,
    cost: number,
    nowMs: number,
  ): Promise<{ allowed: boolean; retryAfterSeconds: number }> {
    const state = this.buckets.get(key);
    const current = state ?? { tokens: capacity, updatedAt: nowMs };
    const elapsedSeconds = Math.max(0, (nowMs - current.updatedAt) / 1000);
    current.tokens = Math.min(capacity, current.tokens + elapsedSeconds * refillPerSecond);
    current.updatedAt = nowMs;
    if (current.tokens < cost) {
      this.buckets.set(key, current);
      const deficit = cost - current.tokens;
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil(deficit / refillPerSecond)),
      };
    }
    current.tokens -= cost;
    this.buckets.set(key, current);
    return { allowed: true, retryAfterSeconds: 0 };
  }

  async reserveQuota(
    key: string,
    limit: number,
    cost: number,
    windowMs: number,
    nowMs: number,
  ): Promise<{ allowed: boolean; resetAtMs: number; used: number }> {
    const state = this.quotas.get(key);
    const windowStart = state?.windowStart ?? nowMs;
    const expired = nowMs - windowStart >= windowMs;
    const used = expired ? 0 : (state?.used ?? 0);
    if (used + cost > limit) {
      this.quotas.set(key, { used, windowStart });
      return { allowed: false, resetAtMs: windowStart + windowMs, used };
    }
    this.quotas.set(key, { used: used + cost, windowStart });
    return { allowed: true, resetAtMs: windowStart + windowMs, used: used + cost };
  }

  async peekQuota(key: string, nowMs: number): Promise<number> {
    const state = this.quotas.get(key);
    if (state === undefined) {
      return 0;
    }
    if (nowMs - state.windowStart >= 86_400_000) {
      return 0;
    }
    return state.used;
  }
}

/** An in-memory verified-recipient set. */
export class MemoryVerifiedRecipientStore implements VerifiedRecipientStore {
  readonly verified = new Set<string>();
  async isVerified(tenantId: string, recipient: string): Promise<boolean> {
    return this.verified.has(`${tenantId}:${recipient.toLowerCase()}`);
  }
  async add(tenantId: string, recipient: string): Promise<void> {
    this.verified.add(`${tenantId}:${recipient.toLowerCase()}`);
  }
  async remove(tenantId: string, recipient: string): Promise<boolean> {
    return this.verified.delete(`${tenantId}:${recipient.toLowerCase()}`);
  }
}

/** An in-memory warmup store. */
export class MemoryWarmupStore implements WarmupStore {
  readonly counters = new Map<string, number>();
  async usage(tenantId: string, domain: string, dayKey: string): Promise<number> {
    return this.counters.get(`${tenantId}:${domain}:${dayKey}`) ?? 0;
  }
  async reserve(
    tenantId: string,
    domain: string,
    dayKey: string,
    cost: number,
    limit: number,
  ): Promise<{ allowed: boolean; used: number }> {
    const key = `${tenantId}:${domain}:${dayKey}`;
    const used = this.counters.get(key) ?? 0;
    if (used + cost > limit) {
      return { allowed: false, used };
    }
    this.counters.set(key, used + cost);
    return { allowed: true, used: used + cost };
  }
}

/** An in-memory reputation counter store. */
export class MemoryReputationStore implements ReputationStore {
  readonly counters = new Map<string, ReputationCounters>();
  async get(subject: string): Promise<ReputationCounters> {
    return (
      this.counters.get(subject) ?? {
        sends: 0,
        complaints: 0,
        hard_bounces: 0,
        defers: 0,
        trap_hits: 0,
      }
    );
  }
  async increment(
    subject: string,
    deltas: Partial<ReputationCounters>,
  ): Promise<ReputationCounters> {
    const current = await this.get(subject);
    const next: ReputationCounters = {
      sends: current.sends + (deltas.sends ?? 0),
      complaints: current.complaints + (deltas.complaints ?? 0),
      hard_bounces: current.hard_bounces + (deltas.hard_bounces ?? 0),
      defers: current.defers + (deltas.defers ?? 0),
      trap_hits: current.trap_hits + (deltas.trap_hits ?? 0),
    };
    this.counters.set(subject, next);
    return next;
  }
}

/** A duplicate-content detector. */
export class MemoryDuplicateContentStore implements DuplicateContentStore {
  readonly seen = new Map<string, number>();
  async recordAndCheck(
    tenantId: string,
    hmac: string,
    windowSeconds: number,
  ): Promise<boolean> {
    const key = `${tenantId}:${hmac}`;
    const at = this.seen.get(key);
    if (at !== undefined && Date.now() - at < windowSeconds * 1000) {
      return true;
    }
    this.seen.set(key, Date.now());
    return false;
  }
}

/** An in-memory DKIM key registry. */
export class MemoryDkimKeyStore implements DkimKeyStore {
  readonly keys: DkimKeyRecord[] = [];
  async findActive(domain: string): Promise<DkimKeyRecord | null> {
    return (
      this.keys.find((k) => k.domain === domain && k.status === "active") ?? null
    );
  }
  async list(domain: string): Promise<readonly DkimKeyRecord[]> {
    return this.keys.filter((k) => k.domain === domain);
  }
  async save(record: DkimKeyRecord): Promise<void> {
    this.keys.push(record);
  }
  async revoke(domain: string, selector: string): Promise<boolean> {
    const index = this.keys.findIndex(
      (k) => k.domain === domain && k.selector === selector,
    );
    if (index < 0) {
      return false;
    }
    const existing = this.keys[index];
    if (existing === undefined) {
      return false;
    }
    this.keys[index] = { ...existing, status: "revoked" };
    return true;
  }
}

/** A private-key loader that returns a fixed PEM. */
export class StaticDkimKeyLoader implements DkimPrivateKeyLoader {
  #pem: string | null;
  constructor(pem: string | null) {
    this.#pem = pem;
  }
  async load(_secretRef: string): Promise<{ pem: string; algorithm: "rsa-sha256" } | null> {
    if (this.#pem === null) {
      return null;
    }
    return { pem: this.#pem, algorithm: "rsa-sha256" };
  }
}

/** An in-memory sending-domain registry. */
export class MemorySendingDomainStore implements SendingDomainStore {
  readonly domains = new Map<string, SendingDomainRecord>();
  async get(tenantId: string, domain: string): Promise<SendingDomainRecord | null> {
    return this.domains.get(`${tenantId}:${domain}`) ?? null;
  }
  async list(tenantId: string): Promise<readonly SendingDomainRecord[]> {
    return [...this.domains.values()].filter((d) => d.tenant_id === tenantId);
  }
  async save(record: SendingDomainRecord): Promise<void> {
    this.domains.set(`${record.tenant_id}:${record.domain}`, record);
  }
}

/** A DNS resolver driven by a static zone map. */
export class StaticDnsResolver implements DnsResolver {
  readonly zones: Map<string, string[]>;
  constructor(zones: Record<string, string[]> = {}) {
    this.zones = new Map(Object.entries(zones));
  }
  async resolveTxt(name: string): Promise<readonly string[]> {
    return this.zones.get(name.toLowerCase()) ?? [];
  }
}

/** An audit sink that records every decision event. */
export class RecordingAuditSink implements AuditSink {
  readonly events: PolicyDecisionRecord[] = [];
  /** When set, `append` throws — used to test the strict fail-closed path. */
  failWith: Error | null = null;
  async append(record: PolicyDecisionRecord): Promise<void> {
    if (this.failWith !== null) {
      throw this.failWith;
    }
    this.events.push(record);
  }
}

/** A helper to build a warmup-aware sending-domain record. */
export function sendingDomainRecord(
  overrides: Partial<SendingDomainRecord> = {},
): SendingDomainRecord {
  return {
    domain: "example.com",
    tenant_id: "tenant-1",
    status: "verified",
    dkim_selector: "railgun1",
    dkim_algorithm: "rsa-sha256",
    dkim_key_ref: "file:///keys/railgun1.pem",
    spf_requirement: "disabled",
    dmarc_posture: "aligned",
    dmarc_failure_policy: "fail_open",
    alignment_mode: "strict",
    authorized_subdomains: [],
    warmup_state: "warm",
    created_at: "2020-01-01T00:00:00.000Z",
    ...overrides,
  };
}
