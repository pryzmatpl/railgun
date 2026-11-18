/* RailGun deterministic in-memory persistence adapter. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { IdempotencyConflictError, PersistenceError } from "./errors.js";
import type {
  AuditStore,
  AuditVerification,
  BounceQuery,
  BounceStore,
  Clock,
  IdempotencyStore,
  IdGenerator,
  LeaseRequest,
  MessageQuery,
  MessageStore,
  OutboxStore,
  RailGunStore,
  SuppressionStore,
} from "./ports.js";
import type {
  AuditEventInput,
  AuditRecord,
  BounceRecord,
  DeliveryAttempt,
  EnvelopeRecipient,
  IdempotencyRecord,
  Message,
  OutboxItem,
  RetentionPolicy,
  Suppression,
} from "./types.js";
import { appendAuditRecord, verifyAuditRecords } from "./audit.js";

const transitions: Readonly<Record<EnvelopeRecipient["status"], readonly EnvelopeRecipient["status"][]>> = {
  pending: ["leased", "suppressed", "bounced"],
  leased: ["deferred", "accepted", "delivered", "bounced", "suppressed", "failed", "pending"],
  deferred: ["leased", "suppressed", "failed"],
  accepted: ["delivered", "failed"],
  delivered: [],
  bounced: [],
  suppressed: [],
  failed: [],
};

function clone<T>(value: T): T {
  if (value instanceof Uint8Array) return new Uint8Array(value) as T;
  if (Array.isArray(value)) return value.map((item) => clone(item)) as T;
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, clone(v)])) as T;
  return value;
}

export class MemoryStore implements RailGunStore {
  readonly messages: MessageStore;
  readonly outbox: OutboxStore;
  readonly idempotency: IdempotencyStore;
  readonly suppressions: SuppressionStore;
  readonly bounces: BounceStore;
  readonly audit: AuditStore;
  private readonly messageMap = new Map<string, Message>();
  private readonly envelopeMap = new Map<string, EnvelopeRecipient>();
  private readonly attemptMap = new Map<string, DeliveryAttempt[]>();
  private readonly outboxMap = new Map<string, OutboxItem>();
  private readonly idempotencyMap = new Map<string, IdempotencyRecord>();
  private readonly suppressionMap = new Map<string, Suppression>();
  private readonly bounceMap = new Map<string, BounceRecord>();
  private readonly auditRecords: AuditRecord[] = [];
  private sequence = 0;
  private fault: "accept" | "audit" | null = null;

  constructor(readonly clock: Clock, readonly ids: IdGenerator) {
    this.messages = this.createMessageStore();
    this.outbox = this.createOutboxStore();
    this.idempotency = this.createIdempotencyStore();
    this.suppressions = this.createSuppressionStore();
    this.bounces = this.createBounceStore();
    this.audit = this.createAuditStore();
  }

  failNext(operation: "accept" | "audit"): void {
    this.fault = operation;
  }

  inspect(): {
    messages: readonly Message[];
    envelopes: readonly EnvelopeRecipient[];
    outbox: readonly OutboxItem[];
    idempotency: readonly IdempotencyRecord[];
    suppressions: readonly Suppression[];
    bounces: readonly BounceRecord[];
    auditHead: { sequence: number; digest: string };
  } {
    return {
      messages: [...this.messageMap.values()].map((v) => clone(v)),
      envelopes: [...this.envelopeMap.values()].map((v) => clone(v)),
      outbox: [...this.outboxMap.values()].map((v) => clone(v)),
      idempotency: [...this.idempotencyMap.values()].map((v) => clone(v)),
      suppressions: [...this.suppressionMap.values()].map((v) => clone(v)),
      bounces: [...this.bounceMap.values()].map((v) => clone(v)),
      auditHead: this.auditRecords.at(-1)
        ? { sequence: this.auditRecords.at(-1)!.sequence, digest: this.auditRecords.at(-1)!.digest }
        : { sequence: 0, digest: "0".repeat(64) },
    };
  }

  async accept(input: import("./accept.js").AcceptInput): Promise<{ message: Message; envelopes: readonly EnvelopeRecipient[]; outbox: readonly OutboxItem[] }> {
    if (this.fault === "accept") {
      this.fault = null;
      throw new Error("Injected acceptance failure");
    }
    const existing = this.idempotencyMap.get(input.idempotency.key);
    if (existing?.state === "committed") {
      if (existing.requestDigest !== input.idempotency.requestDigest) throw new IdempotencyConflictError(input.idempotency.key);
      const message = this.messageMap.get(existing.messageId!);
      if (!message) throw new PersistenceError("CONFLICT", "Committed idempotency record has no message");
      return { message: clone(message), envelopes: await this.messages.envelopes(message.id), outbox: [] };
    }
    const message = clone(input.message);
    const envelopes = input.envelopes.map((v) => clone(v));
    const outbox = input.outbox.map((v) => ({ ...clone(v), acceptedSequence: ++this.sequence }));
    this.messageMap.set(message.id, message);
    for (const envelope of envelopes) this.envelopeMap.set(envelope.envelopeId, envelope);
    for (const item of outbox) this.outboxMap.set(item.id, item);
    this.idempotencyMap.set(input.idempotency.key, { ...clone(input.idempotency), messageId: message.id, response: clone(input.response), state: "committed" });
    return { message: clone(message), envelopes: envelopes.map((v) => clone(v)), outbox: outbox.map((v) => clone(v)) };
  }

  async applyRetention(policy: RetentionPolicy, now: string): Promise<Record<string, number>> {
    const nowMs = new Date(now).getTime();
    const cutoff = (days: number): string => new Date(nowMs - days * 86_400_000).toISOString();
    let messages = 0;
    let bodies = 0;
    for (const [id, message] of this.messageMap) {
      if (message.createdAt < cutoff(policy.messageMetadataDays)) { this.messageMap.delete(id); messages++; }
      else if (message.body && message.createdAt < cutoff(policy.messageBodyDays)) {
        this.messageMap.set(id, { ...message, body: null, version: message.version + 1 }); bodies++;
      }
    }
    let attempts = 0;
    for (const [id, list] of this.attemptMap) {
      const kept = list.filter((attempt) => attempt.startedAt >= cutoff(policy.attemptDays));
      attempts += list.length - kept.length;
      if (kept.length) this.attemptMap.set(id, kept); else this.attemptMap.delete(id);
    }
    let bounces = 0;
    for (const [id, bounce] of this.bounceMap) {
      if (bounce.observedAt < cutoff(policy.bounceDays)) { this.bounceMap.delete(id); bounces++; }
    }
    let idempotency = 0;
    for (const [id, record] of this.idempotencyMap) {
      if (record.expiresAt <= now) { this.idempotencyMap.delete(id); idempotency++; }
    }
    const suppressions = await this.suppressions.expire(now);
    return { messages, bodies, attempts, bounces, idempotency, suppressions, audit: 0 };
  }

  private createMessageStore(): MessageStore {
    return {
      create: async (message) => { this.messageMap.set(message.id, clone(message)); return clone(message); },
      get: async (tenantId, messageId) => {
        const message = this.messageMap.get(messageId);
        return message && message.tenantId === tenantId ? clone(message) : null;
      },
      update: async (message, expectedVersion) => {
        const current = this.messageMap.get(message.id);
        if (!current) throw new PersistenceError("NOT_FOUND", "Message not found");
        if (current.version !== expectedVersion) throw new PersistenceError("STALE_VERSION", "Message version is stale");
        const next = { ...clone(message), version: current.version + 1, updatedAt: this.clock.now().toISOString() };
        this.messageMap.set(message.id, next);
        return clone(next);
      },
      list: async (query) => {
        const rows = [...this.messageMap.values()]
          .filter((m) => m.tenantId === query.tenantId)
          .filter((m) => !query.status || m.status === query.status)
          .filter((m) => !query.recipient || m.recipients.includes(query.recipient))
          .filter((m) => !query.createdAfter || m.createdAt >= query.createdAfter)
          .filter((m) => !query.createdBefore || m.createdAt < query.createdBefore)
          .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
        return rows.slice(0, query.limit ?? 100).map((v) => clone(v));
      },
      envelopes: async (messageId) => [...this.envelopeMap.values()].filter((e) => e.messageId === messageId).map((v) => clone(v)),
      updateEnvelope: async (envelope, expectedVersion) => {
        const current = this.envelopeMap.get(envelope.envelopeId);
        if (!current) throw new PersistenceError("NOT_FOUND", "Envelope not found");
        if (current.version !== expectedVersion) throw new PersistenceError("STALE_VERSION", "Envelope version is stale");
        if (!transitions[current.status].includes(envelope.status)) {
          throw new PersistenceError("INVALID_TRANSITION", `Cannot transition envelope from ${current.status} to ${envelope.status}`);
        }
        const next = { ...clone(envelope), version: current.version + 1, updatedAt: this.clock.now().toISOString() };
        this.envelopeMap.set(envelope.envelopeId, next);
        return clone(next);
      },
      appendAttempt: async (attempt) => {
        const list = this.attemptMap.get(attempt.envelopeId) ?? [];
        list.push(clone(attempt));
        this.attemptMap.set(attempt.envelopeId, list);
        return clone(attempt);
      },
      attempts: async (envelopeId) => (this.attemptMap.get(envelopeId) ?? []).map((v) => clone(v)),
      deleteExpired: async (tenantId, before, bodyBefore) => {
        let deleted = 0;
        let bodies = 0;
        for (const [id, message] of this.messageMap) {
          if (message.tenantId !== tenantId) continue;
          if (message.createdAt < before) { this.messageMap.delete(id); deleted++; }
          else if (bodyBefore && message.body && message.createdAt < bodyBefore) {
            this.messageMap.set(id, { ...message, body: null, version: message.version + 1 }); bodies++;
          }
        }
        return { messages: deleted, bodies };
      },
    };
  }

  private createOutboxStore(): OutboxStore {
    return {
      enqueue: async (items) => items.map((item) => { const next = { ...clone(item), acceptedSequence: ++this.sequence }; this.outboxMap.set(next.id, next); return clone(next); }),
      lease: async (request) => {
        const candidates = [...this.outboxMap.values()]
          .filter((i) => i.tenantId === request.tenantId && i.state === "pending" && i.availableAt <= request.now)
          .sort((a, b) => b.priority - a.priority || a.acceptedSequence - b.acceptedSequence)
          .slice(0, request.limit);
        return candidates.map((item) => {
          const next = { ...item, state: "leased" as const, leaseOwner: request.owner, leaseExpiresAt: request.leaseUntil };
          this.outboxMap.set(item.id, next);
          return clone(next);
        });
      },
      renew: async (itemId, owner, leaseUntil) => {
        const item = this.outboxMap.get(itemId);
        if (!item) throw new PersistenceError("NOT_FOUND", "Outbox item not found");
        if (item.leaseOwner !== owner) throw new PersistenceError("STALE_LEASE", "Outbox lease owner is stale");
        const next = { ...item, leaseExpiresAt: leaseUntil };
        this.outboxMap.set(itemId, next);
        return clone(next);
      },
      complete: async (itemId, owner, outcome) => {
        const item = this.outboxMap.get(itemId);
        if (!item) throw new PersistenceError("NOT_FOUND", "Outbox item not found");
        if (item.leaseOwner !== owner) throw new PersistenceError("STALE_LEASE", "Outbox lease owner is stale");
        const envelope = this.envelopeMap.get(item.envelopeId);
        if (!envelope) throw new PersistenceError("NOT_FOUND", "Envelope not found");
        if (!transitions[envelope.status].includes(outcome.status)) throw new PersistenceError("INVALID_TRANSITION", "Invalid envelope transition");
        const now = this.clock.now().toISOString();
        this.envelopeMap.set(envelope.envelopeId, { ...envelope, status: outcome.status, version: envelope.version + 1, updatedAt: now, lastSmtpCode: outcome.smtpCode ?? envelope.lastSmtpCode, lastResponse: outcome.response ?? envelope.lastResponse, errorCode: outcome.errorCode ?? envelope.errorCode });
        this.outboxMap.set(itemId, { ...item, state: "completed", leaseOwner: null, leaseExpiresAt: null });
      },
      release: async (itemId, owner, nextAttemptAt, errorCode) => {
        const item = this.outboxMap.get(itemId);
        if (!item) throw new PersistenceError("NOT_FOUND", "Outbox item not found");
        if (item.leaseOwner !== owner) throw new PersistenceError("STALE_LEASE", "Outbox lease owner is stale");
        this.outboxMap.set(itemId, { ...item, state: "pending", availableAt: nextAttemptAt, nextAttemptAt, leaseOwner: null, leaseExpiresAt: null, lastErrorCode: errorCode ?? item.lastErrorCode });
      },
      stats: async (tenantId, now) => {
        const items = [...this.outboxMap.values()].filter((i) => i.tenantId === tenantId && i.state !== "completed");
        const oldest = items.reduce<string | null>((value, item) => value === null || item.availableAt < value ? item.availableAt : value, null);
        return { depth: items.length, due: items.filter((i) => i.availableAt <= now).length, oldestAgeMs: oldest === null ? null : Math.max(0, new Date(now).getTime() - new Date(oldest).getTime()) };
      },
      reconcileExpired: async (now) => {
        let count = 0;
        for (const [id, item] of this.outboxMap) {
          if (item.state === "leased" && item.leaseExpiresAt !== null && item.leaseExpiresAt <= now) {
            this.outboxMap.set(id, { ...item, state: "pending", leaseOwner: null, leaseExpiresAt: null });
            count++;
          }
        }
        return count;
      },
    };
  }

  private createIdempotencyStore(): IdempotencyStore {
    return {
      reserve: async (record) => {
        const existing = this.idempotencyMap.get(record.key);
        if (!existing) { this.idempotencyMap.set(record.key, clone(record)); return "reserved"; }
        if (existing.requestDigest !== record.requestDigest) return "conflict";
        return existing.state === "committed" ? "replay" : "reserved";
      },
      commit: async (key, messageId, response, expiresAt) => {
        const current = this.idempotencyMap.get(key);
        if (!current) throw new PersistenceError("NOT_FOUND", "Idempotency reservation not found");
        const next = { ...current, messageId, response: clone(response), expiresAt, state: "committed" as const };
        this.idempotencyMap.set(key, next);
        return clone(next);
      },
      release: async (key) => { this.idempotencyMap.delete(key); },
      get: async (key) => { const value = this.idempotencyMap.get(key); return value ? clone(value) : null; },
      expire: async (now) => { let count = 0; for (const [key, value] of this.idempotencyMap) if (value.expiresAt <= now) { this.idempotencyMap.delete(key); count++; } return count; },
    };
  }

  private createSuppressionStore(): SuppressionStore {
    return {
      isSuppressed: async (tenantId, recipient, now) => [...this.suppressionMap.values()].some((s) => s.tenantId === tenantId && s.active && (s.expiresAt === null || s.expiresAt > now) && (s.recipient === null || s.recipient === recipient)),
      create: async (suppression) => { this.suppressionMap.set(suppression.id, clone(suppression)); return clone(suppression); },
      list: async (tenantId) => [...this.suppressionMap.values()].filter((s) => s.tenantId === tenantId).map((v) => clone(v)),
      remove: async (tenantId, id) => { const current = this.suppressionMap.get(id); if (!current || current.tenantId !== tenantId) return false; return this.suppressionMap.delete(id); },
      expire: async (now) => { let count = 0; for (const [id, value] of this.suppressionMap) if (value.expiresAt !== null && value.expiresAt <= now) { this.suppressionMap.delete(id); count++; } return count; },
    };
  }

  private createBounceStore(): BounceStore {
    const queryRows = (query: BounceQuery): BounceRecord[] => [...this.bounceMap.values()]
      .filter((b) => b.tenantId === query.tenantId)
      .filter((b) => !query.recipient || b.recipient === query.recipient)
      .filter((b) => !query.messageId || b.messageId === query.messageId)
      .filter((b) => !query.envelopeId || b.envelopeId === query.envelopeId)
      .filter((b) => !query.bounceClass || b.bounceClass === query.bounceClass)
      .filter((b) => !query.dsnClass || b.dsnClass === query.dsnClass)
      .filter((b) => !query.dsnCode || b.dsnCode === query.dsnCode)
      .filter((b) => !query.after || b.observedAt >= query.after)
      .filter((b) => !query.before || b.observedAt < query.before)
      .sort((a, b) => a.observedAt.localeCompare(b.observedAt) || a.id.localeCompare(b.id));
    return {
      append: async (bounce) => { this.bounceMap.set(bounce.id, clone(bounce)); return clone(bounce); },
      list: async (query) => queryRows(query).slice(0, query.limit ?? 100).map((v) => clone(v)),
      get: async (tenantId, id) => { const value = this.bounceMap.get(id); return value && value.tenantId === tenantId ? clone(value) : null; },
      counts: async (tenantId) => { const rows = queryRows({ tenantId }); return { hard: rows.filter((r) => r.bounceClass === "hard").length, soft: rows.filter((r) => r.bounceClass === "soft").length, complaint: rows.filter((r) => r.bounceClass === "complaint").length }; },
    };
  }

  private createAuditStore(): AuditStore {
    return {
      append: async (event: AuditEventInput) => {
        if (this.fault === "audit") { this.fault = null; throw new Error("Injected audit failure"); }
        const previous = this.auditRecords.at(-1);
        const record = appendAuditRecord(event, previous, this.clock.now().toISOString());
        this.auditRecords.push(record);
        return clone(record);
      },
      read: async (fromSequence = 1) => this.auditRecords.filter((r) => r.sequence >= fromSequence).map((v) => clone(v)),
      verify: async (): Promise<AuditVerification> => verifyAuditRecords(this.auditRecords),
      head: async () => { const last = this.auditRecords.at(-1); return last ? { sequence: last.sequence, digest: last.digest } : { sequence: 0, digest: "0".repeat(64) }; },
    };
  }
}
