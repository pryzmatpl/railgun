// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * In-memory implementations of the HTTP surface ports.
 *
 * These back the unit/integration test profile. The production profile uses
 * the SQLite-backed stores owned by unit B; the HTTP surface only depends on
 * the interfaces in `types.ts`, so both profiles share the same routes.
 */

import { canonicalDigest } from "./crypto.js";
import type {
  AuditLog,
  BounceRecord,
  BounceStore,
  Clock,
  IdempotencyRecord,
  IdempotencyStore,
  MessageFilter,
  MessageRecord,
  MessageStore,
  OutboxQueue,
  Page,
  StatsBucket,
  SuppressionRecord,
  SuppressionStore,
} from "./types.js";

/** A deterministic clock for tests. */
export class FixedClock implements Clock {
  constructor(private current: Date = new Date("2026-11-18T10:31:04.123Z")) {}

  now(): Date {
    return new Date(this.current);
  }

  set(next: Date | string): void {
    this.current = typeof next === "string" ? new Date(next) : next;
  }

  advanceMs(delta: number): void {
    this.current = new Date(this.current.getTime() + delta);
  }
}

/** Deterministic identifier generator for tests. */
export class SequentialIds {
  private counter = 0;

  messageId(tenant_id: string, request_id: string): string {
    this.counter += 1;
    return `rg-${tenant_id}-${request_id}-${this.counter}`;
  }

  requestId(): string {
    this.counter += 1;
    return `rq-${this.counter}`;
  }

  messageIdHeader(message_id: string): string {
    return `<${message_id}@railgun>`;
  }
}

/** In-memory message journal. */
export class MemoryMessageStore implements MessageStore {
  readonly records = new Map<string, MessageRecord>();

  async list(
    tenant_id: string,
    filter: MessageFilter,
    limit: number,
    cursor: { created_at: string; id: string } | null,
  ): Promise<Page<MessageRecord>> {
    const filtered = [...this.records.values()]
      .filter((record) => record.tenant_id === tenant_id)
      .filter((record) => matchesFilter(record, filter))
      .toSorted((a, b) =>
        a.created_at === b.created_at ? (a.id < b.id ? 1 : -1) : a.created_at < b.created_at ? 1 : -1,
      );
    const startIndex = cursor
      ? filtered.findIndex(
          (record) => record.created_at === cursor.created_at && record.id === cursor.id,
        ) + 1
      : 0;
    const slice = filtered.slice(startIndex, startIndex + limit);
    const hasMore = startIndex + limit < filtered.length;
    return {
      items: slice,
      next_cursor: null,
      has_more: hasMore,
      limit,
    };
  }

  async get(tenant_id: string, id: string): Promise<MessageRecord | null> {
    const record = this.records.get(id);
    if (!record || record.tenant_id !== tenant_id) {
      return null;
    }
    return record;
  }

  async findByRequestId(tenant_id: string, request_id: string): Promise<MessageRecord | null> {
    for (const record of this.records.values()) {
      if (record.tenant_id === tenant_id && record.request_id === request_id) {
        return record;
      }
    }
    return null;
  }

  async insert(message: MessageRecord): Promise<void> {
    this.records.set(message.id, message);
  }

  async update(
    tenant_id: string,
    id: string,
    patch: Partial<MessageRecord>,
  ): Promise<MessageRecord | null> {
    const record = this.records.get(id);
    if (!record || record.tenant_id !== tenant_id) {
      return null;
    }
    const updated = { ...record, ...patch };
    this.records.set(id, updated);
    return updated;
  }

  async count(tenant_id: string): Promise<number> {
    return [...this.records.values()].filter((record) => record.tenant_id === tenant_id).length;
  }

  async aggregate(
    tenant_id: string,
    window: { from?: string; to?: string; domain?: string },
    group_by: "status" | "domain" | "day" | "tag",
  ): Promise<{ totals: Record<string, number>; buckets: StatsBucket[] }> {
    const scoped = [...this.records.values()].filter((record) => {
      if (record.tenant_id !== tenant_id) {
        return false;
      }
      if (window.from && record.created_at < window.from) {
        return false;
      }
      if (window.to && record.created_at >= window.to) {
        return false;
      }
      return true;
    });
    const totals: Record<string, number> = {
      queued: 0,
      accepted: 0,
      sent: 0,
      delivered: 0,
      deferred: 0,
      bounced: 0,
      failed: 0,
      suppressed: 0,
      rejected: 0,
    };
    const bucketMap = new Map<string, StatsBucket>();
    for (const record of scoped) {
      totals[record.status] = (totals[record.status] ?? 0) + 1;
      if (record.status === "accepted") {
        totals.sent = (totals.sent ?? 0) + 1;
      }
      const key =
        group_by === "status"
          ? record.status
          : group_by === "domain"
            ? record.from_addr.split("@")[1] ?? ""
            : group_by === "day"
              ? record.created_at.slice(0, 10)
              : (record.tags[0] ?? "untagged");
      const bucket = bucketMap.get(key) ?? {
        key,
        sent: 0,
        delivered: 0,
        deferred: 0,
        bounced: 0,
        suppressed: 0,
        rejected: 0,
        delivery_rate: null,
      };
      if (record.status === "accepted") {
        bucket.sent += 1;
      }
      if (record.status === "delivered") {
        bucket.delivered += 1;
      }
      if (record.status === "deferred") {
        bucket.deferred += 1;
      }
      if (record.status === "bounced") {
        bucket.bounced += 1;
      }
      if (record.status === "suppressed") {
        bucket.suppressed += 1;
      }
      if (record.status === "rejected") {
        bucket.rejected += 1;
      }
      bucketMap.set(key, bucket);
    }
    const buckets = [...bucketMap.values()].map((bucket) => {
      const denominator =
        bucket.delivered + bucket.deferred + bucket.bounced + bucket.suppressed + bucket.rejected;
      return {
        ...bucket,
        delivery_rate: denominator === 0 ? null : bucket.delivered / denominator,
      };
    });
    return { totals, buckets };
  }
}

/** Filter predicate for the in-memory message store. */
function matchesFilter(record: MessageRecord, filter: MessageFilter): boolean {
  if (filter.status && !filter.status.includes(record.status)) {
    return false;
  }
  if (filter.delivery && !filter.delivery.includes(record.delivery)) {
    return false;
  }
  if (filter.recipient_hash && !record.recipient_hashes.includes(filter.recipient_hash)) {
    return false;
  }
  if (filter.from && record.created_at < filter.from) {
    return false;
  }
  if (filter.to && record.created_at >= filter.to) {
    return false;
  }
  if (filter.domain && !record.from_addr.toLowerCase().endsWith(`@${filter.domain}`)) {
    return false;
  }
  if (filter.request_id && record.request_id !== filter.request_id) {
    return false;
  }
  if (filter.tag && !filter.tag.some((tag) => record.tags.includes(tag))) {
    return false;
  }
  return true;
}

/** In-memory bounce store. */
export class MemoryBounceStore implements BounceStore {
  readonly records = new Map<string, BounceRecord>();

  async list(
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
  ): Promise<Page<BounceRecord>> {
    const filtered = [...this.records.values()]
      .filter((record) => record.tenant_id === tenant_id)
      .filter((record) => (filter.code ? filter.code.includes(record.code) : true))
      .filter((record) =>
        filter.recipient_hash ? record.recipient_hash === filter.recipient_hash : true,
      )
      .filter((record) => (filter.from ? record.occurred_at >= filter.from : true))
      .filter((record) => (filter.to ? record.occurred_at < filter.to : true))
      .toSorted((a, b) => (a.occurred_at < b.occurred_at ? 1 : -1));
    const startIndex = cursor
      ? filtered.findIndex(
          (record) => record.occurred_at === cursor.occurred_at && record.id === cursor.id,
        ) + 1
      : 0;
    const slice = filtered.slice(startIndex, startIndex + limit);
    return {
      items: slice,
      next_cursor: null,
      has_more: startIndex + limit < filtered.length,
      limit,
    };
  }

  async insert(bounce: BounceRecord): Promise<void> {
    this.records.set(bounce.id, bounce);
  }

  async hasSeen(tenant_id: string, message_id: string, recipient_hash: string): Promise<boolean> {
    return [...this.records.values()].some(
      (record) =>
        record.tenant_id === tenant_id &&
        record.message_id === message_id &&
        record.recipient_hash === recipient_hash,
    );
  }
}

/** In-memory suppression store. */
export class MemorySuppressionStore implements SuppressionStore {
  readonly records = new Map<string, SuppressionRecord>();

  private key(tenant_id: string, email: string, scope: string, domain?: string | null): string {
    return `${tenant_id}|${email}|${scope}|${domain ?? ""}`;
  }

  async get(
    tenant_id: string,
    email: string,
    scope: "global" | "domain",
    domain?: string | null,
  ): Promise<SuppressionRecord | null> {
    return this.records.get(this.key(tenant_id, email, scope, domain)) ?? null;
  }

  async upsert(
    record: SuppressionRecord,
  ): Promise<{ record: SuppressionRecord; created: boolean }> {
    const key = this.key(record.tenant_id, record.email, record.scope, record.domain);
    const existing = this.records.get(key);
    if (existing) {
      // A permanent suppression is never downgraded to an expiring one.
      const merged: SuppressionRecord = {
        ...existing,
        ...record,
        id: existing.id,
        created_at: existing.created_at,
        expires_at: existing.expires_at ?? record.expires_at,
      };
      this.records.set(key, merged);
      return { record: merged, created: false };
    }
    this.records.set(key, record);
    return { record, created: true };
  }

  async count(tenant_id: string): Promise<number> {
    return [...this.records.values()].filter((record) => record.tenant_id === tenant_id).length;
  }
}

/** In-memory idempotency store. */
export class MemoryIdempotencyStore implements IdempotencyStore {
  readonly records = new Map<string, IdempotencyRecord>();

  async reserve(record: IdempotencyRecord): Promise<boolean> {
    if (this.records.has(record.scope_key)) {
      return false;
    }
    this.records.set(record.scope_key, record);
    return true;
  }

  async get(scope_key: string): Promise<IdempotencyRecord | null> {
    return this.records.get(scope_key) ?? null;
  }

  async complete(
    scope_key: string,
    result: { status: number; headers: Record<string, string>; body: unknown },
  ): Promise<void> {
    const record = this.records.get(scope_key);
    if (!record) {
      return;
    }
    this.records.set(scope_key, { ...record, ...result });
  }
}

/** In-memory outbox queue that counts enqueued transactions. */
export class MemoryOutboxQueue implements OutboxQueue {
  readonly entries: Array<{
    tenant_id: string;
    message_id: string;
    recipient: string;
    request_id: string;
    enqueued_at: string;
  }> = [];

  async enqueue(entry: {
    tenant_id: string;
    message_id: string;
    recipient: string;
    request_id: string;
    enqueued_at: string;
  }): Promise<void> {
    this.entries.push(entry);
  }

  async depth(): Promise<number> {
    return this.entries.length;
  }
}

/** In-memory audit log. */
export class MemoryAuditLog implements AuditLog {
  readonly records: Array<Record<string, unknown>> = [];

  async append(record: {
    ts: string;
    event: string;
    actor: string;
    resource: string | null;
    tenant_id: string | null;
    request_id: string;
    outcome: "ok" | "denied" | "error";
    detail: Record<string, unknown>;
  }): Promise<void> {
    this.records.push({ ...record });
  }
}

/** Digest helper re-exported for convenience. */
export { canonicalDigest };
