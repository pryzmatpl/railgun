/* RailGun suppression and bounce tests. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { describe, expect, it } from "vitest";
import { MemoryStore } from "../src/index.js";
import type { BounceRecord, Clock, IdGenerator, Suppression } from "../src/index.js";

class TestClock implements Clock {
  constructor(private value = new Date("2026-01-01T00:00:00.000Z")) {}
  now(): Date { return new Date(this.value); }
}
class TestIds implements IdGenerator {
  private value = 0;
  next(): string { return `id-${++this.value}`; }
}

describe("suppression and bounce history", () => {
  it("hard bounce creates recipient-scoped suppression", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    const now = store.clock.now().toISOString();
    const suppression: Suppression = { id: "sup-1", tenantId: "tenant-a", recipient: "bad@example.com", reasonCode: "hard_bounce", source: "hard_bounce", createdAt: now, expiresAt: null, lastHitAt: null, relatedBounceId: "bounce-1", relatedMessageId: "message-1", active: true };
    await store.suppressions.create(suppression);
    expect(await store.suppressions.isSuppressed("tenant-a", "bad@example.com", now)).toBe(true);
    expect(await store.suppressions.isSuppressed("tenant-a", "other@example.com", now)).toBe(false);
    expect(await store.suppressions.isSuppressed("tenant-b", "bad@example.com", now)).toBe(false);
  });

  it("expired suppression no longer blocks and can be removed independently of bounces", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    const now = store.clock.now().toISOString();
    await store.suppressions.create({ id: "sup-1", tenantId: "tenant-a", recipient: "bad@example.com", reasonCode: "operator", source: "operator", createdAt: now, expiresAt: new Date(Date.parse(now) - 1).toISOString(), lastHitAt: null, relatedBounceId: null, relatedMessageId: null, active: true });
    expect(await store.suppressions.isSuppressed("tenant-a", "bad@example.com", now)).toBe(false);
    expect(await store.suppressions.expire(now)).toBe(1);
  });

  it("filters bounce queries and distinguishes bounce classes", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    const now = store.clock.now().toISOString();
    const rows: BounceRecord[] = [
      { id: "bounce-1", tenantId: "tenant-a", messageId: "message-1", envelopeId: "envelope-1", recipient: "one@example.com", observedAt: now, smtpCode: 550, dsnCode: "5.1.1", dsnClass: "5", bounceClass: "hard", diagnostic: "not found", remoteId: "mx", suppressionId: "sup-1" },
      { id: "bounce-2", tenantId: "tenant-a", messageId: "message-2", envelopeId: "envelope-2", recipient: "two@example.com", observedAt: now, smtpCode: 451, dsnCode: "4.2.2", dsnClass: "4", bounceClass: "soft", diagnostic: "try later", remoteId: "mx", suppressionId: null },
      { id: "bounce-3", tenantId: "tenant-b", messageId: "message-3", envelopeId: "envelope-3", recipient: "three@example.com", observedAt: now, smtpCode: 550, dsnCode: "5.7.1", dsnClass: "5", bounceClass: "complaint", diagnostic: "blocked", remoteId: "mx", suppressionId: null },
    ];
    for (const row of rows) await store.bounces.append(row);
    expect(await store.bounces.list({ tenantId: "tenant-a", bounceClass: "hard" })).toHaveLength(1);
    expect(await store.bounces.list({ tenantId: "tenant-a", dsnClass: "4" })).toHaveLength(1);
    expect(await store.bounces.list({ tenantId: "tenant-a", recipient: "two@example.com" })).toHaveLength(1);
    expect(await store.bounces.counts("tenant-a")).toEqual({ hard: 1, soft: 1, complaint: 0 });
  });

  it("does not create wildcard suppression for a malformed DSN", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    await store.bounces.append({ id: "bounce-1", tenantId: "tenant-a", messageId: "message-1", envelopeId: "envelope-1", recipient: "one@example.com", observedAt: store.clock.now().toISOString(), smtpCode: 550, dsnCode: null, dsnClass: null, bounceClass: "hard", diagnostic: null, remoteId: null, suppressionId: null });
    expect(await store.suppressions.list("tenant-a")).toHaveLength(0);
  });
});
