/* RailGun domain behavior tests. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { describe, expect, it } from "vitest";
import { canonicalIdempotencyKey, IdempotencyConflictError, MemoryStore, normalizeEmailAddress } from "../src/index.js";
import type { Clock, IdGenerator, Message, OutboxItem, EnvelopeRecipient, IdempotencyRecord } from "../src/index.js";

class TestClock implements Clock {
  constructor(private value = new Date("2026-01-01T00:00:00.000Z")) {}
  now(): Date { return new Date(this.value); }
  advance(ms: number): void { this.value = new Date(this.value.getTime() + ms); }
}

class TestIds implements IdGenerator {
  private value = 0;
  next(): string { return `id-${++this.value}`; }
}

function fixture(store: MemoryStore): { message: Message; envelopes: EnvelopeRecipient[]; outbox: OutboxItem[]; idempotency: IdempotencyRecord; response: unknown } {
  const now = store.clock.now().toISOString();
  const message: Message = {
    id: "message-1", tenantId: "tenant-a", principalId: "principal-a", correlationId: "corr-1",
    idempotencyKey: canonicalIdempotencyKey("tenant-a", "email_send", "req-1"), requestId: "req-1",
    envelopeSender: "sender@example.com", recipients: ["one@example.com", "two@example.com"], subject: "Hi",
    body: new Uint8Array([1, 2, 3]), bodyReference: null, contentDigest: "digest", rawSize: 3,
    status: "queued", attemptCount: 0, nextAttemptAt: null, createdAt: now, updatedAt: now,
    queuedAt: now, acceptedAt: null, deliveredAt: null, lastSmtpCode: null, lastResponse: null,
    errorCode: null, suppressionReason: null, metadata: {}, version: 1,
  };
  const envelopes: EnvelopeRecipient[] = message.recipients.map((recipient, index) => ({
    envelopeId: `envelope-${index + 1}`, messageId: message.id, tenantId: message.tenantId, recipient,
    recipientKind: "to", status: "pending", attemptCount: 0, nextAttemptAt: null, leaseOwner: null,
    leaseExpiresAt: null, lastSmtpCode: null, lastResponse: null, errorCode: null, createdAt: now,
    updatedAt: now, lastAttemptAt: null, acceptedAt: null, deliveredAt: null, terminalAt: null, version: 1,
  }));
  const outbox: OutboxItem[] = envelopes.map((envelope) => ({
    id: `outbox-${envelope.envelopeId}`, messageId: message.id, envelopeId: envelope.envelopeId,
    tenantId: message.tenantId, priority: 0, availableAt: now, attemptCount: 0, maxAttempts: 5,
    leaseOwner: null, leaseExpiresAt: null, nextAttemptAt: now, state: "pending", lastErrorCode: null, acceptedSequence: 0,
  }));
  const idempotency: IdempotencyRecord = {
    key: message.idempotencyKey, tenantId: message.tenantId, action: "email_send", requestId: message.requestId,
    requestDigest: "request-digest", messageId: null, response: null, state: "reserved", createdAt: now, expiresAt: new Date(Date.parse(now) + 86_400_000).toISOString(),
  };
  return { message, envelopes, outbox, idempotency, response: { id: message.id, status: "queued" } };
}

describe("domain normalization", () => {
  it("normalizes recipient identity and creates canonical idempotency keys", () => {
    expect(normalizeEmailAddress(" User@Example.COM ")).toBe("user@example.com");
    expect(canonicalIdempotencyKey("tenant", "email_send", "request")).toBe("email:idempotency:tenant:email_send:request");
  });
});

describe("atomic acceptance and idempotency", () => {
  it("commits message, envelopes, outbox, and immutable response together", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    const input = fixture(store);
    await store.accept({ ...input, idempotencyExpiresAt: input.idempotency.expiresAt });
    const inspected = store.inspect();
    expect(inspected.messages).toHaveLength(1);
    expect(inspected.envelopes).toHaveLength(2);
    expect(inspected.outbox).toHaveLength(2);
    expect(inspected.idempotency[0]?.state).toBe("committed");
  });

  it("replays the original snapshot without creating a second message", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    const input = fixture(store);
    await store.accept({ ...input, idempotencyExpiresAt: input.idempotency.expiresAt });
    const replay = await store.accept({ ...input, message: { ...input.message, id: "message-2" }, idempotencyExpiresAt: input.idempotency.expiresAt });
    expect(replay.message.id).toBe("message-1");
    expect(store.inspect().messages).toHaveLength(1);
    expect(store.inspect().outbox).toHaveLength(2);
  });

  it("rejects a digest conflict and does not create another message", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    const input = fixture(store);
    await store.accept({ ...input, idempotencyExpiresAt: input.idempotency.expiresAt });
    await expect(store.accept({ ...input, idempotency: { ...input.idempotency, requestDigest: "different" }, idempotencyExpiresAt: input.idempotency.expiresAt })).rejects.toBeInstanceOf(IdempotencyConflictError);
    expect(store.inspect().messages).toHaveLength(1);
  });

  it("rolls back all records when acceptance fails", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    store.failNext("accept");
    await expect(store.accept({ ...fixture(store), idempotencyExpiresAt: new Date(Date.now() + 1000).toISOString() })).rejects.toThrow("Injected");
    expect(store.inspect().messages).toHaveLength(0);
    expect(store.inspect().outbox).toHaveLength(0);
  });
});

describe("outbox leasing and transitions", () => {
  it("leases one item exclusively and rejects stale completion", async () => {
    const clock = new TestClock();
    const store = new MemoryStore(clock, new TestIds());
    await store.accept({ ...fixture(store), idempotencyExpiresAt: new Date(Date.now() + 1000).toISOString() });
    const now = clock.now().toISOString();
    const leased = await store.outbox.lease({ tenantId: "tenant-a", owner: "worker-a", now, leaseUntil: new Date(Date.now() + 30_000).toISOString(), limit: 1 });
    expect(leased).toHaveLength(1);
    const again = await store.outbox.lease({ tenantId: "tenant-a", owner: "worker-b", now, leaseUntil: new Date(Date.now() + 30_000).toISOString(), limit: 1 });
    expect(again[0]?.id).not.toBe(leased[0]?.id);
    await expect(store.outbox.complete(leased[0]!.id, "worker-b", { status: "accepted" })).rejects.toMatchObject({ code: "STALE_LEASE" });
  });

  it("reclaims expired leases and rejects invalid envelope transitions", async () => {
    const clock = new TestClock();
    const store = new MemoryStore(clock, new TestIds());
    await store.accept({ ...fixture(store), idempotencyExpiresAt: new Date(Date.now() + 1000).toISOString() });
    const now = clock.now().toISOString();
    const leased = await store.outbox.lease({ tenantId: "tenant-a", owner: "worker-a", now, leaseUntil: new Date(Date.parse(now) - 1).toISOString(), limit: 1 });
    expect(await store.outbox.reconcileExpired(now)).toBe(1);
    expect(store.inspect().outbox.find((item) => item.id === leased[0]!.id)?.state).toBe("pending");
    const envelope = store.inspect().envelopes[0]!;
    await expect(store.messages.updateEnvelope({ ...envelope, status: "delivered" }, envelope.version)).rejects.toMatchObject({ code: "INVALID_TRANSITION" });
  });

  it("does not lease another tenant's work", async () => {
    const clock = new TestClock();
    const store = new MemoryStore(clock, new TestIds());
    await store.accept({ ...fixture(store), idempotencyExpiresAt: new Date(Date.now() + 1000).toISOString() });
    const leased = await store.outbox.lease({ tenantId: "tenant-b", owner: "worker-b", now: clock.now().toISOString(), leaseUntil: new Date(Date.now() + 1000).toISOString(), limit: 10 });
    expect(leased).toHaveLength(0);
  });
});
