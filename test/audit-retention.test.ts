/* RailGun audit and retention tests. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FileAuditStore, MemoryStore } from "../src/index.js";
import type { Clock, IdGenerator, RetentionPolicy } from "../src/index.js";

class TestClock implements Clock {
  constructor(private value = new Date("2026-01-01T00:00:00.000Z")) {}
  now(): Date { return new Date(this.value); }
}
class TestIds implements IdGenerator {
  private value = 0;
  next(): string { return `id-${++this.value}`; }
}

const event = (action: string) => ({ actor: "operator", tenantId: "tenant-a", action, subjectType: "message", subjectId: "message-1", outcome: "allow", reasonCode: null, correlationId: "corr-1", metadata: { result: "ok" } });

describe("hash-chained audit", () => {
  it("builds a valid chain and detects modified content", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    const first = await store.audit.append(event("created"));
    const second = await store.audit.append(event("accepted"));
    expect(second.previousDigest).toBe(first.digest);
    expect((await store.audit.verify()).valid).toBe(true);
    const tampered = [{ ...first, outcome: "reject" }, second];
    const { verifyAuditRecords } = await import("../src/domain/persistence/audit.js");
    const verification = verifyAuditRecords(tampered);
    expect(verification.valid).toBe(false);
    expect(verification.firstInvalidSequence).toBe(1);
  });

  it("detects a broken previous-digest link", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    const first = await store.audit.append(event("created"));
    const second = await store.audit.append(event("accepted"));
    const { verifyAuditRecords } = await import("../src/domain/persistence/audit.js");
    expect(verifyAuditRecords([first, { ...second, previousDigest: "f".repeat(64) }]).reason).toBe("previous_digest_mismatch");
  });

  it("serializes concurrent appends without forking the chain", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    const records = await Promise.all(Array.from({ length: 20 }, (_, i) => store.audit.append(event(`event-${i}`))));
    expect(new Set(records.map((r) => r.sequence)).size).toBe(20);
    expect((await store.audit.verify()).valid).toBe(true);
  });

  it("persists NDJSON and reports a truncated tail as tampering", async () => {
    const directory = await mkdtemp(join(tmpdir(), "railgun-audit-"));
    const path = join(directory, "audit.ndjson");
    const store = new FileAuditStore({ path });
    await store.append(event("created"));
    await store.append(event("accepted"));
    const content = await readFile(path, "utf8");
    expect(content.split("\n").filter(Boolean)).toHaveLength(2);
    await writeFile(path, `${content}{"partial"`, "utf8");
    const verification = await store.verify();
    expect(verification.valid).toBe(false);
    expect(verification.reason).toBe("truncated_tail");
  });
});

describe("retention", () => {
  it("removes expired metadata and bodies independently within tenant scope", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    const now = store.clock.now().toISOString();
    const policy: RetentionPolicy = { messageMetadataDays: 30, messageBodyDays: 7, attemptDays: 30, bounceDays: 30, idempotencyDays: 30, auditDays: 365 };
    const message = { id: "message-1", tenantId: "tenant-a", principalId: "p", correlationId: "c", idempotencyKey: "k", requestId: "r", envelopeSender: "s@example.com", recipients: ["r@example.com"], subject: "s", body: new Uint8Array([1]), bodyReference: null, contentDigest: "d", rawSize: 1, status: "queued" as const, attemptCount: 0, nextAttemptAt: null, createdAt: new Date(Date.parse(now) - 8 * 86_400_000).toISOString(), updatedAt: now, queuedAt: now, acceptedAt: null, deliveredAt: null, lastSmtpCode: null, lastResponse: null, errorCode: null, suppressionReason: null, metadata: {}, version: 1 };
    await store.messages.create(message);
    const other = { ...message, id: "message-2", tenantId: "tenant-b", createdAt: now };
    await store.messages.create(other);
    const result = await store.applyRetention(policy, now);
    expect(result.bodies).toBe(1);
    expect(store.inspect().messages.find((m) => m.id === "message-1")?.body).toBeNull();
    expect(store.inspect().messages.find((m) => m.id === "message-2")?.body).not.toBeNull();
  });

  it("removes expired suppressions while retaining bounce history", async () => {
    const store = new MemoryStore(new TestClock(), new TestIds());
    const now = store.clock.now().toISOString();
    await store.suppressions.create({ id: "sup-1", tenantId: "tenant-a", recipient: "bad@example.com", reasonCode: "hard_bounce", source: "hard_bounce", createdAt: now, expiresAt: new Date(Date.parse(now) - 1).toISOString(), lastHitAt: null, relatedBounceId: "bounce-1", relatedMessageId: "message-1", active: true });
    await store.bounces.append({ id: "bounce-1", tenantId: "tenant-a", messageId: "message-1", envelopeId: "envelope-1", recipient: "bad@example.com", observedAt: now, smtpCode: 550, dsnCode: "5.1.1", dsnClass: "5", bounceClass: "hard", diagnostic: null, remoteId: null, suppressionId: "sup-1" });
    const result = await store.applyRetention({ messageMetadataDays: 30, messageBodyDays: 7, attemptDays: 30, bounceDays: 30, idempotencyDays: 30, auditDays: 365 }, now);
    expect(result.suppressions).toBe(1);
    expect(store.inspect().bounces).toHaveLength(1);
  });
});
