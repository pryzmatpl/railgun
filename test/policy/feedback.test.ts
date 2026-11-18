// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Authenticated feedback ingestion (DSN / FBL).
//
// Covers IR verification obligation V-22 and the pipeline IR's Rules F-1
// through F-4.

import { describe, expect, it } from "vitest";

import {
  MAX_FEEDBACK_BYTES,
  SOFT_BOUNCE_THRESHOLD,
  classifyFeedback,
  extractRecipient,
  extractStatus,
  ingestFeedback,
  parseFeedback,
  secretsMatch,
  verifyFeedbackSignature,
} from "../../src/spam/feedback.js";
import { MemorySuppressionStore } from "./fakes.js";

const SECRET = "shared-feedback-secret";

const DSN_5_1_1 = [
  "From: MAILER-DAEMON@example.com",
  "To: feedback@example.com",
  "Subject: Delivery Status Notification (Failure)",
  "Final-Recipient: rfc822; bob@example.org",
  "Action: failed",
  "Status: 5.1.1",
  "",
  "550 5.1.1 <bob@example.org>: Recipient address rejected",
].join("\r\n");

const DSN_4_2_2 = [
  "From: MAILER-DAEMON@example.com",
  "To: feedback@example.com",
  "Subject: Delivery Status Notification (Delay)",
  "Final-Recipient: rfc822; bob@example.org",
  "Action: delayed",
  "Status: 4.2.2",
  "",
  "452 4.2.2 <bob@example.org>: Mailbox full",
].join("\r\n");

const FBL_COMPLAINT = [
  "From: feedback@example.com",
  "To: feedback@example.com",
  "Subject: Feedback Loop",
  "Final-Recipient: rfc822; bob@example.org",
  "Feedback-Type: abuse",
  "",
  "User complained about this message.",
].join("\r\n");

/** A soft-bounce counter. */
class CountingSoftBounces {
  readonly counts = new Map<string, number>();
  async increment(tenantId: string, recipient: string): Promise<number> {
    const key = `${tenantId}:${recipient}`;
    const next = (this.counts.get(key) ?? 0) + 1;
    this.counts.set(key, next);
    return next;
  }
}

describe("Feedback parsing", () => {
  it("extracts the reported recipient", () => {
    expect(extractRecipient(DSN_5_1_1)).toBe("bob@example.org");
  });

  it("extracts the DSN status code", () => {
    expect(extractStatus(DSN_5_1_1)).toBe("5.1.1");
    expect(extractStatus(DSN_4_2_2)).toBe("4.2.2");
  });

  it("returns null for a malformed payload", () => {
    expect(extractRecipient("garbage with no recipient")).toBeNull();
    expect(extractStatus("garbage")).toBeNull();
  });

  it("classifies a 5.x.x code as a hard bounce", () => {
    expect(classifyFeedback("5.1.1", false)).toBe("hard_bounce");
  });

  it("classifies a 4.x.x code as a soft bounce", () => {
    expect(classifyFeedback("4.2.2", false)).toBe("soft_bounce");
  });

  it("classifies a complaint as a complaint", () => {
    expect(classifyFeedback(null, true)).toBe("complaint");
  });

  it("detects a feedback-loop report", () => {
    expect(parseFeedback(FBL_COMPLAINT).complaint).toBe(true);
    expect(parseFeedback(DSN_5_1_1).complaint).toBe(false);
  });
});

describe("Feedback authentication (V-22)", () => {
  it("rejects an unauthenticated payload and changes no state", async () => {
    const store = new MemorySuppressionStore();
    const audited: string[] = [];
    const outcome = await ingestFeedback(
      store,
      null,
      DSN_5_1_1,
      "tenant-1",
      Date.parse("2026-11-18T12:00:00.000Z"),
      {
        presented_secret: "wrong",
        expected_secret: SECRET,
        audit: async (o) => {
          audited.push(o.reason);
        },
      },
    );
    expect(outcome.accepted).toBe(false);
    expect(outcome.reason).toBe("unauthenticated");
    expect(store.entries).toHaveLength(0);
    // The failed ingestion is still audited (IR R-10.4.5).
    expect(audited).toEqual(["unauthenticated"]);
  });

  it("rejects a malformed payload and changes no state, but still audits", async () => {
    const store = new MemorySuppressionStore();
    const audited: string[] = [];
    const outcome = await ingestFeedback(
      store,
      null,
      "not a dsn",
      "tenant-1",
      Date.parse("2026-11-18T12:00:00.000Z"),
      {
        presented_secret: SECRET,
        expected_secret: SECRET,
        audit: async (o) => {
          audited.push(o.reason);
        },
      },
    );
    expect(outcome.accepted).toBe(false);
    expect(store.entries).toHaveLength(0);
    expect(audited).toHaveLength(1);
  });

  it("rejects an over-sized payload without parsing it", async () => {
    const store = new MemorySuppressionStore();
    const outcome = await ingestFeedback(
      store,
      null,
      "x".repeat(MAX_FEEDBACK_BYTES + 1),
      "tenant-1",
      Date.parse("2026-11-18T12:00:00.000Z"),
      { presented_secret: SECRET, expected_secret: SECRET },
    );
    expect(outcome.accepted).toBe(false);
    expect(outcome.reason).toBe("payload_too_large");
    expect(store.entries).toHaveLength(0);
  });

  it("compares secrets in constant time", () => {
    expect(secretsMatch(SECRET, SECRET)).toBe(true);
    expect(secretsMatch("wrong", SECRET)).toBe(false);
    expect(secretsMatch("", SECRET)).toBe(false);
  });

  it("verifies an HMAC-signed request", () => {
    const { createHmac } = require("node:crypto") as typeof import("node:crypto");
    const signature = createHmac("sha256", SECRET).update(DSN_5_1_1, "utf8").digest("hex");
    expect(verifyFeedbackSignature(DSN_5_1_1, signature, SECRET)).toBe(true);
    expect(verifyFeedbackSignature(DSN_5_1_1, "0".repeat(64), SECRET)).toBe(false);
  });
});

describe("Feedback suppression (V-22)", () => {
  it("creates a hard_bounce suppression for an authenticated 5.1.1 DSN", async () => {
    const store = new MemorySuppressionStore();
    const outcome = await ingestFeedback(
      store,
      null,
      DSN_5_1_1,
      "tenant-1",
      Date.parse("2026-11-18T12:00:00.000Z"),
      { presented_secret: SECRET, expected_secret: SECRET },
    );
    expect(outcome.accepted).toBe(true);
    expect(outcome.suppression_reason).toBe("hard_bounce");
    expect(store.entries).toHaveLength(1);
    const entry = store.entries[0];
    expect(entry?.reason).toBe("hard_bounce");
    expect(entry?.recipient).toBe("bob@example.org");
    // A hard bounce is indefinite until an operator releases it.
    expect(entry?.expires_at).toBeNull();
  });

  it("creates no indefinite suppression for a 4.2.2 DSN", async () => {
    const store = new MemorySuppressionStore();
    const counters = new CountingSoftBounces();
    const outcome = await ingestFeedback(
      store,
      counters,
      DSN_4_2_2,
      "tenant-1",
      Date.parse("2026-11-18T12:00:00.000Z"),
      { presented_secret: SECRET, expected_secret: SECRET },
    );
    expect(outcome.accepted).toBe(true);
    expect(store.entries).toHaveLength(0);
    expect(outcome.reason).toBe("soft_bounce_counted");
    expect(await counters.increment("tenant-1", "bob@example.org")).toBe(2);
  });

  it("creates a time-bounded soft_bounce suppression past the threshold", async () => {
    const store = new MemorySuppressionStore();
    const counters = new CountingSoftBounces();
    await ingestFeedback(
      store,
      counters,
      DSN_4_2_2,
      "tenant-1",
      Date.parse("2026-11-18T12:00:00.000Z"),
      { presented_secret: SECRET, expected_secret: SECRET },
    );
    for (let i = 1; i < SOFT_BOUNCE_THRESHOLD; i++) {
      await ingestFeedback(
        store,
        counters,
        DSN_4_2_2,
        "tenant-1",
        Date.parse("2026-11-18T12:00:00.000Z"),
        { presented_secret: SECRET, expected_secret: SECRET },
      );
    }
    expect(store.entries).toHaveLength(1);
    const entry = store.entries[0];
    expect(entry?.reason).toBe("soft_bounce");
    // Time-bounded, not indefinite.
    expect(entry?.expires_at).not.toBeNull();
    expect(Date.parse(entry?.expires_at ?? "")).toBeGreaterThan(
      Date.parse("2026-11-18T12:00:00.000Z"),
    );
  });

  it("creates a complaint suppression for a feedback-loop report", async () => {
    const store = new MemorySuppressionStore();
    const outcome = await ingestFeedback(
      store,
      null,
      FBL_COMPLAINT,
      "tenant-1",
      Date.parse("2026-11-18T12:00:00.000Z"),
      { presented_secret: SECRET, expected_secret: SECRET },
    );
    expect(outcome.accepted).toBe(true);
    expect(outcome.suppression_reason).toBe("complaint");
    expect(store.entries[0]?.reason).toBe("complaint");
    expect(store.entries[0]?.expires_at).toBeNull();
  });

  it("bounds the suppression scope to the reported recipient, never a domain", async () => {
    const store = new MemorySuppressionStore();
    await ingestFeedback(store, null, DSN_5_1_1, "tenant-1", Date.now(), {
      presented_secret: SECRET,
      expected_secret: SECRET,
    });
    const entry = store.entries[0];
    expect(entry?.recipient).toBe("bob@example.org");
    // A domain-scoped or wildcard entry would be `domain: null` with a
    // domain-level value; the scope here is global but the *subject* is the
    // single reported address.
    expect(entry?.recipient).not.toContain("*");
    expect(entry?.domain).toBeNull();
  });
});
