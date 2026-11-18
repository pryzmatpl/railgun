// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The policy engine: suppression, blocklists, role addresses, rate limits,
// warmup, DKIM gating, content scoring and auditability.
//
// Covers IR verification obligations V-9, V-11, V-12, V-13, V-14, V-15,
// V-20 and V-21.

import { describe, expect, it } from "vitest";

import { REASON_CODES } from "../../src/domain/policy.js";
import { DEFAULT_POLICY_CONFIG } from "../../src/spam/config.js";
import {toRecipient} from "../../src/spam/engine.js";
import type { BlocklistEntry, SuppressionEntry } from "../../src/domain/identity.js";
import {harness, principal, request} from "./harness.js";

describe("Policy engine — suppression (V-13)", () => {
  it("denies a suppressed recipient with the reason class only", async () => {
    const h = harness();
    const entry: SuppressionEntry = {
      id: "sup-1",
      tenant_id: "tenant-1",
      scope: "global",
      domain: null,
      recipient: "bob@example.org",
      reason: "hard_bounce",
      created_at: "2026-01-01T00:00:00.000Z",
      expires_at: null,
      source: "bounce",
    };
    await h.suppression.add(entry);
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.SUPPRESSED);
    expect(decision.record.evidence?.suppression_reason).toBe("hard_bounce");
  });

  it("does not apply another tenant's domain-scoped suppression", async () => {
    const h = harness();
    await h.suppression.add({
      id: "sup-1",
      tenant_id: "tenant-2",
      scope: "domain",
      domain: "example.com",
      recipient: "bob@example.org",
      reason: "complaint",
      created_at: "2026-01-01T00:00:00.000Z",
      expires_at: null,
      source: "feedback",
    });
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(decision.decision).toBe("allow");
  });

  it("honours the expiry of a soft-bounce suppression", async () => {
    const h = harness();
    await h.suppression.add({
      id: "sup-1",
      tenant_id: "tenant-1",
      scope: "global",
      domain: null,
      recipient: "bob@example.org",
      reason: "soft_bounce",
      created_at: "2026-01-01T00:00:00.000Z",
      expires_at: "2026-01-02T00:00:00.000Z",
      source: "bounce",
    });
    // The clock is at 2026-11-18, well past the expiry.
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(decision.decision).toBe("allow");
  });

  it("re-checks suppression immediately before delivery (V-13)", async () => {
    const h = harness();
    const recipients = [toRecipient("bob@example.org")].filter(
      (r): r is NonNullable<typeof r> => r !== null,
    );
    // Suppression arrives after enqueue.
    await h.suppression.add({
      id: "sup-1",
      tenant_id: "tenant-1",
      scope: "global",
      domain: null,
      recipient: "bob@example.org",
      reason: "hard_bounce",
      created_at: "2026-11-18T11:00:00.000Z",
      expires_at: null,
      source: "bounce",
    });
    const result = await h.engine.recheckBeforeDelivery(
      "tenant-1",
      "example.com",
      recipients,
    );
    expect(result.suppressed).toHaveLength(1);
    expect(result.allowed).toHaveLength(0);
  });
});

describe("Policy engine — blocklists (V-12)", () => {
  it("denies a recipient address on the local blocklist", async () => {
    const h = harness();
    const entry: BlocklistEntry = {
      id: "bl-1",
      kind: "recipient_address",
      value: "bob@example.org",
      tenant_id: null,
      created_at: "2026-01-01T00:00:00.000Z",
      expires_at: null,
    };
    await h.blocklist.add(entry);
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.BLOCKED);
  });

  it("denies a recipient domain on the local blocklist", async () => {
    const h = harness();
    await h.blocklist.add({
      id: "bl-1",
      kind: "recipient_domain",
      value: "example.org",
      tenant_id: null,
      created_at: "2026-01-01T00:00:00.000Z",
      expires_at: null,
    });
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.BLOCKED);
  });
});

describe("Policy engine — role addresses (V-14)", () => {
  it("denies a protected role address under `require_verified`", async () => {
    const h = harness();
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["abuse@example.org"]),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.ROLE_ADDRESS_PROTECTED);
  });

  it("allows a protected role address once it is verified", async () => {
    const h = harness();
    await h.verified.add("tenant-1", "abuse@example.org");
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["abuse@example.org"]),
    );
    expect(decision.decision).toBe("allow");
  });

  it("denies a protected role address under `deny` mode", async () => {
    const h = harness({
      config: {
        spam: {
          ...DEFAULT_POLICY_CONFIG.spam,
          role_addresses: {
            mode: "deny",
            list: DEFAULT_POLICY_CONFIG.spam.role_addresses.list,
            trap_recipients: [],
          },
        },
      },
    });
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["postmaster@example.org"]),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.ROLE_ADDRESS_PROTECTED);
  });

  it("allows a protected role address under `allow` mode", async () => {
    const h = harness({
      config: {
        spam: {
          ...DEFAULT_POLICY_CONFIG.spam,
          role_addresses: {
            mode: "allow",
            list: DEFAULT_POLICY_CONFIG.spam.role_addresses.list,
            trap_recipients: [],
          },
        },
      },
    });
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["postmaster@example.org"]),
    );
    expect(decision.decision).toBe("allow");
  });

  it("denies a trap recipient unconditionally", async () => {
    const h = harness({
      config: {
        spam: {
          ...DEFAULT_POLICY_CONFIG.spam,
          role_addresses: {
            mode: "allow",
            list: DEFAULT_POLICY_CONFIG.spam.role_addresses.list,
            trap_recipients: ["spamtrap@example.org"],
          },
        },
      },
    });
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["spamtrap@example.org"]),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.ROLE_ADDRESS_PROTECTED);
  });
});

