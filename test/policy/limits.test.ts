// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The policy engine: rate limits, quotas, warmup, DKIM gating, content
// scoring, auditability and determinism.
//
// Covers IR verification obligations V-9, V-11, V-15, V-20 and V-21.

import { describe, expect, it } from "vitest";

import { REASON_CODES } from "../../src/domain/policy.js";
import { DEFAULT_POLICY_CONFIG, validatePolicyConfig } from "../../src/spam/config.js";
import { PolicyEngine } from "../../src/spam/engine.js";
import {
  MemoryDuplicateContentStore,
  MemoryReputationStore,
  StaticDkimKeyLoader,
  StaticDnsResolver,
  sendingDomainRecord,
} from "./fakes.js";
import {harness, principal, request} from "./harness.js";

describe("Policy engine — rate limits (V-9)", () => {
  it("throttles with RATE_LIMITED and a retry_at when the bucket is empty", async () => {
    const h = harness({
      config: {
        rate_limit: { ...DEFAULT_POLICY_CONFIG.rate_limit, messages_per_minute: 1 },
      },
    });
    const first = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(first.decision).toBe("allow");
    const second = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"], { request_id: "req-2" }),
    );
    expect(second.decision).toBe("throttle");
    expect(second.record.reason_code).toBe(REASON_CODES.RATE_LIMITED);
    expect(second.record.retry_at).toBeDefined();
    expect(second.record.evidence?.dimension).toBeDefined();
  });

  it("throttles when the durable daily quota is exhausted", async () => {
    const h = harness({
      config: {
        rate_limit: { ...DEFAULT_POLICY_CONFIG.rate_limit, messages_per_day: 1 },
      },
    });
    await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    const second = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"], { request_id: "req-2" }),
    );
    expect(second.decision).toBe("throttle");
    expect(second.record.reason_code).toBe(REASON_CODES.RATE_LIMITED);
    expect(second.record.evidence?.dimension).toBe("tenant.messages_per_day");
  });

  it("throttles a new recipient when the new-recipient bucket is exhausted", async () => {
    const h = harness({
      config: {
        rate_limit: {
          ...DEFAULT_POLICY_CONFIG.rate_limit,
          new_recipients_per_hour: 1,
          messages_per_minute: 100,
        },
      },
    });
    const first = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(first.decision).toBe("allow");
    const second = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"], { request_id: "req-2" }),
    );
    expect(second.decision).toBe("throttle");
    expect(second.record.evidence?.dimension).toBe("recipient.new_per_hour");
  });
});

describe("Policy engine — warmup (V-11)", () => {
  it("throttles with WARMUP_LIMITED when the day-1 cap is exceeded", async () => {
    const h = harness({
      warmupPolicy: { warmup_daily_cap: 1, warmup_recipient_cap: 10 },
    });
    await h.domains.save(
      sendingDomainRecord({
        domain: "example.com",
        created_at: new Date(h.clock.now()).toISOString(),
      }),
    );
    const first = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(first.decision).toBe("allow");
    const second = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"], { request_id: "req-2" }),
    );
    expect(second.decision).toBe("throttle");
    expect(second.record.reason_code).toBe(REASON_CODES.WARMUP_LIMITED);
    expect(second.record.retry_at).toBeDefined();
  });

  it("denies an unverified recipient permanently under verified-only warmup", async () => {
    const h = harness();
    await h.domains.save(
      sendingDomainRecord({
        domain: "example.com",
        created_at: new Date(h.clock.now()).toISOString(),
      }),
    );
    const decision = await h.engine.authorizeSubmission(
      request(principal({ recipient_scope: "verified_recipients_only" }), [
        "bob@example.org",
      ]),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.RECIPIENT_NOT_VERIFIED);
  });
});

describe("Policy engine — content scoring (V-15)", () => {
  it("denies a phishing message that crosses the deny threshold", async () => {
    const h = harness();
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"], {
        subject: "Verify your account",
        text: "Please verify your account and confirm your password immediately.",
        html: "<p>Please <a href='http://192.0.2.1:8081/verify'>verify your account</a></p>",
        attachments: ["invoice.pdf.exe"],
      }),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.SPAM_POLICY_DENIED);
    expect(decision.record.spam_score).toBeGreaterThanOrEqual(
      DEFAULT_POLICY_CONFIG.spam.deny_threshold,
    );
    expect(decision.record.spam_model_version).toBe("railgun-spam-1");
  });

  it("quarantines a message in the review band", async () => {
    const h = harness();
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"], {
        subject: "Hello there",
        text: "Please click here to verify your account.",
      }),
    );
    expect(decision.decision).toBe("quarantine");
    expect(decision.record.reason_code).toBe(REASON_CODES.QUARANTINED);
  });

  it("denies rather than quarantines when quarantine is disabled", async () => {
    const h = harness({
      config: {
        spam: { ...DEFAULT_POLICY_CONFIG.spam, quarantine: false },
      },
    });
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"], {
        subject: "Hello there",
        text: "Please click here to verify your account.",
      }),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.SPAM_POLICY_DENIED);
  });

  it("records feature names but never body text in the evidence (V-15)", async () => {
    const h = harness();
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"], {
        subject: "Verify your account",
        text: "UNIQUE-BODY-MARKER please verify your account",
      }),
    );
    const features = decision.record.evidence?.features ?? [];
    expect(features.length).toBeGreaterThan(0);
    expect(features).toContain("phishing_phrase");
    const serialized = JSON.stringify(decision.record);
    expect(serialized).not.toContain("UNIQUE-BODY-MARKER");
  });

  it("scores the same message identically across runs", async () => {
    const scores: number[] = [];
    for (let i = 0; i < 3; i++) {
      const h = harness();
      const decision = await h.engine.authorizeSubmission(
        request(principal(), ["bob@example.org"], {
          subject: "Verify your account",
          text: "please verify your account",
        }),
      );
      scores.push(decision.record.spam_score ?? -1);
    }
    expect(new Set(scores).size).toBe(1);
  });
});

describe("Policy engine — DKIM (V-4)", () => {
  it("denies with DKIM_KEY_UNAVAILABLE when the domain has no key", async () => {
    const h = harness();
    h.dkimKeys.keys.length = 0;
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.DKIM_KEY_UNAVAILABLE);
  });

  it("signs a message and returns the signature header", async () => {
    const h = harness();
    const result = await h.engine.signAndFinalize({
      headers: [
        { name: "From", value: "alice@example.com" },
        { name: "To", value: "bob@example.org" },
        { name: "Subject", value: "Hello" },
        { name: "Date", value: "Tue, 18 Nov 2026 11:00:00 +0000" },
        { name: "Message-ID", value: "<abc@example.com>" },
      ],
      body: "Hello there.\r\n",
      domain: "example.com",
      selector: "railgun1",
      timestamp: 1_800_000_000,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.signature_header).toContain("DKIM-Signature:");
      expect(result.signature_header).toContain("d=example.com");
    }
  });

  it("fails closed with DKIM_KEY_UNAVAILABLE when the key material is missing", async () => {
    const h = harness();
    const engine = new PolicyEngine({
      clock: h.clock,
      config: DEFAULT_POLICY_CONFIG,
      suppression: h.suppression,
      blocklist: h.blocklist,
      rateLimits: h.rateLimits,
      verifiedRecipients: h.verified,
      warmup: h.warmup,
      reputation: new MemoryReputationStore(),
      duplicates: new MemoryDuplicateContentStore(),
      dkimKeys: h.dkimKeys,
      dkimKeyLoader: new StaticDkimKeyLoader(null),
      sendingDomains: h.domains,
      dns: new StaticDnsResolver(),
      audit: h.audit,
      tenant_secret: "tenant-secret",
    });
    const result = await engine.signAndFinalize({
      headers: [{ name: "From", value: "alice@example.com" }],
      body: "body\r\n",
      domain: "example.com",
      selector: "railgun1",
      timestamp: 1,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason_code).toBe("DKIM_KEY_UNAVAILABLE");
    }
  });
});

describe("Policy engine — audit (V-20, V-21)", () => {
  it("emits exactly one decision event per outcome", async () => {
    const h = harness();
    await h.engine.authorizeSubmission(request(principal(), ["bob@example.org"]));
    expect(h.audit.events).toHaveLength(1);
    expect(h.audit.events[0]?.decision).toBe("allow");
  });

  it("never puts the subject, body or a raw recipient address in the audit row", async () => {
    const h = harness();
    await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"], {
        subject: "SECRET-SUBJECT",
        text: "SECRET-BODY",
      }),
    );
    const serialized = JSON.stringify(h.audit.events);
    expect(serialized).not.toContain("SECRET-SUBJECT");
    expect(serialized).not.toContain("SECRET-BODY");
    expect(serialized).not.toContain("bob@example.org");
    expect(serialized).toContain("recipient_hashes");
  });

  it("denies the send when the audit write fails in strict mode (V-21)", async () => {
    const h = harness({
      config: {
        audit: { ...DEFAULT_POLICY_CONFIG.audit, write_failure_mode: "strict" },
      },
    });
    h.audit.failWith = new Error("audit path unwritable");
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.AUDIT_UNAVAILABLE);
  });

  it("proceeds when the audit write fails in warn mode (V-21)", async () => {
    const h = harness({
      config: {
        audit: { ...DEFAULT_POLICY_CONFIG.audit, write_failure_mode: "warn" },
      },
    });
    h.audit.failWith = new Error("audit path unwritable");
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(decision.decision).toBe("allow");
  });

  it("records every matched rule id deterministically (R-5.2.1)", async () => {
    const h = harness();
    await h.suppression.add({
      id: "sup-1",
      tenant_id: "tenant-1",
      scope: "global",
      domain: null,
      recipient: "bob@example.org",
      reason: "hard_bounce",
      created_at: "2026-01-01T00:00:00.000Z",
      expires_at: null,
      source: "bounce",
    });
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    const rules = decision.record.rule_ids;
    expect([...rules]).toEqual([...rules].toSorted());
    expect(rules.length).toBeGreaterThan(0);
  });
});

describe("Policy configuration validation", () => {
  it("accepts the shipped defaults", () => {
    expect(validatePolicyConfig(DEFAULT_POLICY_CONFIG)).toEqual([]);
  });

  it("rejects allow_threshold >= deny_threshold", () => {
    const problems = validatePolicyConfig({
      ...DEFAULT_POLICY_CONFIG,
      spam: {
        ...DEFAULT_POLICY_CONFIG.spam,
        allow_threshold: 0.9,
        deny_threshold: 0.5,
      },
    });
    expect(problems.some((p) => p.setting === "spam.allow_threshold")).toBe(true);
  });

  it("rejects an RSA minimum below 2048 bits", () => {
    const problems = validatePolicyConfig({
      ...DEFAULT_POLICY_CONFIG,
      signer: { ...DEFAULT_POLICY_CONFIG.signer, rsa_min_bits: 1024 },
    });
    expect(problems.some((p) => p.setting === "signer.rsa_min_bits")).toBe(true);
  });

  it("rejects an unknown relay scope", () => {
    const problems = validatePolicyConfig({
      ...DEFAULT_POLICY_CONFIG,
      relay: { ...DEFAULT_POLICY_CONFIG.relay, default_scope: "everything" as never },
    });
    expect(problems.some((p) => p.setting === "relay.default_scope")).toBe(true);
  });

  it("rejects an unlimited abuse-sensitive limit", () => {
    const problems = validatePolicyConfig({
      ...DEFAULT_POLICY_CONFIG,
      rate_limit: {
        ...DEFAULT_POLICY_CONFIG.rate_limit,
        messages_per_minute: 0,
      },
    });
    expect(
      problems.some((p) => p.setting === "rate_limit.messages_per_minute"),
    ).toBe(true);
  });
});

describe("Policy engine — determinism", () => {
  it("produces the same decision and rule ids for the same input", async () => {
    const results = [];
    for (let i = 0; i < 3; i++) {
      const h = harness();
      const decision = await h.engine.authorizeSubmission(
        request(principal(), ["bob@example.org"]),
      );
      results.push({
        decision: decision.decision,
        reason: decision.record.reason_code,
        rules: decision.record.rule_ids,
        score: decision.record.spam_score,
      });
    }
    expect(new Set(results.map((r) => JSON.stringify(r))).size).toBe(1);
  });
});
