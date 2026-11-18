// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The policy engine: relay authorization (INV-1), suppression, blocklists,
// role addresses, rate limits, warmup, content scoring and auditability.
//
// Covers IR verification obligations V-9, V-11, V-12, V-13, V-14, V-15,
// V-16, V-18, V-20, V-21.

import { describe, expect, it } from "vitest";

import { REASON_CODES } from "../../src/domain/policy.js";
import { harness, principal, request } from "./harness.js";

describe("Policy engine — relay authorization (INV-1, V-16)", () => {
  it("denies a recipient domain outside the allowlist", async () => {
    const h = harness();
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@not-allowed.test"]),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.RECIPIENT_SCOPE_DENIED);
  });

  it("allows a recipient domain on the allowlist", async () => {
    const h = harness();
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org"]),
    );
    expect(decision.decision).toBe("allow");
  });

  it("denies every recipient when the scope is `none`", async () => {
    const h = harness();
    const decision = await h.engine.authorizeSubmission(
      request(principal({ recipient_scope: "none" }), ["bob@example.org"]),
    );
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.RECIPIENT_SCOPE_DENIED);
  });

  it("denies an arbitrary From domain that the principal does not own", async () => {
    const h = harness();
    const req = request(principal(), ["bob@example.org"]);
    const decision = await h.engine.authorizeSubmission({
      ...req,
      envelope: { ...req.envelope, sender: "attacker@evil.test" },
    });
    expect(decision.decision).toBe("deny");
    expect(decision.record.reason_code).toBe(REASON_CODES.SENDER_NOT_ALLOWED);
  });

  it("denies a null reverse-path envelope sender", async () => {
    const h = harness();
    const req = request(principal(), ["bob@example.org"]);
    const decision = await h.engine.authorizeSubmission({
      ...req,
      envelope: { ...req.envelope, sender: "<>" },
    });
    expect(decision.decision).toBe("reject");
    expect(decision.record.reason_code).toBe(REASON_CODES.VALIDATION_FAILED);
  });

  it("allows the `all` scope but keeps the sender domain restricted", async () => {
    const h = harness();
    const p = principal({ recipient_scope: "all", roles: ["admin"] });
    const decision = await h.engine.authorizeSubmission(
      request(p, ["bob@anywhere.test"]),
    );
    expect(decision.decision).toBe("allow");

    // The sender domain is still restricted: an unauthorized From is denied.
    const req = request(p, ["bob@anywhere.test"]);
    const denied = await h.engine.authorizeSubmission({
      ...req,
      envelope: { ...req.envelope, sender: "attacker@evil.test" },
    });
    expect(denied.decision).toBe("deny");
    expect(denied.record.reason_code).toBe(REASON_CODES.SENDER_NOT_ALLOWED);
  });

  it("enforces `same_domain_only` against the tenant's sending domains", async () => {
    const h = harness();
    const p = principal({ recipient_scope: "same_domain_only" });
    const allowed = await h.engine.authorizeSubmission(
      request(p, ["bob@example.com"]),
    );
    expect(allowed.decision).toBe("allow");
    const denied = await h.engine.authorizeSubmission(
      request(p, ["bob@other.test"]),
    );
    expect(denied.decision).toBe("deny");
  });

  it("enforces `verified_recipients_only` permanently", async () => {
    const h = harness();
    const p = principal({ recipient_scope: "verified_recipients_only" });
    const denied = await h.engine.authorizeSubmission(
      request(p, ["bob@example.org"]),
    );
    expect(denied.decision).toBe("deny");
    expect(denied.record.reason_code).toBe(REASON_CODES.RECIPIENT_NOT_VERIFIED);

    await h.verified.add("tenant-1", "bob@example.org");
    const allowed = await h.engine.authorizeSubmission(
      request(p, ["bob@example.org"]),
    );
    expect(allowed.decision).toBe("allow");
  });

  it("applies the same scope on the outbound relay path (V-17)", async () => {
    const h = harness();
    const p = principal();
    const allowed = await h.engine.authorizeRelay("tenant-1", p, "example.org");
    expect(allowed.allowed).toBe(true);
    const denied = await h.engine.authorizeRelay("tenant-1", p, "evil.test");
    expect(denied.allowed).toBe(false);
    expect(denied.reason_code).toBe(REASON_CODES.RECIPIENT_SCOPE_DENIED);
  });

  it("matches an allowlist subdomain only when configured to", async () => {
    const h = harness();
    const strict = await h.engine.authorizeSubmission(
      request(principal(), ["bob@mail.example.org"]),
    );
    expect(strict.decision).toBe("deny");

    const h2 = harness();
    const relaxed = await h2.engine.authorizeSubmission(
      request(
        principal({
          allowlist_includes_subdomains: true,
        }),
        ["bob@mail.example.org"],
      ),
    );
    expect(relaxed.decision).toBe("allow");
  });
});

describe("Policy engine — partial acceptance (V-18)", () => {
  it("enqueues only the allowed recipients and reports the denied one", async () => {
    const h = harness();
    const decision = await h.engine.authorizeSubmission(
      request(principal(), ["bob@example.org", "eve@not-allowed.test"]),
    );
    expect(decision.recipients).toHaveLength(2);
    const allowed = decision.recipients.filter((r) => r.decision === "allow");
    const denied = decision.recipients.filter((r) => r.decision !== "allow");
    expect(allowed).toHaveLength(1);
    expect(allowed[0]?.recipient.address).toBe("bob@example.org");
    expect(denied).toHaveLength(1);
    expect(denied[0]?.reason_code).toBe(REASON_CODES.RECIPIENT_SCOPE_DENIED);
  });
});

