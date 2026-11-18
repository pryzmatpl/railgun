// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * HTTP round-trip integration tests for the RailGun HTTP surface.
 *
 * Every test boots the real service over a real socket and talks to it with
 * a real HTTP client (`docs/design/railgun-http-api-ir.md` §10.1).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  FIXTURE_SECRETS,
  request,
  startHarness,
  tenantAJwt,
  type Harness,
} from "./harness.js";

describe("RailGun HTTP API surface", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await startHarness();
  });

  afterEach(async () => {
    await harness.close();
  });

  /* ---------------------------------------------------------------------- */
  /* Submission                                                             */
  /* ---------------------------------------------------------------------- */

  it("H-01 accepts a Jaisiu-compatible send with an x-api-key", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "a@example.com", subject: "Hello", text: "plain body" },
    });

    expect(result.status).toBe(202);
    const body = result.body as Record<string, unknown>;
    expect(body.success).toBe(true);
    expect(body.status).toBe("queued");
    expect(body.deliveryConfirmed).toBe(false);
    expect(typeof body.id).toBe("string");
    expect(result.headers.get("location")).toBe(`/v1/messages/${body.id}`);
    expect(result.headers.get("x-request-id")).toBeTruthy();
  });

  it("H-02 accepts the same request through Authorization: Bearer", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { authorization: `Bearer ${FIXTURE_SECRETS.apiKeyTenantA}` },
      body: { to: "a@example.com", subject: "Hello", text: "plain body" },
    });

    expect(result.status).toBe(202);
    expect((result.body as Record<string, unknown>).status).toBe("queued");
  });

  it("H-03 accepts an audience-scoped JWT", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { authorization: `Bearer ${tenantAJwt()}` },
      body: {
        to: "a@example.com",
        subject: "Hello",
        text: "plain body",
        request_id: "jwt-1",
      },
    });

    expect(result.status).toBe(202);
  });

  it("H-04 rejects a JWT whose audience is /mcp", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { authorization: `Bearer ${tenantAJwt({ aud: "/mcp" })}` },
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "mcp-1" },
    });

    expect(result.status).toBe(401);
    expect((result.body as { error: { code: string } }).error.code).toBe("UNAUTHENTICATED");
  });

  it("H-05 rejects a request without a credential and sets WWW-Authenticate", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "no-auth" },
    });

    expect(result.status).toBe(401);
    expect(result.headers.get("www-authenticate")).toBe("Bearer");
    expect(result.raw).not.toContain(FIXTURE_SECRETS.apiKeyTenantA);
  });

  it("H-06 rejects an invalid API key", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": "rgk_tenantA_wrongsecretwrongsecretwrong" },
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "bad-key" },
    });

    expect(result.status).toBe(401);
  });

  it("H-07 rejects a revoked API key", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": "rgk_revoked_fffffffffffffffffffffffffff" },
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "revoked" },
    });

    expect(result.status).toBe(401);
  });

  it("H-08 rejects a read-only key on the send path", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyReadOnly },
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "read-only" },
    });

    expect(result.status).toBe(403);
    const error = (result.body as { error: { code: string; details?: Record<string, unknown> } })
      .error;
    expect(error.code).toBe("INSUFFICIENT_SCOPE");
    expect(error.details?.required_scope).toBe("send");
  });

  it("H-09 does not let an admin-only key send (admin does not imply send)", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyAdminOnly },
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "admin-only" },
    });

    expect(result.status).toBe(403);
    expect((result.body as { error: { code: string } }).error.code).toBe("INSUFFICIENT_SCOPE");
  });

  it("H-10 rejects a sender outside the principal's allowed senders", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: {
        to: "a@example.com",
        subject: "Hello",
        text: "x",
        from: "attacker@evil.example.net",
        request_id: "bad-sender",
      },
    });

    expect(result.status).toBe(403);
    const error = (result.body as { error: { code: string; details?: Record<string, unknown> } })
      .error;
    expect(error.code).toBe("INSUFFICIENT_SCOPE");
    expect(error.details?.reason).toBe("SENDER_NOT_ALLOWED");
  });

  it("H-11 rejects a body that names another tenant", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: {
        to: "a@example.com",
        subject: "Hello",
        text: "x",
        tenant_id: "tenant_b",
        request_id: "tenant-override",
      },
    });

    expect(result.status).toBe(400);
    expect((result.body as { error: { code: string } }).error.code).toBe("INVALID_REQUEST");
  });

  it("derives a replay identity for a legacy body without request_id", async () => {
    // The IR is internally inconsistent here: §4.2 asks for `request_id`
    // unless an Idempotency-Key header is present, while H-01 (the Jaisiu
    // drop-in contract, design goal G1) sends neither. G1/H-01 wins, so the
    // server derives the identity from the canonical body — which keeps the
    // replay guarantee of rules I-1…I-3 intact.
    const headers = { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA };
    const body = { to: "legacy@example.com", subject: "Hello", text: "legacy body" };

    const first = await request(harness, "POST", "/v1/email/send", { headers, body });
    const second = await request(harness, "POST", "/v1/email/send", { headers, body });

    expect(first.status).toBe(202);
    expect(second.status).toBe(202);
    expect((second.body as { id: string }).id).toBe((first.body as { id: string }).id);
    expect(await harness.messages.count("tenant_a")).toBe(1);
    expect(harness.queue.entries).toHaveLength(1);
  });

  it("H-18 rejects both field dialects with different values", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: {
        to: "a@example.com",
        subject: "Hello",
        text: "x",
        request_id: "dialect-1",
        reply_to: "one@example.com",
        replyTo: "two@example.com",
      },
    });

    expect(result.status).toBe(400);
    expect((result.body as { error: { code: string } }).error.code).toBe("AMBIGUOUS_FIELD");
  });

  it("H-19 accepts both field dialects with equal values", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: {
        to: "a@example.com",
        subject: "Hello",
        text: "x",
        request_id: "dialect-2",
        reply_to: "same@example.com",
        replyTo: "same@example.com",
      },
    });

    expect(result.status).toBe(202);
  });

  it("H-20 serves the POST /send alias", async () => {
    const result = await request(harness, "POST", "/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "alias-1" },
    });

    expect(result.status).toBe(202);
    const body = result.body as Record<string, unknown>;
    expect(body.success).toBe(true);
    expect(typeof body.messageId).toBe("string");
  });

  it("H-21 rejects a send without a subject", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "a@example.com", text: "x", request_id: "no-subject" },
    });

    expect(result.status).toBe(400);
    const error = (result.body as { error: { details?: Record<string, unknown> } }).error;
    expect(error.details?.field).toBe("subject");
  });

  it("H-49 accepts camelCase request fields", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: {
        to: "a@example.com",
        subject: "Hello",
        text: "x",
        requestId: "camel-1",
        replyTo: "reply@example.com",
      },
    });

    expect(result.status).toBe(202);
    expect((result.body as { request_id: string }).request_id).toBe("camel-1");
  });

  it("H-50 rejects a schedule_at in the past", async () => {
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: {
        to: "a@example.com",
        subject: "Hello",
        text: "x",
        request_id: "schedule-1",
        schedule_at: "2020-01-01T00:00:00Z",
      },
    });

    expect(result.status).toBe(400);
    const error = (result.body as { error: { details?: Record<string, unknown> } }).error;
    expect(error.details?.field).toBe("schedule_at");
  });

  it("H-22 rejects a suppressed recipient without queuing anything", async () => {
    harness.policy.suppressed.add("blocked@example.com");
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: {
        to: "blocked@example.com",
        subject: "Hello",
        text: "x",
        request_id: "suppressed-1",
      },
    });

    expect(result.status).toBe(422);
    const error = (result.body as { error: { code: string; details?: Record<string, unknown> } })
      .error;
    expect(error.code).toBe("SUPPRESSED");
    expect(error.details?.reason).toBeTruthy();
    expect(harness.queue.entries).toHaveLength(0);
    expect(await harness.messages.count("tenant_a")).toBe(0);
  });

  it("H-23 partially accepts a mixed recipient list", async () => {
    harness.policy.suppressed.add("blocked@example.com");
    const result = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: {
        to: ["ok@example.com", "blocked@example.com"],
        subject: "Hello",
        text: "x",
        request_id: "partial-1",
      },
    });

    expect(result.status).toBe(202);
    const body = result.body as { recipients?: Array<{ status: string }> };
    expect(body.recipients?.map((entry) => entry.status)).toEqual(["queued", "suppressed"]);
    expect(harness.queue.entries).toHaveLength(1);
  });

  /* ---------------------------------------------------------------------- */
  /* Idempotency                                                            */
  /* ---------------------------------------------------------------------- */

  it("H-14 replays an idempotent send without a duplicate message", async () => {
    const headers = {
      "x-api-key": FIXTURE_SECRETS.apiKeyTenantA,
      "idempotency-key": "idem-h14",
    };
    const body = { to: "a@example.com", subject: "Hello", text: "x", request_id: "h14" };

    const first = await request(harness, "POST", "/v1/email/send", { headers, body });
    const second = await request(harness, "POST", "/v1/email/send", { headers, body });

    expect(first.status).toBe(202);
    expect(second.status).toBe(202);
    expect(second.raw).toBe(first.raw);
    expect(second.headers.get("idempotency-replayed")).toBe("true");
    expect(await harness.messages.count("tenant_a")).toBe(1);
    expect(harness.queue.entries).toHaveLength(1);
  });

  it("H-15 rejects an idempotency key reused with a different body", async () => {
    const headers = {
      "x-api-key": FIXTURE_SECRETS.apiKeyTenantA,
      "idempotency-key": "idem-h15",
    };
    await request(harness, "POST", "/v1/email/send", {
      headers,
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "h15" },
    });
    const second = await request(harness, "POST", "/v1/email/send", {
      headers,
      body: { to: "b@example.com", subject: "Hello", text: "x", request_id: "h15" },
    });

    expect(second.status).toBe(409);
    expect((second.body as { error: { code: string } }).error.code).toBe("IDEMPOTENCY_KEY_REUSED");
    expect(await harness.messages.count("tenant_a")).toBe(1);
  });

  it("H-16 replays a repeated request_id without a duplicate message", async () => {
    const headers = { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA };
    const body = { to: "a@example.com", subject: "Hello", text: "x", request_id: "h16" };

    const first = await request(harness, "POST", "/v1/email/send", { headers, body });
    const second = await request(harness, "POST", "/v1/email/send", { headers, body });

    expect(first.status).toBe(202);
    expect(second.status).toBe(202);
    expect(await harness.messages.count("tenant_a")).toBe(1);
    expect(harness.queue.entries).toHaveLength(1);
  });

  /* ---------------------------------------------------------------------- */
  /* Reads, tenant isolation and actions                                    */
  /* ---------------------------------------------------------------------- */

  it("H-12 hides a tenant-A message from tenant B", async () => {
    const created = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "iso-1" },
    });
    const id = (created.body as { id: string }).id;

    const result = await request(harness, "GET", `/v1/messages/${id}`, {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantB },
    });

    expect(result.status).toBe(404);
    expect((result.body as { error: { code: string } }).error.code).toBe("NOT_FOUND");
  });

  it("H-13 lists only the caller's tenant messages", async () => {
    await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "a@example.com", subject: "A", text: "x", request_id: "list-a" },
    });
    await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantB },
      body: { to: "b@example.com", subject: "B", text: "x", request_id: "list-b" },
    });

    const result = await request(harness, "GET", "/v1/messages", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantB },
    });

    expect(result.status).toBe(200);
    const body = result.body as { data: Array<{ request_id: string }> };
    expect(body.data).toHaveLength(1);
    expect(body.data[0]?.request_id).toBe("list-b");
  });

  it("H-30 rejects limit=0", async () => {
    const result = await request(harness, "GET", "/v1/messages?limit=0", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    expect(result.status).toBe(400);
    expect((result.body as { error: { code: string } }).error.code).toBe("INVALID_LIMIT");
  });

  it("H-31 rejects an unknown filter", async () => {
    const result = await request(harness, "GET", "/v1/messages?bogus_filter=1", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    expect(result.status).toBe(400);
    expect((result.body as { error: { code: string } }).error.code).toBe("UNKNOWN_FILTER");
  });

  it("H-32 rejects a tampered cursor", async () => {
    const result = await request(harness, "GET", "/v1/messages?cursor=tampered.cursor", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    expect(result.status).toBe(400);
    expect((result.body as { error: { code: string } }).error.code).toBe("INVALID_CURSOR");
  });

  it("H-33 rejects a cursor bound to a different filter set", async () => {
    for (let index = 0; index < 3; index += 1) {
      await request(harness, "POST", "/v1/email/send", {
        headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
        body: {
          to: `a${index}@example.com`,
          subject: "Hello",
          text: "x",
          request_id: `cursor-${index}`,
        },
      });
    }
    const page = await request(harness, "GET", "/v1/messages?limit=1", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });
    const cursor = (page.body as { page: { next_cursor: string } }).page.next_cursor;
    expect(cursor).toBeTruthy();

    const result = await request(harness, "GET", `/v1/messages?limit=1&status=queued&cursor=${cursor}`, {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    expect(result.status).toBe(400);
    expect((result.body as { error: { code: string } }).error.code).toBe("INVALID_CURSOR");
  });

  it("H-34 omits the body for a read-only principal", async () => {
    const created = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "a@example.com", subject: "Hello", text: "secret body", request_id: "body-1" },
    });
    const id = (created.body as { id: string }).id;

    const result = await request(harness, "GET", `/v1/messages/${id}?include_body=true`, {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyReadOnly },
    });

    expect(result.status).toBe(200);
    expect(result.raw).not.toContain("secret body");
    expect((result.body as Record<string, unknown>).text).toBeUndefined();
  });

  it("H-35 returns the body for a body:read principal", async () => {
    const created = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "a@example.com", subject: "Hello", text: "visible body", request_id: "body-2" },
    });
    const id = (created.body as { id: string }).id;

    const result = await request(harness, "GET", `/v1/messages/${id}?include_body=true`, {
      headers: { "x-api-key": "rgk_bodyreader_eeeeeeeeeeeeeeeeeeeeeee" },
    });

    expect(result.status).toBe(200);
    expect((result.body as { text?: string }).text).toBe("visible body");
  });

  it("H-36 rejects a retry without an Idempotency-Key", async () => {
    const created = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "retry-1" },
    });
    const id = (created.body as { id: string }).id;

    const result = await request(harness, "POST", `/v1/messages/${id}/retry`, {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyAdminOnly },
    });

    expect(result.status).toBe(400);
    expect((result.body as { error: { code: string } }).error.code).toBe("INVALID_REQUEST");
  });

  it("H-37 retries a message and keeps its identifier", async () => {
    const created = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "retry-2" },
    });
    const id = (created.body as { id: string }).id;
    await harness.messages.update("tenant_a", id, { status: "deferred", attempts: 3 });

    const result = await request(harness, "POST", `/v1/messages/${id}/retry`, {
      headers: {
        "x-api-key": FIXTURE_SECRETS.apiKeyAdminOnly,
        "idempotency-key": "retry-key-2",
      },
    });

    expect(result.status).toBe(202);
    const body = result.body as { id: string; attempts_reset: boolean };
    expect(body.id).toBe(id);
    expect(body.attempts_reset).toBe(true);
    const stored = await harness.messages.get("tenant_a", id);
    expect(stored?.attempts).toBe(0);
    expect(stored?.status).toBe("queued");
  });

  it("H-38 suppresses a recipient for later sends", async () => {
    const created = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "target@example.com", subject: "Hello", text: "x", request_id: "suppress-1" },
    });
    const id = (created.body as { id: string }).id;

    const suppressed = await request(harness, "POST", `/v1/messages/${id}/suppress`, {
      headers: {
        "x-api-key": FIXTURE_SECRETS.apiKeyAdminOnly,
        "idempotency-key": "suppress-key-1",
      },
      body: { email: "target@example.com", reason: "manual", scope: "global" },
    });
    expect(suppressed.status).toBe(200);

    harness.policy.suppressed.add("target@example.com");
    const later = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "target@example.com", subject: "Hello", text: "x", request_id: "suppress-2" },
    });

    expect(later.status).toBe(422);
    expect((later.body as { error: { code: string } }).error.code).toBe("SUPPRESSED");
  });

  it("H-39 makes suppression idempotent", async () => {
    const created = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "target@example.com", subject: "Hello", text: "x", request_id: "suppress-3" },
    });
    const id = (created.body as { id: string }).id;
    const headers = {
      "x-api-key": FIXTURE_SECRETS.apiKeyAdminOnly,
      "idempotency-key": "suppress-key-2",
    };
    const body = { email: "target@example.com", reason: "manual", scope: "global" };

    const first = await request(harness, "POST", `/v1/messages/${id}/suppress`, { headers, body });
    const second = await request(harness, "POST", `/v1/messages/${id}/suppress`, { headers, body });

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect((second.body as { created: boolean }).created).toBe(false);
  });

  /* ---------------------------------------------------------------------- */
  /* Health, readiness, bounces and stats                                  */
  /* ---------------------------------------------------------------------- */

  it("H-24 serves the health endpoints without a credential", async () => {
    for (const path of ["/health", "/healthz"]) {
      const result = await request(harness, "GET", path);
      expect(result.status).toBe(200);
      const body = result.body as { ok: boolean; status: string };
      expect(body.ok).toBe(true);
      expect(body.status).toBe("ok");
    }
  });

  it("H-25 does not shadow health paths by prefix", async () => {
    for (const path of ["/health/anything", "/healthz/anything"]) {
      const result = await request(harness, "GET", path);
      expect(result.status).toBe(404);
    }
  });

  it("H-26 serves readiness with a read key", async () => {
    const result = await request(harness, "GET", "/ready", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    expect(result.status).toBe(200);
    const body = result.body as { ok: boolean; checks: unknown[] };
    expect(body.ok).toBe(true);
    expect(Array.isArray(body.checks)).toBe(true);
  });

  it("H-29 returns stats with a null delivery rate when no data", async () => {
    const result = await request(harness, "GET", "/v1/stats?group_by=day", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    expect(result.status).toBe(200);
    const body = result.body as { totals: Record<string, number>; buckets: unknown[] };
    expect(body.totals.queued).toBe(0);
    expect(body.buckets).toEqual([]);
  });

  it("H-28 serves a sanitized bounce list", async () => {
    await harness.bounces.insert({
      id: "bnc-1",
      tenant_id: "tenant_a",
      message_id: "rg-1",
      request_id: "r1",
      recipient_hash: "sha256:abc",
      code: "5.1.1",
      enhanced_code: "5.1.1",
      class: "hard",
      reason: "mailbox_does_not_exist",
      remote_mta: "mx.example.net",
      action_taken: "suppressed",
      occurred_at: "2026-11-18T10:35:11.004Z",
    });

    const result = await request(harness, "GET", "/v1/bounces", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    expect(result.status).toBe(200);
    const body = result.body as { data: Array<Record<string, unknown>> };
    expect(body.data).toHaveLength(1);
    expect(body.data[0]?.code).toBe("5.1.1");
    expect(body.data[0]?.reason).toBe("mailbox_does_not_exist");
    expect(body.data[0]?.raw_response).toBeUndefined();
  });

  it("H-41 rejects an invalid webhook signature", async () => {
    const result = await request(harness, "POST", "/v1/events", {
      headers: {
        "x-railgun-signature": "sha256=deadbeef",
        "x-railgun-timestamp": String(Math.floor(Date.now() / 1000)),
      },
      body: [{ message_id: "rg-1", code: "5.1.1" }],
    });

    expect(result.status).toBe(401);
    expect((result.body as { error: { code: string } }).error.code).toBe("UNAUTHENTICATED");
  });

  it("H-42 serves Prometheus metrics without credential material", async () => {
    const result = await request(harness, "GET", "/metrics");

    expect(result.status).toBe(200);
    expect(result.headers.get("content-type")).toContain("text/plain");
    expect(result.raw).not.toContain(FIXTURE_SECRETS.apiKeyTenantA);
  });

  /* ---------------------------------------------------------------------- */
  /* Structural guarantees                                                   */
  /* ---------------------------------------------------------------------- */

  it("H-43 never leaks a stack trace or a file path", async () => {
    const result = await request(harness, "GET", "/v1/messages/does-not-exist", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    expect(result.status).toBe(404);
    expect(result.raw).not.toContain(" at ");
    expect(result.raw).not.toContain("/home/");
    expect(result.raw).not.toMatch(/\.ts:\d+/);
  });

  it("H-44 never echoes a fixture secret in any response", async () => {
    const responses = await Promise.all([
      request(harness, "GET", "/health"),
      request(harness, "GET", "/ready"),
      request(harness, "GET", "/v1/messages", {
        headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      }),
      request(harness, "POST", "/v1/email/send", {
        headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
        body: { to: "a@example.com", subject: "Hello", text: "x" },
      }),
      request(harness, "GET", "/v1/messages/missing", {
        headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      }),
    ]);

    for (const response of responses) {
      for (const secret of Object.values(FIXTURE_SECRETS)) {
        expect(response.raw).not.toContain(secret);
      }
    }
  });

  it("H-45 rejects a payload over the body limit", async () => {
    const oversized = await startHarness({ body_limit_bytes: 256 });
    try {
      const result = await request(oversized, "POST", "/v1/email/send", {
        headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
        body: { to: "a@example.com", subject: "Hello", text: "x".repeat(2048), request_id: "big" },
      });

      expect(result.status).toBe(413);
      expect((result.body as { error: { code: string } }).error.code).toBe("PAYLOAD_TOO_LARGE");
    } finally {
      await oversized.close();
    }
  });

  it("H-46 rate limits with a Retry-After header", async () => {
    const limited = await startHarness({ rate_limit_per_minute: 1 });
    try {
      const headers = { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA };
      const first = await request(limited, "GET", "/v1/messages", { headers });
      const second = await request(limited, "GET", "/v1/messages", { headers });

      expect(first.status).toBe(200);
      expect(second.status).toBe(429);
      expect(second.headers.get("retry-after")).toBeTruthy();
      expect((second.body as { error: { details?: Record<string, unknown> } }).error.details?.limit).toBe(
        "api_key_minute",
      );
    } finally {
      await limited.close();
    }
  });

  it("H-47 reports acceptance without claiming delivery", async () => {
    const created = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "accept-1" },
    });
    const id = (created.body as { id: string }).id;
    await harness.messages.update("tenant_a", id, {
      status: "accepted",
      delivery: "accepted",
      deliveryConfirmed: true,
      smtp_code: 250,
      accepted_at: "2026-11-18T10:31:05.000Z",
    });

    const result = await request(harness, "GET", `/v1/messages/${id}`, {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    expect(result.status).toBe(200);
    const body = result.body as { status: string; deliveryConfirmed: boolean; delivery: string };
    expect(body.status).toBe("accepted");
    expect(body.deliveryConfirmed).toBe(true);
    expect(body.delivery).not.toBe("delivered");
  });

  it("H-48 reports a confirmed delivery", async () => {
    const created = await request(harness, "POST", "/v1/email/send", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
      body: { to: "a@example.com", subject: "Hello", text: "x", request_id: "deliver-1" },
    });
    const id = (created.body as { id: string }).id;
    await harness.messages.update("tenant_a", id, {
      status: "delivered",
      delivery: "delivered",
      deliveryConfirmed: true,
      accepted_at: "2026-11-18T10:31:05.000Z",
      delivered_at: "2026-11-18T10:32:05.000Z",
    });

    const result = await request(harness, "GET", `/v1/messages/${id}`, {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    const body = result.body as { status: string; delivery: string; deliveryConfirmed: boolean };
    expect(body.status).toBe("delivered");
    expect(body.delivery).toBe("delivered");
    expect(body.deliveryConfirmed).toBe(true);
  });

  it("returns 405 for a known path with the wrong method", async () => {
    const result = await request(harness, "DELETE", "/v1/messages", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    expect(result.status).toBe(405);
    expect((result.body as { error: { code: string } }).error.code).toBe("METHOD_NOT_ALLOWED");
  });

  it("serves an OpenAPI document generated from the route table", async () => {
    const result = await request(harness, "GET", "/v1/openapi.json", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });

    expect(result.status).toBe(200);
    const body = result.body as {
      openapi: string;
      paths: Record<string, Record<string, unknown>>;
    };
    expect(body.openapi).toBe("3.1.0");
    expect(body.paths["/v1/email/send"]?.post).toBeDefined();
    expect(body.paths["/v1/messages/{id}"]?.get).toBeDefined();
    expect(body.paths["/health"]?.get).toBeDefined();
  });
});
