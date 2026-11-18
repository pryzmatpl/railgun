// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * Unit tests for the send-request schema, the auth resolver, the crypto
 * helpers and the router.
 */

import { describe, expect, it } from "vitest";
import { createHmac } from "node:crypto";
import {
  classifyBearer,
  extractBearer,
  hashApiKey,
  keyPrefix,
  resolveApiKey,
  verifyJwt,
  verifyWebhookHmac,
} from "../../src/http/auth.js";
import { canonicalDigest, canonicalJson, decodeCursor, encodeCursor, safeEqual } from "../../src/http/crypto.js";
import { HttpError } from "../../src/http/errors.js";
import { Router } from "../../src/http/router.js";
import {
  isValidAddress,
  normalizeAddress,
  parseSendRequest,
  splitAddressList,
} from "../../src/http/schemas/send.js";
import { deliveryRate } from "../../src/http/schemas/projection.js";

const NOW = new Date("2026-11-18T10:31:04.123Z");

const OPTIONS = {
  now: NOW,
  hasIdempotencyHeader: false,
  max_body_bytes: 1024,
  max_attachment_bytes: 1024,
  max_recipients_per_message: 50,
};

describe("send request schema", () => {
  it("accepts the minimal Jaisiu body", () => {
    const parsed = parseSendRequest(
      { to: "a@example.com", subject: "Hello", text: "body" },
      OPTIONS,
    );
    expect(parsed.to).toEqual(["a@example.com"]);
    expect(parsed.subject).toBe("Hello");
    expect(parsed.request_id).toBeNull();
  });

  it("parses a comma-separated recipient list", () => {
    const parsed = parseSendRequest(
      { to: "a@example.com, b@example.com", subject: "Hello", text: "body" },
      OPTIONS,
    );
    expect(parsed.to).toEqual(["a@example.com", "b@example.com"]);
  });

  it("does not split a comma inside a quoted display name", () => {
    expect(splitAddressList('"Doe, Jane" <jane@example.com>')).toEqual([
      '"Doe, Jane" <jane@example.com>',
    ]);
  });

  it("rejects an invalid address", () => {
    expect(() =>
      parseSendRequest({ to: "not-an-address", subject: "Hello", text: "b" }, OPTIONS),
    ).toThrowError(HttpError);
  });

  it("rejects a missing body", () => {
    try {
      parseSendRequest({ to: "a@example.com", subject: "Hello" }, OPTIONS);
      throw new Error("expected a body failure");
    } catch (error) {
      expect((error as HttpError).details?.field).toBe("body");
    }
  });

  it("rejects both dialects with different values", () => {
    try {
      parseSendRequest(
        {
          to: "a@example.com",
          subject: "Hello",
          text: "b",
          request_id: "r1",
          reply_to: "one@example.com",
          replyTo: "two@example.com",
        },
        OPTIONS,
      );
      throw new Error("expected an AMBIGUOUS_FIELD failure");
    } catch (error) {
      expect(error).toBeInstanceOf(HttpError);
      expect((error as HttpError).code).toBe("AMBIGUOUS_FIELD");
      expect((error as HttpError).status).toBe(400);
    }
  });

  it("accepts both dialects with equal values", () => {
    const parsed = parseSendRequest(
      {
        to: "a@example.com",
        subject: "Hello",
        text: "b",
        request_id: "r1",
        reply_to: "same@example.com",
        replyTo: "same@example.com",
      },
      OPTIONS,
    );
    expect(parsed.reply_to).toBe("same@example.com");
  });

  it("rejects a schedule_at in the past", () => {
    try {
      parseSendRequest(
        {
          to: "a@example.com",
          subject: "Hello",
          text: "b",
          request_id: "r1",
          schedule_at: "2020-01-01T00:00:00Z",
        },
        OPTIONS,
      );
      throw new Error("expected a schedule_at failure");
    } catch (error) {
      expect((error as HttpError).details?.field).toBe("schedule_at");
    }
  });

  it("rejects oversized metadata", () => {
    const metadata: Record<string, string> = {};
    for (let index = 0; index < 20; index += 1) {
      metadata[`key-${index}`] = "value";
    }
    try {
      parseSendRequest(
        { to: "a@example.com", subject: "Hello", text: "b", request_id: "r1", metadata },
        OPTIONS,
      );
      throw new Error("expected a metadata failure");
    } catch (error) {
      expect((error as HttpError).details?.field).toBe("metadata");
    }
  });

  it("normalizes the domain but keeps the local part", () => {
    expect(normalizeAddress("User@EXAMPLE.COM")).toBe("User@example.com");
    expect(isValidAddress("user@example.com")).toBe(true);
    expect(isValidAddress("user@localhost")).toBe(false);
    expect(isValidAddress("user example.com")).toBe(false);
  });
});

describe("credential classification", () => {
  it("classifies a JWT and an API key by shape", () => {
    expect(classifyBearer("aaa.bbb.ccc")).toBe("jwt");
    expect(classifyBearer("rgk_abc_def")).toBe("api_key");
    expect(classifyBearer("opaque")).toBe("unknown");
  });

  it("extracts a bearer token case-insensitively", () => {
    expect(extractBearer("bearer abc")).toBe("abc");
    expect(extractBearer("Bearer abc")).toBe("abc");
    expect(extractBearer("Basic abc")).toBeUndefined();
  });

  it("derives the lookup prefix of an API key", () => {
    expect(keyPrefix("rgk_tenantA_secret")).toBe("tenantA");
  });
});

describe("api key resolution", () => {
  const record = {
    id: "key_1",
    tenant_id: "tenant_a",
    key_prefix: "abc",
    key_hash: hashApiKey("rgk_abc_secret"),
    scopes: ["send", "read"],
    roles: [],
    allowed_senders: ["tenant_a.example.com"],
    allowed_domains: ["tenant_a.example.com"],
    active: true,
    expires_at: null,
  };

  it("resolves an active key", async () => {
    const principal = await resolveApiKey(
      "rgk_abc_secret",
      { findByPrefix: async () => record },
      NOW,
    );
    expect(principal.tenant_id).toBe("tenant_a");
    expect(principal.scopes).toContain("send");
  });

  it("rejects a revoked key", async () => {
    await expect(
      resolveApiKey("rgk_abc_secret", { findByPrefix: async () => ({ ...record, active: false }) }, NOW),
    ).rejects.toThrowError(HttpError);
  });

  it("rejects an expired key", async () => {
    await expect(
      resolveApiKey(
        "rgk_abc_secret",
        { findByPrefix: async () => ({ ...record, expires_at: "2020-01-01T00:00:00Z" }) },
        NOW,
      ),
    ).rejects.toThrowError(HttpError);
  });

  it("rejects a wrong secret", async () => {
    await expect(
      resolveApiKey("rgk_abc_other", { findByPrefix: async () => record }, NOW),
    ).rejects.toThrowError(HttpError);
  });
});

describe("jwt verification", () => {
  const secret = "unit-test-secret";

  function sign(claims: Record<string, unknown>): string {
    const encode = (value: unknown): string =>
      Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
    const header = encode({ alg: "HS256", typ: "JWT" });
    const payload = encode(claims);
    const signature = createHmac("sha256", secret)
      .update(`${header}.${payload}`)
      .digest("base64url");
    return `${header}.${payload}.${signature}`;
  }

  it("accepts a token with the /railgun audience", () => {
    const token = sign({
      sub: "operator",
      tenant_id: "tenant_a",
      aud: "/railgun",
      scopes: ["send"],
      exp: Math.floor(NOW.getTime() / 1000) + 600,
    });
    const principal = verifyJwt(token, { secret, audience: "/railgun" }, NOW);
    expect(principal.tenant_id).toBe("tenant_a");
    expect(principal.scopes).toEqual(["send"]);
  });

  it("rejects a token with another audience", () => {
    const token = sign({
      sub: "operator",
      tenant_id: "tenant_a",
      aud: "/mcp",
      exp: Math.floor(NOW.getTime() / 1000) + 600,
    });
    expect(() => verifyJwt(token, { secret, audience: "/railgun" }, NOW)).toThrowError(HttpError);
  });

  it("rejects an expired token", () => {
    const token = sign({
      sub: "operator",
      tenant_id: "tenant_a",
      aud: "/railgun",
      exp: Math.floor(NOW.getTime() / 1000) - 600,
    });
    expect(() => verifyJwt(token, { secret, audience: "/railgun" }, NOW)).toThrowError(HttpError);
  });
});

describe("webhook hmac", () => {
  it("accepts a valid signature inside the replay window", () => {
    const secret = "webhook-secret";
    const body = Buffer.from("[]", "utf8");
    const signature = createHmac("sha256", secret).update(body).digest("hex");
    expect(() =>
      verifyWebhookHmac(
        {
          "x-railgun-signature": `sha256=${signature}`,
          "x-railgun-timestamp": String(Math.floor(NOW.getTime() / 1000)),
        },
        body,
        secret,
        NOW,
      ),
    ).not.toThrow();
  });

  it("rejects a stale timestamp", () => {
    const secret = "webhook-secret";
    const body = Buffer.from("[]", "utf8");
    const signature = createHmac("sha256", secret).update(body).digest("hex");
    expect(() =>
      verifyWebhookHmac(
        {
          "x-railgun-signature": `sha256=${signature}`,
          "x-railgun-timestamp": String(Math.floor(NOW.getTime() / 1000) - 3600),
        },
        body,
        secret,
        NOW,
      ),
    ).toThrowError(HttpError);
  });
});

describe("crypto helpers", () => {
  it("hashes equivalent bodies identically regardless of key order", () => {
    expect(canonicalDigest({ a: 1, b: 2 })).toBe(canonicalDigest({ b: 2, a: 1 }));
    expect(canonicalJson({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  it("signs and verifies a cursor", () => {
    const cursor = encodeCursor("secret", { ts: "2026-11-18T10:00:00Z", id: "rg-1", f: "filters" });
    expect(decodeCursor("secret", cursor)).toEqual({
      ts: "2026-11-18T10:00:00Z",
      id: "rg-1",
      f: "filters",
    });
  });

  it("rejects a tampered cursor", () => {
    const cursor = encodeCursor("secret", { ts: "2026-11-18T10:00:00Z", id: "rg-1", f: "filters" });
    expect(decodeCursor("other-secret", cursor)).toBeNull();
    expect(decodeCursor("secret", `${cursor}x`)).toBeNull();
  });

  it("compares strings in constant time", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcd")).toBe(false);
  });
});

describe("router", () => {
  function router(): Router {
    const instance = new Router();
    instance.add({ method: "GET", template: "/health", name: "health", handler: async () => {} });
    instance.add({
      method: "GET",
      template: "/v1/messages/{id}",
      name: "messages.get",
      handler: async () => {},
    });
    return instance;
  }

  it("matches an exact path", () => {
    const match = router().match("GET", "/health");
    expect(match && "route" in match).toBe(true);
  });

  it("does not match a prefix of a path", () => {
    expect(router().match("GET", "/health/anything")).toBeNull();
    expect(router().match("GET", "/healthy")).toBeNull();
  });

  it("captures a path parameter", () => {
    const match = router().match("GET", "/v1/messages/rg-123");
    expect(match && "params" in match ? match.params : null).toEqual({ id: "rg-123" });
  });

  it("reports a method mismatch for a known path", () => {
    const match = router().match("POST", "/health");
    expect(match && "methodMismatch" in match ? match.methodMismatch : false).toBe(true);
  });
});

describe("delivery rate", () => {
  it("returns null when the denominator is zero", () => {
    expect(
      deliveryRate({ delivered: 0, deferred: 0, bounced: 0, suppressed: 0, rejected: 0 }),
    ).toBeNull();
  });

  it("excludes queued and accepted messages", () => {
    expect(deliveryRate({ delivered: 1, deferred: 1, bounced: 0, suppressed: 0, rejected: 0 })).toBe(
      0.5,
    );
  });
});
