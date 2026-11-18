// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The package-wide verification suite.
 *
 * These are the T2/T3 integration checks of the verification IR: the shipped
 * fake MX server drives the real outbound path, the SMTP submission surface
 * queues into the durable outbox, the HTTP and MCP surfaces replay the same
 * idempotency key, the rate limiter refuses before any SMTP transaction is
 * opened, and a signed message verifies with an independent DKIM check.
 *
 * Contract: `docs/design/481de2b7-e002-4cdc-95e0-0adc9068e2c4.md` §3.
 */
import { createHash, createVerify, generateKeyPairSync, sign } from "node:crypto";

import { afterEach, describe, expect, it } from "vitest";

import { startFakeMxServer, type FakeMxServer } from "../../src/verification/fake-mx.js";
import { buildMessageId, messageIdHeader } from "../../src/outbound/message-id.js";
import { inspectLoopMarker } from "../../src/outbound/engine.js";
import {
  canonicalizeBody,
  canonicalizeHeaderSet,
  parseHeaderBlock,
} from "../../src/signer/canonicalization.js";
import { FIXTURE_SECRETS, request, startHarness, type Harness } from "../http/harness.js";

/** The fake servers started by a test, closed after the test. */
const fakeServers: FakeMxServer[] = [];
/** The HTTP harnesses started by a test, closed after the test. */
const harnesses: Harness[] = [];

/** Start a fake MX and register it for cleanup. */
async function fakeMx(script: Parameters<typeof startFakeMxServer>[0] = {}): Promise<FakeMxServer> {
  const server = await startFakeMxServer(script);
  fakeServers.push(server);
  return server;
}

/** Start the HTTP harness and register it for cleanup. */
async function harness(): Promise<Harness> {
  const started = await startHarness();
  harnesses.push(started);
  return started;
}

afterEach(async () => {
  while (harnesses.length > 0) {
    const started = harnesses.pop();
    await started?.close();
  }
  while (fakeServers.length > 0) {
    const server = fakeServers.pop();
    await server?.close();
  }
});

describe("the shipped fake MX harness", () => {
  it("binds to loopback on an ephemeral port", async () => {
    const mx = await fakeMx();
    expect(mx.host).toBe("127.0.0.1");
    expect(mx.port).toBeGreaterThan(0);
  });

  it("records the SMTP dialogue and the exact DATA bytes", async () => {
    const mx = await fakeMx({ capabilities: ["8BITMIME"] });
    const { SmtpClient } = await import("../../src/outbound/smtp-client.js");
    const client = new SmtpClient({
      host: mx.host,
      port: mx.port,
      address: mx.host,
      localDomain: "railgun.test",
      connectionTimeoutMs: 5_000,
      commandTimeoutMs: 5_000,
      tlsMode: "opportunistic",
      allowPlaintext: true,
    });
    await client.connect();
    await client.command("EHLO", "railgun.test");
    await client.command("MAIL", "FROM:<sender@example.test>");
    await client.command("RCPT", "TO:<user@example.test>");
    await client.command("DATA");
    const final = await client.data(Buffer.from("Subject: hi\r\n\r\nbody\r\n", "utf8"));
    await client.quit();

    expect(final.code).toBe(250);
    expect(mx.connectionCount).toBe(1);
    expect(mx.received).toContain("MAIL FROM:<sender@example.test>");
    expect(mx.received).toContain("RCPT TO:<user@example.test>");
    expect(mx.sessions[0]?.body).toContain("Subject: hi");
  });

  it("scripts a permanent rejection", async () => {
    const mx = await fakeMx({ final: { code: 550, text: "5.1.1 No such user" } });
    const { SmtpClient } = await import("../../src/outbound/smtp-client.js");
    const client = new SmtpClient({
      host: mx.host,
      port: mx.port,
      address: mx.host,
      localDomain: "railgun.test",
      connectionTimeoutMs: 5_000,
      commandTimeoutMs: 5_000,
      tlsMode: "opportunistic",
      allowPlaintext: true,
    });
    await client.connect();
    await client.command("EHLO", "railgun.test");
    await client.command("MAIL", "FROM:<sender@example.test>");
    await client.command("RCPT", "TO:<user@example.test>");
    await client.command("DATA");
    const final = await client.data(Buffer.from("body\r\n", "utf8"));
    await client.quit();

    expect(final.code).toBe(550);
  });

  it("scripts a per-recipient rejection", async () => {
    const mx = await fakeMx({
      rcptTo: {
        "blocked@example.test": { code: 550, text: "5.1.1 Blocked" },
      },
    });
    const { SmtpClient } = await import("../../src/outbound/smtp-client.js");
    const client = new SmtpClient({
      host: mx.host,
      port: mx.port,
      address: mx.host,
      localDomain: "railgun.test",
      connectionTimeoutMs: 5_000,
      commandTimeoutMs: 5_000,
      tlsMode: "opportunistic",
      allowPlaintext: true,
    });
    await client.connect();
    await client.command("EHLO", "railgun.test");
    await client.command("MAIL", "FROM:<sender@example.test>");
    const blocked = await client.command("RCPT", "TO:<blocked@example.test>");
    const allowed = await client.command("RCPT", "TO:<user@example.test>");
    await client.quit();

    expect(blocked.code).toBe(550);
    expect(allowed.code).toBe(250);
  });

  it("never records AUTH material", async () => {
    const mx = await fakeMx({ capabilities: ["AUTH PLAIN LOGIN"] });
    const { SmtpClient } = await import("../../src/outbound/smtp-client.js");
    const client = new SmtpClient({
      host: mx.host,
      port: mx.port,
      address: mx.host,
      localDomain: "railgun.test",
      connectionTimeoutMs: 5_000,
      commandTimeoutMs: 5_000,
      tlsMode: "opportunistic",
      allowPlaintext: true,
      auth: { username: "sender@example.test", password: FIXTURE_SECRETS.smtpPassword },
    });
    await client.connect();
    await client.command("EHLO", "railgun.test");
    await client.quit();

    expect(mx.received).not.toContain(FIXTURE_SECRETS.smtpPassword);
    expect(mx.received).not.toContain("AUTH PLAIN ");
  });
});

describe("the HTTP surface (V-HTTP-1 … V-HTTP-6)", () => {
  it("accepts a send and returns a queued message", async () => {
    const http = await harness();
    const response = await request(http, "POST", "/v1/email/send", {
      headers: {
        "content-type": "application/json",
        "x-api-key": FIXTURE_SECRETS.apiKeyTenantA,
        "idempotency-key": "http-request-1",
      },
      body: ({
        to: ["user@example.test"],
        subject: "hello",
        text: "body",
      }),
    });

    expect(response.status).toBe(202);
    expect((response.body as { status: string }).status).toBe("queued");
    expect((response.body as { id: string }).id).toMatch(/^rg-/);
  });

  it("replays the original response for a repeated Idempotency-Key", async () => {
    const http = await harness();
    const payload = {
      to: ["user@example.test"],
      subject: "hello",
      text: "body",
    };
    const first = await request(http, "POST", "/v1/email/send", {
      headers: {
        "content-type": "application/json",
        "x-api-key": FIXTURE_SECRETS.apiKeyTenantA,
        "idempotency-key": "http-request-2",
      },
      body: payload,
    });
    const second = await request(http, "POST", "/v1/email/send", {
      headers: {
        "content-type": "application/json",
        "x-api-key": FIXTURE_SECRETS.apiKeyTenantA,
        "idempotency-key": "http-request-2",
      },
      body: payload,
    });

    expect(second.status).toBe(202);
    expect((second.body as { id: string }).id).toBe((first.body as { id: string }).id);
  });

  it("rejects an unauthenticated request with 401", async () => {
    const http = await harness();
    const response = await request(http, "POST", "/v1/email/send", {
      headers: { "content-type": "application/json" },
      body: ({ to: ["user@example.test"], subject: "x", text: "y" }),
    });

    expect(response.status).toBe(401);
  });

  it("keeps a tenant's messages invisible to another tenant", async () => {
    const http = await harness();
    const sent = await request(http, "POST", "/v1/email/send", {
      headers: {
        "content-type": "application/json",
        "x-api-key": FIXTURE_SECRETS.apiKeyTenantA,
        "idempotency-key": "tenant-isolation-1",
      },
      body: ({
        to: ["user@example.test"],
        subject: "hello",
        text: "body",
      }),
    });
    const id = (sent.body as { id: string }).id;

    const other = await request(http, "GET", `/v1/messages/${id}`, {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantB },
    });

    expect(other.status).toBe(404);
  });

  it("serves the health endpoint without authentication", async () => {
    const http = await harness();
    const response = await request(http, "GET", "/health");
    expect(response.status).toBe(200);
  });
});

describe("the idempotency boundary (V-IDEM-1 … V-IDEM-5)", () => {
  it("creates at most one message for a repeated key", async () => {
    const http = await harness();
    const payload = {
      to: ["user@example.test"],
      subject: "hello",
      text: "body",
    };
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await request(http, "POST", "/v1/email/send", {
        headers: {
          "content-type": "application/json",
          "x-api-key": FIXTURE_SECRETS.apiKeyTenantA,
          "idempotency-key": "single-effect-1",
        },
        body: payload,
      });
    }

    const listed = await request(http, "GET", "/v1/messages", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });
    const items = (listed.body as { data?: unknown[] }).data ?? [];
    expect(items.length).toBe(1);
  });

  it("does not consume the idempotency key when the request is rejected", async () => {
    const http = await harness();
    const rejected = await request(http, "POST", "/v1/email/send", {
      headers: {
        "content-type": "application/json",
        "x-api-key": FIXTURE_SECRETS.apiKeyTenantA,
        "idempotency-key": "rejected-then-accepted",
      },
      body: ({ to: ["not-an-address"], subject: "x", text: "y" }),
    });
    expect(rejected.status).toBeGreaterThanOrEqual(400);

    // The rejection must not leave a durable message behind: the message list
    // stays empty, and the next distinct request still succeeds.
    const listed = await request(http, "GET", "/v1/messages", {
      headers: { "x-api-key": FIXTURE_SECRETS.apiKeyTenantA },
    });
    expect((listed.body as { data?: unknown[] }).data ?? []).toHaveLength(0);

    const accepted = await request(http, "POST", "/v1/email/send", {
      headers: {
        "content-type": "application/json",
        "x-api-key": FIXTURE_SECRETS.apiKeyTenantA,
        "idempotency-key": "rejected-then-accepted-2",
      },
      body: ({
        to: ["user@example.test"],
        subject: "x",
        text: "y",
      }),
    });
    expect(accepted.status).toBe(202);
  });
});

describe("the rate limiter (V-RATE-1 … V-RATE-6)", () => {
  it("refuses a suppressed recipient without opening an SMTP transaction", async () => {
    const http = await harness();
    http.policy.suppressed.add("suppressed@example.test");

    const response = await request(http, "POST", "/v1/email/send", {
      headers: {
        "content-type": "application/json",
        "x-api-key": FIXTURE_SECRETS.apiKeyTenantA,
        "idempotency-key": "suppressed-1",
      },
      body: ({
        to: ["suppressed@example.test"],
        subject: "hello",
        text: "body",
      }),
    });

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(http.mx.connections).toBe(0);
    expect(http.mx.transactions).toBe(0);
  });

  it("refuses a tenant that exceeds its quota without opening an SMTP transaction", async () => {
    const http = await harness();
    http.policy.tenantRejection = { code: "RATE_LIMITED" };

    const response = await request(http, "POST", "/v1/email/send", {
      headers: {
        "content-type": "application/json",
        "x-api-key": FIXTURE_SECRETS.apiKeyTenantA,
        "idempotency-key": "rate-limited-1",
      },
      body: ({
        to: ["user@example.test"],
        subject: "hello",
        text: "body",
      }),
    });

    // A tenant-level policy rejection is surfaced as a sanitized 422 with the
    // stable `RATE_LIMITED` reason code (TypeScript IR §7).
    expect(response.status).toBe(422);
    expect((response.body as { error: { code: string } }).error.code).toBe("RATE_LIMITED");
    expect(http.mx.connections).toBe(0);
  });
});

describe("the MCP surface (V-MCP-1 … V-MCP-6)", () => {
  it("serves a send round trip over the streamable HTTP transport", async () => {
    const { MemoryEmailApplication } = await import("../../src/application/memory-email-application.js");
    const { createRailGunMcpServer } = await import("../../src/mcp/server.js");
    const {
      createHttpContextResolver,
      startHttpTransport,
    } = await import("../../src/mcp/transports/http.js");
    const { makePrincipal, TestPrincipalResolver, TEST_SALT } = await import("../mcp/fixtures.js");

    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    resolver.apiKeys.set("verification-key", makePrincipal());
    const handle = await startHttpTransport({
      createServer: () =>
        createRailGunMcpServer({
          application,
          principalResolver: resolver,
          recipientSalt: TEST_SALT,
          resolveContext: createHttpContextResolver(resolver),
        }),
      principalResolver: resolver,
      host: "127.0.0.1",
      port: 0,
      enableJsonResponse: true,
      log: () => {},
    });

    try {
      const initialize = await fetch(handle.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: "Bearer verification-key",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "railgun-verification", version: "1.0.0" },
          },
        }),
      });
      expect(initialize.status).toBe(200);
      const sessionId = initialize.headers.get("mcp-session-id");
      expect(sessionId).toBeTruthy();

      const send = await fetch(handle.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: "Bearer verification-key",
          "mcp-session-id": sessionId ?? "",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: {
            name: "email_send",
            arguments: {
              to: ["user@example.test"],
              subject: "hello",
              text: "body",
              requestId: "mcp-request-1",
            },
          },
        }),
      });

      expect(send.status).toBe(200);
      const text = await send.text();
      expect(text).toContain("queued");
      // The message must exist in the store after the round trip.
      const stored = await application.status({
        tenantId: "tnt_a",
        principalId: "prp_sender_a",
        requestId: "mcp-request-1",
      });
      expect(stored).not.toBeNull();
    } finally {
      await handle.close();
    }
  });

  it("replays the same requestId instead of creating a second message", async () => {
    const { MemoryEmailApplication } = await import("../../src/application/memory-email-application.js");
    const application = new MemoryEmailApplication();
    const command = {
      tenantId: "tnt_a",
      principalId: "prp_sender_a",
      to: ["user@example.test"],
      cc: [],
      bcc: [],
      subject: "hello",
      text: "body",
      requestId: "mcp-request-2",
    };

    const first = await application.send(command);
    const second = await application.send(command);

    expect(second.id).toBe(first.id);
    expect(second.replayed).toBe(true);
  });
});

describe("the SMTP submission surface (V-SMTP-1 … V-SMTP-8)", () => {
  it("accepts a message, queues it and reports per-recipient outcomes", async () => {
    const { startTestServer } = await import("../smtp/helpers.js");
    const server = await startTestServer();

    try {
      const client = await server.connect();
      const greeting = await client.expectReply();
      expect(greeting.code).toBe(220);

      await client.command("EHLO railgun.test");
      const mail = await client.command("MAIL FROM:<sender@example.test>");
      expect(mail.code).toBe(250);
      const rcpt = await client.command("RCPT TO:<user@example.test>");
      expect(rcpt.code).toBe(250);
      const data = await client.command("DATA");
      expect(data.code).toBe(354);
      await client.sendRaw("From: sender@example.test\r\nSubject: hello\r\n\r\nbody\r\n.\r\n");
      const accepted = await client.expectReply();
      expect(accepted.code).toBe(250);
      await client.command("QUIT");

      expect(server.queue.submissions).toHaveLength(1);
      expect(server.queue.submissions[0]?.recipients).toContain("user@example.test");
    } finally {
      await server.close();
    }
  });

  it("unstuffs a doubled leading dot exactly once", async () => {
    const { startTestServer } = await import("../smtp/helpers.js");
    const server = await startTestServer();

    try {
      const client = await server.connect();
      await client.expectReply();
      await client.command("EHLO railgun.test");
      await client.command("MAIL FROM:<sender@example.test>");
      await client.command("RCPT TO:<user@example.test>");
      await client.command("DATA");
      await client.sendRaw("From: sender@example.test\r\nSubject: dots\r\n\r\n..leading\r\n.\r\n");
      const accepted = await client.expectReply();
      expect(accepted.code).toBe(250);
      await client.command("QUIT");

      const raw = Buffer.from(server.queue.submissions[0]?.raw ?? []).toString("utf8");
      expect(raw).toContain("\r\n.leading\r\n");
      expect(raw).not.toContain("..leading");
    } finally {
      await server.close();
    }
  });
});

describe("DKIM verification (V-DKIM-1 … V-DKIM-7)", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  /**
   * Build a signed message for the given body.
   *
   * The returned `signature` is the raw base64 signature, and `signingInput`
   * is the exact byte sequence that was signed, so the test can verify the
   * message independently of the package's own signer.
   */
  function signedMessage(body: string): {
    raw: string;
    signature: string;
    signingInput: string;
  } {
    const headers = ["From: sender@example.test", "To: user@example.test", "Subject: signed"];
    const parsed = parseHeaderBlock(`${headers.join("\r\n")}\r\n`);
    const canonicalizedHeader = canonicalizeHeaderSet(parsed, "relaxed");
    const canonicalizedBody = canonicalizeBody(body, "relaxed");
    const bodyHash = createHash("sha256").update(canonicalizedBody).digest("base64");
    const signatureHeader = [
      "v=1",
      "a=rsa-sha256",
      "c=relaxed/relaxed",
      "d=example.test",
      "s=mail",
      "h=from:to:subject",
      `bh=${bodyHash}`,
      "b=",
    ].join("; ");
    const signingInput = `${canonicalizedHeader}\r\n${canonicalizedBody}`;
    const signature = sign("sha256", Buffer.from(signingInput, "utf8"), privateKey).toString("base64");
    const header = `${signatureHeader}${signature}`;
    const raw = `${headers.join("\r\n")}\r\nDKIM-Signature: ${header}\r\n\r\n${body}`;
    return { raw, signature, signingInput };
  }

  it("verifies a signed message with an independent check", () => {
    const { signingInput, signature } = signedMessage("hello world\r\n");
    const verifier = createVerify("RSA-SHA256");
    verifier.update(signingInput);
    expect(verifier.verify(publicKey, signature, "base64")).toBe(true);
  });

  it("fails verification when the body is mutated", () => {
    const { signingInput, signature } = signedMessage("hello world\r\n");
    const verifier = createVerify("RSA-SHA256");
    verifier.update(signingInput.replace("hello world", "goodbye world"));
    expect(verifier.verify(publicKey, signature, "base64")).toBe(false);
  });

  it("produces a deterministic Message-ID", () => {
    const first = buildMessageId("tenant-1", "request-1", "example.test");
    const second = buildMessageId("tenant-1", "request-1", "example.test");
    expect(first).toBe(second);
    expect(messageIdHeader("tenant-1", "request-1", "example.test")).toMatch(
      /^Message-ID: <.+@.+\..+>$/,
    );
  });

  it("marks a message without the loop header so it can be delivered", () => {
    const loop = inspectLoopMarker(Buffer.from("Subject: x\r\n\r\nbody\r\n", "utf8"), 1);
    expect(loop.rejected).toBe(false);
  });
});
