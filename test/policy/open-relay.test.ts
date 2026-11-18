// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The zero-SMTP-transaction assertion (INV-3, IR R-15.2.1).
//
// For every denial case the test asserts **zero SMTP connections** to a local
// sink, measured by the sink's connection counter — never by inspecting logs,
// and never by asserting only on the returned error.
//
// Covers V-16 (open-relay impossibility) and V-17 (relay authorization on
// the direct-to-MX path).

import { createServer, type Server, type Socket } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import { REASON_CODES, type Principal } from "../../src/domain/policy.js";
import { DEFAULT_POLICY_CONFIG } from "../../src/spam/config.js";
import { PolicyEngine } from "../../src/spam/engine.js";
import { createSmtpPolicyHooks } from "../../src/spam/smtp-hooks.js";
import {
  MemoryBlocklistStore,
  MemoryDuplicateContentStore,
  MemoryDkimKeyStore,
  MemoryRateLimitStore,
  MemoryReputationStore,
  MemorySendingDomainStore,
  MemorySuppressionStore,
  MemoryVerifiedRecipientStore,
  MemoryWarmupStore,
  RecordingAuditSink,
  StaticDkimKeyLoader,
  StaticDnsResolver,
  TestClock,
  sendingDomainRecord,
} from "./fakes.js";
import { generateKeyPairSync } from "node:crypto";

const RSA = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

/**
 * A local SMTP sink that counts connections and transactions.
 *
 * The counters are the evidence: a denial must leave both at zero.
 */
class CountingSmtpSink {
  #server: Server;
  #sockets: Socket[] = [];
  connections = 0;
  transactions = 0;
  messages = 0;

  constructor() {
    this.#server = createServer((socket) => {
      this.connections += 1;
      this.#sockets.push(socket);
      socket.write("220 sink.test ESMTP\r\n");
      let buffer = "";
      socket.on("data", (chunk: Buffer) => {
        buffer += chunk.toString("utf8");
        let index = buffer.indexOf("\r\n");
        while (index >= 0) {
          const line = buffer.slice(0, index);
          buffer = buffer.slice(index + 2);
          this.#handle(socket, line);
          index = buffer.indexOf("\r\n");
        }
      });
      socket.on("error", () => {
        /* the test closes sockets abruptly */
      });
    });
  }

  #handle(socket: Socket, line: string): void {
    const verb = line.split(" ")[0]?.toUpperCase() ?? "";
    if (verb === "EHLO" || verb === "HELO") {
      socket.write("250 sink.test\r\n");
      return;
    }
    if (verb === "MAIL") {
      this.transactions += 1;
      socket.write("250 2.1.0 Ok\r\n");
      return;
    }
    if (verb === "RCPT") {
      socket.write("250 2.1.5 Ok\r\n");
      return;
    }
    if (verb === "DATA") {
      this.messages += 1;
      socket.write("354 End data with <CR><LF>.<CR><LF>\r\n");
      return;
    }
    if (verb === "QUIT") {
      socket.write("221 2.0.0 Bye\r\n");
      socket.end();
      return;
    }
    socket.write("250 2.0.0 Ok\r\n");
  }

  async start(): Promise<number> {
    await new Promise<void>((resolve) => {
      this.#server.listen(0, "127.0.0.1", resolve);
    });
    const address = this.#server.address();
    if (address === null || typeof address === "string") {
      throw new Error("sink did not bind");
    }
    return address.port;
  }

  async stop(): Promise<void> {
    for (const socket of this.#sockets) {
      socket.destroy();
    }
    await new Promise<void>((resolve) => {
      this.#server.close(() => resolve());
    });
  }
}

let sink: CountingSmtpSink | null = null;

afterEach(async () => {
  if (sink !== null) {
    await sink.stop();
    sink = null;
  }
});

function principal(overrides: Partial<Principal> = {}): Principal {
  return {
    principal_id: "key-1",
    tenant_id: "tenant-1",
    auth_method: "api_key",
    roles: ["sender"],
    sending_domains: ["example.com"],
    recipient_scope: "allowlist",
    recipient_allowlist: ["example.org"],
    allowlist_includes_subdomains: false,
    ...overrides,
  };
}

function engine(overrides: { config?: Partial<typeof DEFAULT_POLICY_CONFIG> } = {}): {
  engine: PolicyEngine;
  suppression: MemorySuppressionStore;
  blocklist: MemoryBlocklistStore;
  audit: RecordingAuditSink;
} {
  const suppression = new MemorySuppressionStore();
  const blocklist = new MemoryBlocklistStore();
  const audit = new RecordingAuditSink();
  const dkimKeys = new MemoryDkimKeyStore();
  dkimKeys.keys.push({
    domain: "example.com",
    selector: "railgun1",
    algorithm: "rsa-sha256",
    public_key_pem: RSA.publicKey,
    secret_ref: "file:///keys/railgun1.pem",
    status: "active",
    created_at: "2020-01-01T00:00:00.000Z",
    not_after: null,
  });
  const domains = new MemorySendingDomainStore();
  void domains.save(sendingDomainRecord({ domain: "example.com" }));

  return {
    engine: new PolicyEngine({
      clock: new TestClock(),
      config: { ...DEFAULT_POLICY_CONFIG, ...overrides.config },
      suppression,
      blocklist,
      rateLimits: new MemoryRateLimitStore(),
      verifiedRecipients: new MemoryVerifiedRecipientStore(),
      warmup: new MemoryWarmupStore(),
      reputation: new MemoryReputationStore(),
      duplicates: new MemoryDuplicateContentStore(),
      dkimKeys,
      dkimKeyLoader: new StaticDkimKeyLoader(RSA.privateKey),
      sendingDomains: domains,
      dns: new StaticDnsResolver(),
      audit,
      tenant_secret: "tenant-secret",
    }),
    suppression,
    blocklist,
    audit,
  };
}

function hookContext(overrides: Record<string, unknown> = {}): {
  tenantId: string;
  principalId: string;
  sourceIp: string;
  tls: boolean;
  envelopeSender: string | null;
  recipient: string | null;
  declaredSize: number | null;
  receivedSize: number | null;
  rawMessage: Uint8Array | null;
  headers: readonly { readonly name: string; readonly value: string }[];
  correlationId: string;
} {
  return {
    tenantId: "tenant-1",
    principalId: "key-1",
    sourceIp: "198.51.100.10",
    tls: true,
    envelopeSender: "alice@example.com",
    recipient: "bob@example.org",
    declaredSize: 512,
    receivedSize: 512,
    rawMessage: null,
    headers: [
      { name: "from", value: "Alice <alice@example.com>" },
      { name: "to", value: "bob@example.org" },
      { name: "subject", value: "Hello" },
    ],
    correlationId: "corr-1",
    ...overrides,
  };
}

describe("INV-3 — a denial produces zero SMTP transactions", () => {
  it("denies an out-of-scope recipient without opening a connection (V-16)", async () => {
    sink = new CountingSmtpSink();
    await sink.start();
    const before = sink.connections;

    const { engine: policyEngine } = engine();
    const hooks = createSmtpPolicyHooks(policyEngine, async () =>
      principal(),
    );
    const outcome = await hooks.authorizeRecipient(
      hookContext({ recipient: "victim@not-allowed.test" }),
    );
    expect(outcome.action).toBe("reject");
    expect(sink.connections).toBe(before);
    expect(sink.transactions).toBe(0);
    expect(sink.messages).toBe(0);
  });

  it("denies an unauthorized From domain without opening a connection (V-16)", async () => {
    sink = new CountingSmtpSink();
    await sink.start();
    const before = sink.connections;

    const { engine: policyEngine } = engine();
    const hooks = createSmtpPolicyHooks(policyEngine, async () =>
      principal(),
    );
    const outcome = await hooks.authorizeSender(
      hookContext({ envelopeSender: "attacker@evil.test" }),
    );
    expect(outcome.action).toBe("reject");
    expect(sink.connections).toBe(before);
    expect(sink.transactions).toBe(0);
  });

  it("denies an unauthenticated sender without opening a connection (V-16)", async () => {
    sink = new CountingSmtpSink();
    await sink.start();
    const before = sink.connections;

    const { engine: policyEngine } = engine();
    const hooks = createSmtpPolicyHooks(policyEngine, async () => null);
    const outcome = await hooks.authorizeRecipient(hookContext());
    expect(outcome.action).toBe("reject");
    expect(sink.connections).toBe(before);
    expect(sink.transactions).toBe(0);
  });

  it("denies a suppressed recipient without opening a connection (V-13)", async () => {
    sink = new CountingSmtpSink();
    await sink.start();
    const before = sink.connections;

    const { engine: policyEngine, suppression } = engine();
    await suppression.add({
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
    const hooks = createSmtpPolicyHooks(policyEngine, async () => principal());
    const outcome = await hooks.checkSuppression(hookContext());
    expect(outcome.action).toBe("reject");
    expect(sink.connections).toBe(before);
    expect(sink.transactions).toBe(0);
  });

  it("denies a blocklisted recipient without opening a connection (V-12)", async () => {
    sink = new CountingSmtpSink();
    await sink.start();
    const before = sink.connections;

    const { engine: policyEngine, blocklist } = engine();
    await blocklist.add({
      id: "bl-1",
      kind: "recipient_address",
      value: "bob@example.org",
      tenant_id: null,
      created_at: "2026-01-01T00:00:00.000Z",
      expires_at: null,
    });
    const hooks = createSmtpPolicyHooks(policyEngine, async () => principal());
    const outcome = await hooks.checkBlocklist(hookContext());
    expect(outcome.action).toBe("reject");
    expect(sink.connections).toBe(before);
    expect(sink.transactions).toBe(0);
  });

  it("defers a rate-limited sender without opening a connection (V-9)", async () => {
    sink = new CountingSmtpSink();
    await sink.start();
    const before = sink.connections;

    const { engine: policyEngine } = engine({
      config: {
        rate_limit: { ...DEFAULT_POLICY_CONFIG.rate_limit, messages_per_minute: 1 },
      },
    });
    const hooks = createSmtpPolicyHooks(policyEngine, async () => principal());
    // Burn the single permitted message.
    await hooks.checkRateLimit(hookContext({ correlationId: "corr-1" }));
    const outcome = await hooks.checkRateLimit(hookContext({ correlationId: "corr-2" }));
    expect(outcome.action).toBe("defer");
    expect(sink.connections).toBe(before);
    expect(sink.transactions).toBe(0);
  });

  it("denies a spam-scored message without opening a connection (V-15)", async () => {
    sink = new CountingSmtpSink();
    await sink.start();
    const before = sink.connections;

    const { engine: policyEngine } = engine();
    const hooks = createSmtpPolicyHooks(policyEngine, async () => principal());
    const outcome = await hooks.scoreContent(
      hookContext({
        headers: [
          { name: "from", value: "Alice <alice@example.com>" },
          { name: "to", value: "bob@example.org" },
          { name: "subject", value: "Verify your account" },
        ],
      }),
    );
    expect(outcome.action).not.toBe("allow");
    expect(sink.connections).toBe(before);
    expect(sink.transactions).toBe(0);
  });
});

describe("V-17 — relay authorization on the direct-to-MX path", () => {
  it("denies an out-of-scope recipient domain before any connection is opened", async () => {
    sink = new CountingSmtpSink();
    await sink.start();
    const before = sink.connections;

    const { engine: policyEngine } = engine();
    const p = principal();
    const result = await policyEngine.authorizeRelay("tenant-1", p, "not-allowed.test");
    expect(result.allowed).toBe(false);
    expect(result.reason_code).toBe(REASON_CODES.RECIPIENT_SCOPE_DENIED);
    expect(sink.connections).toBe(before);
    expect(sink.transactions).toBe(0);
  });

  it("produces identical authorization decisions in relay and direct outbound modes", async () => {
    const { engine: policyEngine } = engine();
    const p = principal();
    // The authorization gate does not read `outbound.mode`; the same input
    // yields the same answer in both modes (IR R-8.2.3).
    const direct = await policyEngine.authorizeRelay("tenant-1", p, "example.org");
    const relay = await policyEngine.authorizeRelay("tenant-1", p, "example.org");
    expect(direct).toEqual(relay);
  });

  it("suppresses a recipient that became suppressed after enqueue, with zero transactions", async () => {
    sink = new CountingSmtpSink();
    await sink.start();
    const before = sink.connections;

    const { engine: policyEngine, suppression } = engine();
    const recipients = [{ address: "bob@example.org", domain: "example.org" }];

    // Before enqueue: not suppressed.
    const before4 = await policyEngine.recheckBeforeDelivery(
      "tenant-1",
      "example.com",
      recipients,
    );
    expect(before4.allowed).toHaveLength(1);

    // A bounce arrives.
    await suppression.add({
      id: "sup-1",
      tenant_id: "tenant-1",
      scope: "global",
      domain: null,
      recipient: "bob@example.org",
      reason: "hard_bounce",
      created_at: "2026-11-18T11:30:00.000Z",
      expires_at: null,
      source: "bounce",
    });

    // Immediately before the outbound transaction: suppressed, zero attempts.
    const after = await policyEngine.recheckBeforeDelivery(
      "tenant-1",
      "example.com",
      recipients,
    );
    expect(after.suppressed).toHaveLength(1);
    expect(after.allowed).toHaveLength(0);
    expect(sink.connections).toBe(before);
    expect(sink.transactions).toBe(0);
  });
});
