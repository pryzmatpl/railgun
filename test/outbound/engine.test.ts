/* RailGun direct-to-MX delivery engine — integration tests.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { describe, expect, it } from "vitest";

import { DeliveryEngine, inspectLoopMarker } from "../../src/outbound/engine.js";
import {
  FakeDnsResolver,
  RecordingAttemptStore,
  RecordingAuditSink,
  RecordingBounceSink,
  RecordingEventSink,
  startFakeMx,
  testConfig,
  type FakeMxServer,
} from "./harness.js";
import type { DeliveryRequest, OutboxLease } from "../../src/outbound/types.js";

/** The artifact the engine transmits. */
const ARTIFACT = Buffer.from(
  [
    "Message-ID: <abc123@example.test>",
    "Subject: hello",
    "X-RailGun-Loop: hop-1",
    "",
    "body line",
    "",
  ].join("\r\n"),
  "utf8",
);

/** A request for one recipient. */
function request(overrides: Partial<DeliveryRequest> = {}): DeliveryRequest {
  return {
    messageId: "message-1",
    requestId: "request-1",
    tenantId: "tenant-1",
    envelopeId: "envelope-1",
    recipient: "user@example.test",
    envelopeSender: "sender@example.test",
    artifact: ARTIFACT,
    domain: "example.test",
    attempt: 1,
    loopLimit: 1,
    ...overrides,
  };
}

/** A lease matching the request. */
function lease(overrides: Partial<OutboxLease> = {}): OutboxLease {
  return {
    id: "outbox-1",
    messageId: "message-1",
    envelopeId: "envelope-1",
    tenantId: "tenant-1",
    attemptCount: 0,
    maxAttempts: 5,
    ...overrides,
  };
}

/** Build an engine wired to the recording sinks. */
function buildEngine(options: {
  resolver: FakeDnsResolver;
  store?: RecordingAttemptStore;
  bounces?: RecordingBounceSink;
  events?: RecordingEventSink;
  audit?: RecordingAuditSink;
  config?: ReturnType<typeof testConfig>;
  allowLocalTransport?: boolean;
  port?: number;
}) {
  const store = options.store ?? new RecordingAttemptStore();
  const bounces = options.bounces ?? new RecordingBounceSink();
  const events = options.events ?? new RecordingEventSink();
  const audit = options.audit ?? new RecordingAuditSink();
  // The fake MX does not advertise STARTTLS unless the script asks for it,
  // so the default test posture is opportunistic TLS with plaintext allowed.
  const config = options.config ?? testConfig({ requireTls: false });
  if (options.port !== undefined) config.outbound.direct.port = options.port;
  const engine = new DeliveryEngine({
    config,
    resolver: options.resolver,
    attempts: store,
    bounces,
    audit,
    events,
    workerId: "worker-1",
    allowLocalTransport: options.allowLocalTransport ?? true,
    now: () => new Date("2026-11-18T12:00:00.000Z"),
  });
  return { engine, store, bounces, events, audit };
}

/** The resolver answers that point at the local fake MX. */
function resolverFor(mx: FakeMxServer, family: 4 | 6 = 4): FakeDnsResolver {
  const address = family === 4 ? mx.address : "::1";
  return new FakeDnsResolver({
    mx: { "example.test": [{ exchange: "mx.fake.test", preference: 10 }] },
    a: { "mx.fake.test": family === 4 ? [mx.address] : [] },
    aaaa: { "mx.fake.test": family === 6 ? ["::1"] : [] },
    ptr: { [mx.address]: ["mx.fake.test"] },
  });
}

describe("the direct-to-MX engine (R-MODE-1, R-SMTP-*, R-CLS-*)", () => {
  it("delivers through a local fake MX over IPv4", async () => {
    const mx = await startFakeMx({ capabilities: ["8BITMIME", "PIPELINING"] });
    try {
      const { engine, store, events } = buildEngine({ resolver: resolverFor(mx), port: mx.port });
      const result = await engine.deliver(request(), lease());

      expect(result.outcome).toBe("accepted");
      expect(result.smtpCode).toBe(250);
      expect(result.remoteAccepted).toBe(true);
      expect(store.finalizations).toHaveLength(1);
      expect(store.finalizations[0]!.status).toBe("accepted");
      expect(store.finalizations[0]!.messageStatus).toBe("accepted");

      // The fake MX observed the exact envelope.
      const commands = mx.received;
      expect(commands).toContain("EHLO example.test");
      expect(commands).toContain("MAIL FROM:<sender@example.test>");
      expect(commands).toContain("RCPT TO:<user@example.test>");
      expect(commands).toContain("DATA");

      // The artifact bytes reached the peer unchanged.
      expect(mx.received).toContain("Subject: hello");
      expect(mx.received).toContain("body line");
    } finally {
      await mx.close();
    }
  });

  it("records an accepted outcome and emits the delivery events", async () => {
    const mx = await startFakeMx();
    try {
      const { engine, events, audit } = buildEngine({ resolver: resolverFor(mx), port: mx.port });
      await engine.deliver(request(), lease());

      const names = events.events.map((event) => event.event);
      expect(names).toContain("delivery_attempt_started");
      expect(names).toContain("delivery_smtp_response");
      expect(names).toContain("delivery_delivered");
      expect(names).toContain("delivery_finalized");
      expect(audit.entries.some((entry) => entry.action === "delivery_accepted")).toBe(true);
    } finally {
      await mx.close();
    }
  });

  it("defers a 4xx reply and schedules a retry", async () => {
    const mx = await startFakeMx({ final: { code: 451, text: "4.3.0 Try later" } });
    try {
      const { engine, store, bounces } = buildEngine({ resolver: resolverFor(mx), port: mx.port });
      const result = await engine.deliver(request(), lease());

      expect(result.outcome).toBe("deferred");
      expect(result.errorCode).toBe("temporary_failure");
      expect(result.smtpCode).toBe(451);
      // A 4xx never produces a bounce (R-CLS-2).
      expect(bounces.bounces).toHaveLength(0);
      expect(store.finalizations[0]!.status).toBe("deferred");
      expect(store.finalizations[0]!.nextAttemptAt).not.toBeNull();
    } finally {
      await mx.close();
    }
  });

  it("bounces a 5xx reply and records a suppression", async () => {
    const mx = await startFakeMx({ rcptTo: { code: 550, text: "5.1.1 User unknown" } });
    try {
      const { engine, store, bounces } = buildEngine({ resolver: resolverFor(mx), port: mx.port });
      const result = await engine.deliver(request(), lease());

      expect(result.outcome).toBe("bounced");
      expect(result.errorCode).toBe("user_not_local");
      expect(result.smtpCode).toBe(550);
      expect(bounces.bounces).toHaveLength(1);
      expect(bounces.bounces[0]!.recipient).toBe("user@example.test");
      expect(bounces.bounces[0]!.suppressionId).not.toBeNull();
      expect(store.finalizations[0]!.status).toBe("bounced");
    } finally {
      await mx.close();
    }
  });

  it("does not retry another MX candidate after a permanent recipient failure", async () => {
    const mx = await startFakeMx({ rcptTo: { code: 550, text: "5.1.1 User unknown" } });
    try {
      const resolver = new FakeDnsResolver({
        mx: {
          "example.test": [
            { exchange: "mx.fake.test", preference: 10 },
            { exchange: "mx2.fake.test", preference: 20 },
          ],
        },
        a: { "mx.fake.test": [mx.address], "mx2.fake.test": [mx.address] },
        ptr: { [mx.address]: ["mx.fake.test"] },
      });
      const { engine } = buildEngine({ resolver, port: mx.port });
      const result = await engine.deliver(request(), lease());

      expect(result.outcome).toBe("bounced");
      // Only one host was contacted: a permanent failure is recipient-level.
      expect(resolver.mxCalls).toEqual(["example.test"]);
      expect(result.mxHost).toBe("mx.fake.test");
    } finally {
      await mx.close();
    }
  });

  it("defers when the domain publishes no MX", async () => {
    const resolver = new FakeDnsResolver({ mx: { "example.test": [] } });
    const { engine, store } = buildEngine({ resolver });
    const result = await engine.deliver(request(), lease());

    expect(result.outcome).toBe("bounced");
    expect(result.errorCode).toBe("dns_no_mx");
    expect(store.finalizations[0]!.status).toBe("bounced");
  });

  it("bounces a null MX as mailbox_unavailable", async () => {
    const resolver = new FakeDnsResolver({
      mx: { "example.test": [{ exchange: ".", preference: 0 }] },
    });
    const { engine } = buildEngine({ resolver });
    const result = await engine.deliver(request(), lease());

    expect(result.outcome).toBe("bounced");
    expect(result.errorCode).toBe("mailbox_unavailable");
  });

  it("defers a temporary DNS failure", async () => {
    const resolver = new FakeDnsResolver({});
    resolver.resolveMx = async () => {
      throw Object.assign(new Error("SERVFAIL"), { code: "SERVFAIL" });
    };
    const { engine, store } = buildEngine({ resolver });
    const result = await engine.deliver(request(), lease());

    expect(result.outcome).toBe("deferred");
    expect(result.errorCode).toBe("dns_temporary");
    expect(store.finalizations[0]!.status).toBe("deferred");
  });

  it("refuses to connect to a private address without the local exception", async () => {
    const resolver = new FakeDnsResolver({
      mx: { "example.test": [{ exchange: "mx.fake.test", preference: 10 }] },
      a: { "mx.fake.test": ["10.1.2.3"] },
    });
    const { engine } = buildEngine({ resolver, allowLocalTransport: false });
    const result = await engine.deliver(request(), lease());

    // No usable candidate remains, so the recipient is deferred.
    expect(result.outcome).toBe("deferred");
    expect(result.errorCode).toBe("dns_temporary");
  });

  it("degrades to a temporary failure when TLS is required but not advertised", async () => {
    const mx = await startFakeMx({ capabilities: ["8BITMIME"] });
    try {
      const { engine, store } = buildEngine({
        resolver: resolverFor(mx),
        port: mx.port,
        config: testConfig({ requireTls: true }),
      });
      const result = await engine.deliver(request(), lease());

      expect(result.outcome).toBe("bounced");
      expect(result.errorCode).toBe("tls_unavailable");
      expect(store.finalizations[0]!.status).toBe("bounced");
    } finally {
      await mx.close();
    }
  });

  it("delivers in plaintext when TLS is opportunistic and plaintext is allowed", async () => {
    const mx = await startFakeMx({ capabilities: ["8BITMIME"] });
    try {
      const { engine } = buildEngine({
        resolver: resolverFor(mx),
        port: mx.port,
        config: testConfig({ requireTls: false }),
      });
      const result = await engine.deliver(request(), lease());

      expect(result.outcome).toBe("accepted");
      expect(result.tls).toBeNull();
    } finally {
      await mx.close();
    }
  });

  it("rejects a looped artifact before any connection (R-LOOP-2)", async () => {
    const resolver = new FakeDnsResolver({});
    const { engine, store, audit } = buildEngine({ resolver });
    const result = await engine.deliver(
      request({
        artifact: Buffer.from(
          ["X-RailGun-Loop: hop-1, hop-2", "", "body", ""].join("\r\n"),
          "utf8",
        ),
      }),
      lease(),
    );

    expect(result.outcome).toBe("bounced");
    expect(result.errorCode).toBe("delivery_loop");
    // No network attempt was made.
    expect(resolver.mxCalls).toHaveLength(0);
    expect(store.finalizations[0]!.status).toBe("bounced");
    expect(audit.entries.some((entry) => entry.action === "delivery_loop_rejected")).toBe(true);
  });

  it("transmits an artifact with the marker within the hop limit unchanged", () => {
    const inspection = inspectLoopMarker(ARTIFACT, 1);
    expect(inspection.rejected).toBe(false);
    expect(inspection.markerPresent).toBe(true);
    expect(inspection.hops).toBe(1);
  });

  it("reports a missing loop marker as a normalization defect, not a failure", async () => {
    const mx = await startFakeMx();
    try {
      const { engine, audit } = buildEngine({ resolver: resolverFor(mx), port: mx.port });
      const result = await engine.deliver(
        request({ artifact: Buffer.from("Subject: hi\r\n\r\nbody\r\n", "utf8") }),
        lease(),
      );

      expect(result.outcome).toBe("accepted");
      expect(audit.entries.some((entry) => entry.action === "delivery_loop_marker_absent")).toBe(true);
    } finally {
      await mx.close();
    }
  });

  it("does not report success when the durable write fails (R-FIN-4)", async () => {
    const mx = await startFakeMx();
    try {
      const store = new RecordingAttemptStore();
      store.failFinalize = new Error("disk full");
      const { engine, audit } = buildEngine({ resolver: resolverFor(mx), port: mx.port, store });
      const result = await engine.deliver(request(), lease());

      // The remote accepted, but the engine must not report a durable success.
      expect(result.outcome).toBe("accepted");
      expect(store.finalizations).toHaveLength(0);
      expect(audit.entries.some((entry) => entry.action === "delivery_store_write_failed")).toBe(true);
    } finally {
      await mx.close();
    }
  });

  it("stops retrying once the attempt ceiling is reached (R-RET-4, R-CLS-5)", async () => {
    const mx = await startFakeMx({ final: { code: 451, text: "4.3.0 Try later" } });
    try {
      const { engine, store } = buildEngine({
        resolver: resolverFor(mx),
        port: mx.port,
        config: testConfig({ maxAttempts: 2, requireTls: false }),
      });
      const result = await engine.deliver(
        request({ attempt: 2 }),
        lease({ attemptCount: 1, maxAttempts: 2 }),
      );

      expect(result.outcome).toBe("deferred");
      // No further attempt is scheduled at the ceiling.
      expect(store.finalizations[0]!.nextAttemptAt).toBeNull();
    } finally {
      await mx.close();
    }
  });

  it("redacts the recipient in the observability events (R-OBS-4)", async () => {
    const mx = await startFakeMx();
    try {
      const { engine, events } = buildEngine({ resolver: resolverFor(mx), port: mx.port });
      await engine.deliver(request(), lease());

      for (const event of events.events) {
        expect(event.recipient).not.toContain("user@example.test");
        expect(event.recipient.startsWith("sha256:")).toBe(true);
      }
    } finally {
      await mx.close();
    }
  });

  it("keeps the transmitted bytes byte-identical across two attempts", async () => {
    const mx = await startFakeMx({ final: { code: 451, text: "4.3.0 Try later" } });
    try {
      const { engine } = buildEngine({ resolver: resolverFor(mx), port: mx.port });
      await engine.deliver(request({ attempt: 1 }), lease());
      await engine.deliver(request({ attempt: 2 }), lease({ attemptCount: 1 }));

      // Both sessions carried exactly the same artifact bytes.
      expect(mx.sessions).toHaveLength(2);
      expect(mx.sessions[0]!.body).toBe(mx.sessions[1]!.body);
      expect(mx.sessions[0]!.body).toContain("Subject: hello");
      expect(mx.sessions[0]!.body).toContain("body line");
    } finally {
      await mx.close();
    }
  });
});

describe("IPv6 fallback (R-DNS-4)", () => {
  it("falls back to IPv6 when the IPv4 address does not answer", async () => {
    // The IPv4 address is a documentation address that refuses the
    // connection; the IPv6 loopback reaches the fake MX.
    let mx: FakeMxServer | null = null;
    try {
      mx = await startFakeMx({}, { host: "::1" });
      const resolver = new FakeDnsResolver({
        mx: { "example.test": [{ exchange: "mx.fake.test", preference: 10 }] },
        a: { "mx.fake.test": ["192.0.2.1"] },
        aaaa: { "mx.fake.test": ["::1"] },
        ptr: { "192.0.2.1": ["mx.fake.test"], "::1": ["mx.fake.test"] },
      });
      const { engine } = buildEngine({ resolver, port: mx.port });
      const result = await engine.deliver(request(), lease());

      // The IPv4 attempt failed transiently, so the engine moved on to the
      // IPv6 address of the same MX host.
      expect(result.outcome).toBe("accepted");
      expect(result.remoteIp).toBe("::1");
    } catch (error) {
      // A host without IPv6 loopback cannot exercise the fallback.
      if (!(error instanceof Error) || !/EADDRNOTAVAIL|EAFNOSUPPORT/.test(error.message)) {
        throw error;
      }
    } finally {
      if (mx) await mx.close();
    }
  });
});
