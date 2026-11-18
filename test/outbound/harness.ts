/* RailGun direct-to-MX delivery engine — test harness.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import net from "node:net";
import tls from "node:tls";

import { defaultConfig, type RailgunConfig } from "../../src/config/config.js";
import type {
  AuditSink,
  BounceSink,
  DeliveryAttemptStore,
  DeliveryEvent,
  DnsResolver,
  EventSink,
  MxRecord,
  OutboxLease,
} from "../../src/outbound/types.js";
import type { BounceRecord } from "../../src/domain/persistence/types.js";

/* -------------------------------------------------------------------------- */
/* A fake DNS resolver                                                         */
/* -------------------------------------------------------------------------- */

/** The answers a fake resolver holds. */
export interface FakeDnsAnswers {
  readonly mx?: Record<string, readonly MxRecord[]>;
  readonly a?: Record<string, readonly string[]>;
  readonly aaaa?: Record<string, readonly string[]>;
  readonly ptr?: Record<string, readonly string[]>;
}

/**
 * A deterministic resolver, so the engine can be driven without touching the
 * public internet (R-DNS-9).
 */
export class FakeDnsResolver implements DnsResolver {
  readonly mxCalls: string[] = [];
  readonly addressCalls: string[] = [];

  constructor(private readonly answers: FakeDnsAnswers = {}) {}

  async resolveMx(domain: string): Promise<readonly MxRecord[]> {
    this.mxCalls.push(domain);
    return this.answers.mx?.[domain.toLowerCase()] ?? [];
  }

  async resolve4(host: string): Promise<readonly string[]> {
    this.addressCalls.push(host);
    return this.answers.a?.[host.toLowerCase()] ?? [];
  }

  async resolve6(host: string): Promise<readonly string[]> {
    this.addressCalls.push(host);
    return this.answers.aaaa?.[host.toLowerCase()] ?? [];
  }

  async resolvePtr(address: string): Promise<readonly string[]> {
    return this.answers.ptr?.[address] ?? [];
  }
}

/* -------------------------------------------------------------------------- */
/* A fake MX server                                                            */
/* -------------------------------------------------------------------------- */

/** The reply script one fake-MX session follows. */
export interface FakeMxScript {
  /** The EHLO capabilities to advertise. */
  readonly capabilities?: readonly string[];
  /** The reply to `MAIL FROM`. */
  readonly mailFrom?: { code: number; text: string };
  /** The reply to `RCPT TO`. */
  readonly rcptTo?: { code: number; text: string };
  /** The reply to `DATA`. */
  readonly data?: { code: number; text: string };
  /** The final reply after the body. */
  readonly final?: { code: number; text: string };
  /** The reply to `STARTTLS`; when absent, STARTTLS is not advertised. */
  readonly starttls?: { code: number; text: string };
  /** Serve TLS on the accepted socket. */
  readonly serveTls?: boolean;
  /** The TLS server options used when `serveTls` is set. */
  readonly tlsOptions?: tls.TlsOptions;
}

/** One observed fake-MX session. */
export interface FakeMxSession {
  readonly commands: string[];
  /** The exact bytes received in the DATA phase. */
  readonly body: string;
  readonly remoteAddress: string | null;
}

/** The fake MX handle. */
export interface FakeMxServer {
  readonly host: string;
  readonly port: number;
  readonly address: string;
  readonly sessions: readonly FakeMxSession[];
  /** The bytes received across every session, concatenated. */
  readonly received: string;
  close(): Promise<void>;
}

/**
 * Start a fake MX server.
 *
 * The server speaks just enough SMTP to drive the engine: a greeting, an
 * EHLO reply with the requested capabilities, and the configured replies for
 * the envelope commands.
 */
export async function startFakeMx(
  script: FakeMxScript = {},
  options: { host?: string } = {},
): Promise<FakeMxServer> {
  const host = options.host ?? "127.0.0.1";
  const sessions: FakeMxSession[] = [];
  const chunks: string[] = [];

  const server = net.createServer((socket) => {
    const commands: string[] = [];
    let body = "";
    let inData = false;
    let pending = "";

    const send = (code: number, text: string): void => {
      socket.write(`${code} ${text}\r\n`);
    };

    let recorded = false;
    const recordSession = (): void => {
      if (recorded) return;
      recorded = true;
      sessions.push({ commands: [...commands], body, remoteAddress: socket.remoteAddress ?? null });
    };

    const handleLine = (line: string): boolean => {
      if (inData) {
        if (line === ".") {
          inData = false;
          const final = script.final ?? { code: 250, text: "2.0.0 Accepted" };
          send(final.code, final.text);
          recordSession();
          return false;
        }
        body += `${line.startsWith("..") ? line.slice(1) : line}\r\n`;
        return false;
      }

      commands.push(line);
      const verb = line.slice(0, 4).toUpperCase();

      if (verb === "EHLO") {
        const capabilities = script.capabilities ?? [];
        const entries = ["fake.mx.test greets you", ...capabilities.map((c) => ` ${c}`)];
        socket.write(
          entries
            .map((entry, index) => {
              const isLast = index === entries.length - 1;
              return `250${isLast ? " " : "-"}${entry}`;
            })
            .join("\r\n") + "\r\n",
        );
        return false;
      }
      if (verb === "HELO") {
        send(250, "fake.mx.test");
        return false;
      }
      if (verb === "STARTTLS") {
        const reply = script.starttls ?? { code: 220, text: "2.0.0 Ready to start TLS" };
        send(reply.code, reply.text);
        return false;
      }
      if (verb === "MAIL") {
        const mail = script.mailFrom ?? { code: 250, text: "2.1.0 Sender ok" };
        send(mail.code, mail.text);
        return false;
      }
      if (verb === "RCPT") {
        const rcpt = script.rcptTo ?? { code: 250, text: "2.1.5 Recipient ok" };
        send(rcpt.code, rcpt.text);
        return false;
      }
      if (verb === "DATA") {
        const data = script.data ?? { code: 354, text: "End data with <CRLF>.<CRLF>" };
        send(data.code, data.text);
        if (data.code === 354) inData = true;
        return false;
      }
      if (verb === "QUIT") {
        send(221, "2.0.0 Bye");
        socket.end();
        return true;
      }
      if (verb === "NOOP") {
        send(250, "2.0.0 Ok");
        return false;
      }
      send(502, "Command not implemented");
      return false;
    };

    socket.write("220 fake.mx.test ESMTP ready\r\n");

    socket.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      chunks.push(text);
      pending += text;
      let index = pending.indexOf("\r\n");
      while (index !== -1) {
        const line = pending.slice(0, index);
        pending = pending.slice(index + 2);
        if (handleLine(line)) return;
        index = pending.indexOf("\r\n");
      }
    });

    socket.on("error", () => undefined);
    socket.on("close", () => recordSession());
  });

  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("The fake MX server did not bind a TCP port");
  }

  return {
    host: "mx.fake.test",
    port: address.port,
    address: host,
    get sessions() {
      return sessions;
    },
    get received() {
      return chunks.join("");
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

/* -------------------------------------------------------------------------- */
/* In-memory sinks                                                             */
/* -------------------------------------------------------------------------- */

/** A recording event sink. */
export class RecordingEventSink implements EventSink {
  readonly events: DeliveryEvent[] = [];

  emit(event: DeliveryEvent): void {
    this.events.push(event);
  }
}

/** A recording audit sink. */
export class RecordingAuditSink implements AuditSink {
  readonly entries: {
    action: string;
    subjectId: string;
    outcome: string;
    reasonCode: string | null;
    metadata: Record<string, unknown>;
  }[] = [];

  async append(input: {
    action: string;
    subjectId: string;
    outcome: string;
    reasonCode: string | null;
    metadata: Record<string, unknown>;
  }): Promise<void> {
    this.entries.push({ ...input });
  }
}

/** A recording bounce sink. */
export class RecordingBounceSink implements BounceSink {
  readonly bounces: {
    recipient: string;
    smtpCode: number | null;
    bounceClass: string;
    diagnostic: string | null;
    suppressionId: string | null;
  }[] = [];

  async record(input: {
    tenantId: string;
    messageId: string | null;
    envelopeId: string | null;
    recipient: string;
    smtpCode: number | null;
    dsnCode: string | null;
    dsnClass: string | null;
    bounceClass: "hard" | "soft" | "complaint";
    diagnostic: string | null;
    remoteId: string | null;
  }): Promise<{ bounce: BounceRecord; suppressionId: string | null }> {
    this.bounces.push({
      recipient: input.recipient,
      smtpCode: input.smtpCode,
      bounceClass: input.bounceClass,
      diagnostic: input.diagnostic,
      suppressionId: `sup-${this.bounces.length + 1}`,
    });
    const bounce = {
      id: `bounce-${this.bounces.length}`,
      tenantId: input.tenantId,
      messageId: input.messageId,
      envelopeId: input.envelopeId,
      recipient: input.recipient,
      observedAt: new Date(0).toISOString(),
      smtpCode: input.smtpCode,
      dsnCode: input.dsnCode,
      dsnClass: input.dsnClass,
      bounceClass: input.bounceClass,
      diagnostic: input.diagnostic,
      remoteId: input.remoteId,
      suppressionId: `sup-${this.bounces.length}`,
    } as BounceRecord;
    return { bounce, suppressionId: bounce.suppressionId };
  }
}

/** The recorded finalization calls. */
export interface FinalizationRecord {
  readonly itemId: string;
  readonly envelopeId: string;
  readonly status: string;
  readonly smtpCode: number | null;
  readonly response: string | null;
  readonly errorCode: string | null;
  readonly nextAttemptAt: string | null;
  readonly messageStatus: string;
}

/** A recording attempt store. */
export class RecordingAttemptStore implements DeliveryAttemptStore {
  readonly finalizations: FinalizationRecord[] = [];
  readonly started: string[] = [];
  readonly completed: string[] = [];
  /** When set, `finalize` rejects with this error. */
  failFinalize: Error | null = null;

  constructor(private readonly leases: readonly OutboxLease[] = []) {}

  async claim(): Promise<readonly OutboxLease[]> {
    return this.leases;
  }

  async startAttempt(attempt: { attemptId: string }): Promise<void> {
    this.started.push(attempt.attemptId);
  }

  async completeAttempt(attempt: { attemptId: string }): Promise<void> {
    this.completed.push(attempt.attemptId);
  }

  async envelope(): Promise<null> {
    return null;
  }

  async message(): Promise<null> {
    return null;
  }

  async finalize(input: {
    itemId: string;
    owner: string;
    envelopeId: string;
    status: string;
    smtpCode: number | null;
    response: string | null;
    errorCode: string | null;
    nextAttemptAt: string | null;
    messageStatus: string;
  }): Promise<void> {
    if (this.failFinalize) throw this.failFinalize;
    this.finalizations.push({
      itemId: input.itemId,
      envelopeId: input.envelopeId,
      status: input.status,
      smtpCode: input.smtpCode,
      response: input.response,
      errorCode: input.errorCode,
      nextAttemptAt: input.nextAttemptAt,
      messageStatus: input.messageStatus,
    });
  }
}

/* -------------------------------------------------------------------------- */
/* Configuration helpers                                                       */
/* -------------------------------------------------------------------------- */

/** A configuration with the direct outbound overrides applied. */
export function testConfig(overrides: {
  requireTls?: boolean;
  mxLookup?: boolean;
  ipv4First?: boolean;
  ipv6Fallback?: boolean;
  requireReverseDns?: boolean;
  port?: number;
  maxAttempts?: number;
  sendingDomains?: readonly string[];
} = {}): RailgunConfig {
  const config = defaultConfig();
  config.outbound.mode = "direct";
  config.outbound.direct.port = overrides.port ?? 25;
  config.outbound.direct.mx_lookup = overrides.mxLookup ?? true;
  config.outbound.direct.ipv4_first = overrides.ipv4First ?? true;
  config.outbound.direct.ipv6_fallback = overrides.ipv6Fallback ?? true;
  config.outbound.direct.require_tls = overrides.requireTls ?? true;
  config.outbound.direct.require_reverse_dns = overrides.requireReverseDns ?? false;
  config.outbound.direct.connection_timeout_ms = 2_000;
  config.outbound.direct.command_timeout_ms = 2_000;
  config.queue.max_attempts = overrides.maxAttempts ?? 5;
  config.domains.sending_domains = [...(overrides.sendingDomains ?? ["example.test"])];
  return config;
}
