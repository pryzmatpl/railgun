/* RailGun SMTP submission server — test harness.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import net from "node:net";
import tls from "node:tls";

import { startSmtpServer, type SmtpServerHandle } from "../../src/smtp/server.js";
import type {
  SmtpPrincipal,
  SmtpQueuePort,
  SmtpServerEvent,
  SmtpServerOptions,
  SmtpSubmission,
} from "../../src/smtp/types.js";

/** One complete SMTP reply: every `NNN-` line plus the final `NNN ` line. */
export interface SmtpReply {
  /** The numeric code of the reply. */
  readonly code: number;
  /** The full reply text, including the CRLF terminators. */
  readonly raw: string;
  /** The reply text without the code prefixes and CRLFs. */
  readonly text: string;
}

/**
 * Parse a complete reply from the head of `buffer`.
 *
 * Returns `null` when the buffer does not yet hold a complete reply. A reply
 * is complete when a line with a space after the code has been seen; all
 * preceding continuation lines (`NNN-`) belong to it.
 */
export function takeReply(buffer: string): { reply: SmtpReply; rest: string } | null {
  let offset = 0;
  const lines: string[] = [];
  for (;;) {
    const idx = buffer.indexOf("\r\n", offset);
    if (idx === -1) return null;
    const line = buffer.slice(offset, idx);
    if (!/^\d{3}[ -]/.test(line)) {
      // Not a reply line — the caller is out of sync.
      throw new Error(`Unexpected data in reply stream: ${JSON.stringify(line)}`);
    }
    lines.push(line);
    const isFinal = line[3] === " ";
    offset = idx + 2;
    if (isFinal) break;
  }
  const raw = lines.join("\r\n") + "\r\n";
  const code = Number.parseInt(lines[lines.length - 1]!.slice(0, 3), 10);
  const text = lines
    .map((line) => line.slice(4))
    .join("\n");
  return { reply: { code, raw, text }, rest: buffer.slice(offset) };
}

/**
 * A minimal SMTP client that speaks the submission subset over a socket.
 *
 * Replies are consumed whole, including multi-line replies, so a caller
 * always observes exactly one reply per command.
 */
export class TestSmtpClient {
  private socket: net.Socket;
  private buffer = "";
  private readonly waiters: Array<{
    resolve: (value: SmtpReply) => void;
    reject: (error: Error) => void;
    code: number | null;
  }> = [];

  private constructor(socket: net.Socket) {
    this.socket = socket;
    this.socket.setEncoding("latin1");
    this.socket.on("data", (chunk: string) => {
      this.buffer += chunk;
      this.drain();
    });
  }

  static async connect(port: number, secure = false): Promise<TestSmtpClient> {
    const socket = secure
      ? tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false })
      : net.connect({ host: "127.0.0.1", port });
    await new Promise<void>((resolve, reject) => {
      socket.once(secure ? "secureConnect" : "connect", () => resolve());
      socket.once("error", reject);
    });
    return new TestSmtpClient(socket);
  }

  private drain(): void {
    while (this.waiters.length > 0) {
      const waiter = this.waiters[0]!;
      const taken = takeReply(this.buffer);
      if (!taken) return;
      if (waiter.code !== null && taken.reply.code !== waiter.code) {
        // The reply does not match the expected code. It is consumed and the
        // waiter keeps looking for the right one, so a caller that wants the
        // final `250` of a transaction is not confused by an earlier `250`.
        this.buffer = taken.rest;
        continue;
      }
      this.buffer = taken.rest;
      this.waiters.shift();
      waiter.resolve(taken.reply);
    }
  }

  /** Send raw bytes. */
  sendRaw(data: string): void {
    this.socket.write(data, "latin1");
  }

  /** Send a command line and await the next reply. */
  async command(line: string): Promise<SmtpReply> {
    this.sendRaw(`${line}\r\n`);
    return this.expectReply();
  }

  /** Send a command line and await a reply with the given code. */
  async commandExpecting(line: string, code: number): Promise<SmtpReply> {
    this.sendRaw(`${line}\r\n`);
    return this.expectReply(code);
  }

  /** Await the next reply, optionally filtered by code. */
  expectReply(code: number | null = null, timeoutMs = 5000): Promise<SmtpReply> {
    for (;;) {
      const taken = takeReply(this.buffer);
      if (!taken) break;
      this.buffer = taken.rest;
      if (code === null || taken.reply.code === code) {
        return Promise.resolve(taken.reply);
      }
      // Skip a reply whose code does not match; the caller is waiting for a
      // specific one (e.g. the final `250` of a transaction).
    }
    return new Promise<SmtpReply>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(
          new Error(
            `Timed out waiting for ${code === null ? "any" : code} reply (buffer=${JSON.stringify(this.buffer)})`,
          ),
        );
      }, timeoutMs);
      this.waiters.push({
        code,
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
    });
  }

  /**
   * Upgrade the connection to TLS in place.
   *
   * Used by the `STARTTLS` test: the server replies `220` and then performs
   * the handshake, so the client must upgrade its side at the same point.
   */
  async upgradeToTls(): Promise<void> {
    const plain = this.socket as net.Socket;
    const { port } = plain.localAddress
      ? { port: plain.remotePort ?? 0 }
      : { port: 0 };
    const secure = tls.connect(
      {
        host: "127.0.0.1",
        port,
        rejectUnauthorized: false,
        // The server's `STARTTLS` handshake starts on the existing socket;
        // `tls.connect` over the same TCP connection is not possible, so the
        // socket is wrapped instead.
        socket: plain,
      },
      () => undefined,
    );
    await new Promise<void>((resolve, reject) => {
      secure.once("secureConnect", () => resolve());
      secure.once("error", reject);
    });
    this.socket = secure;
    secure.setEncoding("latin1");
    secure.on("data", (chunk: string) => {
      this.buffer += chunk;
      this.drain();
    });
  }

  /** Read all currently buffered reply text without waiting. */
  peek(): string {
    return this.buffer;
  }

  end(): void {
    this.socket.destroy();
  }
}

export type CapturedSubmission = SmtpSubmission;

/** An in-memory queue port that records what the server handed it. */
export class MemoryQueue implements SmtpQueuePort {
  readonly submissions: CapturedSubmission[] = [];
  failNext = false;
  messageCounter = 0;

  async enqueue(submission: SmtpSubmission): Promise<{ messageId: string }> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error("store unavailable");
    }
    this.submissions.push(submission);
    this.messageCounter += 1;
    return { messageId: `rg-test-${this.messageCounter}` };
  }
}

/** A deterministic authenticator used by the tests. */
export class TestAuthenticator {
  constructor(
    private readonly users: Record<string, { password: string; principal: SmtpPrincipal }>,
  ) {}

  async verify(username: string, password: string): Promise<SmtpPrincipal | null> {
    const entry = this.users[username];
    if (!entry) return null;
    if (entry.password !== password) return null;
    return entry.principal;
  }
}

export interface TestServerOptions {
  readonly options?: Partial<SmtpServerOptions>;
  readonly users?: Record<string, { password: string; principal: SmtpPrincipal }>;
  readonly queue?: MemoryQueue;
  readonly events?: SmtpServerEvent[];
}

export interface RunningTestServer {
  readonly port: number;
  readonly queue: MemoryQueue;
  readonly events: SmtpServerEvent[];
  readonly handle: SmtpServerHandle;
  connect(secure?: boolean): Promise<TestSmtpClient>;
  close(): Promise<void>;
}

/** Start a server on an ephemeral loopback port. */
export async function startTestServer(config: TestServerOptions = {}): Promise<RunningTestServer> {
  const queue = config.queue ?? new MemoryQueue();
  const events = config.events ?? [];

  const handle = await startSmtpServer({
    host: "127.0.0.1",
    port: 0,
    hostname: "railgun.test",
    requireAuth: false,
    ...config.options,
    queue,
    onEvent: (event) => events.push(event),
  } as SmtpServerOptions);

  const port = handle.port;
  return {
    port,
    queue,
    events,
    handle,
    async connect(secure = false): Promise<TestSmtpClient> {
      return TestSmtpClient.connect(port, secure);
    },
    async close(): Promise<void> {
      await handle.close();
    },
  };
}

/** Default principal for the tests. */
export function principal(overrides: Partial<SmtpPrincipal> = {}): SmtpPrincipal {
  return {
    id: "tenant-a:user",
    tenantId: "tenant-a",
    allowedSenders: [],
    allowedRecipientDomains: [],
    allowAuthzId: false,
    ...overrides,
  };
}
