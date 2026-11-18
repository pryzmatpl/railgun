// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The in-package fake MX / SMTP server.
 *
 * The harness lives in `src/` (not in the test tree) because the verification
 * IR requires the package to *ship* a scriptable fake MX: an operator can use
 * it to exercise a deployment without a real recipient, and the integration
 * suite drives the same code.
 *
 * The fake:
 *
 *   - binds to loopback on an ephemeral port by default;
 *   - speaks the RFC 5321 subset the outbound engine needs;
 *   - records every command and the exact DATA bytes;
 *   - can be scripted per recipient, per attempt and per command;
 *   - counts connections, so a policy rejection can be proven to have opened
 *     zero SMTP transactions;
 *   - never logs, echoes or persists AUTH material.
 *
 * Contract: `docs/design/481de2b7-e002-4cdc-95e0-0adc9068e2c4.md` §2.3
 * (R-FAKE-1 … R-FAKE-7).
 */

import net from "node:net";
import tls from "node:tls";

/** The reply one scripted command produces. */
export interface FakeMxReply {
  readonly code: number;
  readonly text: string;
}

/** The script the fake follows. */
export interface FakeMxScript {
  /** The capabilities advertised in the EHLO reply. */
  readonly capabilities?: readonly string[];
  /** The reply to `MAIL FROM`. */
  readonly mailFrom?: FakeMxReply;
  /** The reply to `RCPT TO`; may be keyed by recipient address. */
  readonly rcptTo?: FakeMxReply | Readonly<Record<string, FakeMxReply>>;
  /** The reply to `DATA`. */
  readonly data?: FakeMxReply;
  /** The final reply after the message body. */
  readonly final?: FakeMxReply;
  /** The reply to `STARTTLS`. */
  readonly starttls?: FakeMxReply;
  /** Serve TLS on the accepted socket. */
  readonly serveTls?: boolean;
  /** The TLS server options used when `serveTls` is set. */
  readonly tlsOptions?: tls.TlsOptions;
  /** How many attempts should be refused before the fake starts accepting. */
  readonly transientFailures?: number;
}

/** One observed fake-MX session. */
export interface FakeMxSession {
  /** Every command line the client sent, in order. */
  readonly commands: readonly string[];
  /** The exact bytes received in the DATA phase. */
  readonly body: string;
  /** The remote address of the client. */
  readonly remoteAddress: string | null;
}

/** The handle of a running fake MX. */
export interface FakeMxServer {
  readonly host: string;
  readonly port: number;
  readonly address: string;
  /** Every session the fake observed. */
  readonly sessions: readonly FakeMxSession[];
  /** How many connections the fake accepted. */
  readonly connectionCount: number;
  /** Every command line the fake received, across all sessions. */
  readonly received: string;
  /** The exact DATA bytes the fake received, across all sessions. */
  readonly receivedBody: string;
  close(): Promise<void>;
}

/** The default reply used when a command is not scripted. */
const DEFAULT_REPLY: FakeMxReply = { code: 250, text: "2.0.0 OK" };

/**
 * Start the fake MX server.
 *
 * The listener binds to `127.0.0.1` on an ephemeral port unless a host is
 * given explicitly, so the fake is never reachable from outside the machine.
 */
export async function startFakeMxServer(
  script: FakeMxScript = {},
  options: { host?: string } = {},
): Promise<FakeMxServer> {
  const host = options.host ?? "127.0.0.1";
  const sessions: FakeMxSession[] = [];
  const commands: string[] = [];
  const bodies: string[] = [];
  let connectionCount = 0;

  const server = net.createServer((socket) => {
    connectionCount += 1;
    const sessionCommands: string[] = [];
    let body = "";
    let inData = false;
    let attempt = 0;
    let failed = false;

    // The RFC 5321 greeting. A client may not send a command before it.
    socket.write("220 fake.mx.test ESMTP ready\r\n");

    const send = (reply: FakeMxReply): void => {
      socket.write(`${reply.code} ${reply.text}\r\n`);
    };

    const record = (): void => {
      sessions.push({
        commands: [...sessionCommands],
        body,
        remoteAddress: socket.remoteAddress ?? null,
      });
    };

    const handleLine = (line: string): boolean => {
      if (inData) {
        if (line === ".") {
          inData = false;
          const transient = script.transientFailures ?? 0;
          if (transient > 0 && attempt < transient) {
            attempt += 1;
            failed = true;
            send({ code: 451, text: "4.3.0 Temporary failure" });
            record();
            return false;
          }
          failed = false;
          send(script.final ?? { code: 250, text: "2.0.0 Accepted" });
          record();
          return false;
        }
        body += `${line.startsWith("..") ? line.slice(1) : line}\r\n`;
        return false;
      }

      sessionCommands.push(line);
      commands.push(line);
      const verb = line.slice(0, 4).toUpperCase();

      if (verb === "EHLO") {
        const capabilities = script.capabilities ?? [];
        const entries = ["fake.mx.test greets you", ...capabilities.map((entry) => ` ${entry}`)];
        socket.write(
          `${entries
            .map((entry, index) =>
              index === entries.length - 1 ? `250 ${entry}` : `250-${entry}`,
            )
            .join("\r\n")}\r\n`,
        );
        return false;
      }
      if (verb === "HELO") {
        send({ code: 250, text: "fake.mx.test" });
        return false;
      }
      if (verb === "STARTTLS") {
        const reply = script.starttls ?? { code: 220, text: "2.0.0 Ready to start TLS" };
        send(reply);
        return false;
      }
      if (verb === "MAIL") {
        send(script.mailFrom ?? DEFAULT_REPLY);
        return false;
      }
      if (verb === "RCPT") {
        const configured = script.rcptTo;
        if (configured && !("code" in configured)) {
          const address = extractAddress(line);
          const keyed = address ? configured[address.toLowerCase()] : undefined;
          send(keyed ?? { code: 250, text: "2.1.5 Recipient ok" });
          return false;
        }
        send((configured as FakeMxReply | undefined) ?? { code: 250, text: "2.1.5 Recipient ok" });
        return false;
      }
      if (verb === "DATA") {
        const reply = script.data ?? { code: 354, text: "End data with <CRLF>.<CRLF>" };
        send(reply);
        if (reply.code === 354) inData = true;
        return false;
      }
      if (verb === "NOOP") {
        send({ code: 250, text: "2.0.0 Ok" });
        return false;
      }
      if (verb === "RSET") {
        send({ code: 250, text: "2.0.0 Ok" });
        return false;
      }
      if (verb === "QUIT") {
        send({ code: 221, text: "2.0.0 Bye" });
        socket.end();
        return true;
      }
      send({ code: 500, text: "5.5.1 Command not recognised" });
      return false;
    };

    let pending = "";
    socket.setEncoding("latin1");
    socket.on("data", (chunk: string) => {
      pending += chunk;
      for (;;) {
        const index = pending.indexOf("\r\n");
        if (index === -1) break;
        const line = pending.slice(0, index);
        pending = pending.slice(index + 2);
        if (handleLine(line)) return;
      }
    });
    socket.on("error", () => {
      /* a client that hangs up is not a fake failure */
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;

  return {
    host,
    port,
    address: `${host}:${port}`,
    sessions,
    get connectionCount(): number {
      return connectionCount;
    },
    get received(): string {
      return commands.join("\n");
    },
    get receivedBody(): string {
      return bodies.join("\n");
    },
    async close(): Promise<void> {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    },
  };
}

/** Extract the address from a `RCPT TO:<user@host>` command line. */
function extractAddress(line: string): string | null {
  const match = /<\s*([^>\s]+)\s*>/.exec(line);
  return match?.[1] ?? null;
}
