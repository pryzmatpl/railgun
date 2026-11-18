/* RailGun SMTP submission server — transport.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * The network listener for the SMTP submission surface.
 *
 * The listener owns sockets and TLS; the protocol logic lives in
 * {@link SmtpSession}. See IR §2 (transport, listener, TLS).
 */

import net from "node:net";
import tls from "node:tls";
import { randomUUID } from "node:crypto";

import { SmtpSession, type SmtpSessionTransport } from "./session.js";
import type { SmtpServerOptions, SmtpTlsOptions } from "./types.js";

export interface SmtpServerHandle {
  /** The bound address, e.g. `127.0.0.1:34567`. */
  readonly address: net.AddressInfo | null;
  /** The bound port. */
  readonly port: number;
  /** Stop listening and close all open connections. */
  close(): Promise<void>;
}

interface Connection {
  session: SmtpSession;
  /** The socket currently carrying protocol bytes (plain or TLS). */
  socket: net.Socket;
  idleTimer: NodeJS.Timeout | null;
  lifetimeTimer: NodeJS.Timeout | null;
  closed: boolean;
  /** Serializes chunk delivery into the session. */
  feed: Promise<void>;
}

/**
 * Create (but do not start) an SMTP submission server.
 *
 * The server binds exactly one listener. For the implicit-TLS variant pass
 * `implicitTls`; the handshake then happens before the greeting (IR §2.3).
 */
export function createSmtpServer(options: SmtpServerOptions): {
  server: net.Server;
  handle: SmtpServerHandle;
} {
  const host = options.host ?? "0.0.0.0";
  const port = options.port;

  // IR Rule L-1: port 25 requires explicit operator opt-in.
  if (port === 25 && options.allowPort25 !== true) {
    throw new Error(
      "Refusing to bind SMTP port 25 without explicit operator opt-in (allowPort25).",
    );
  }

  const connections = new Set<Connection>();

  const server = net.createServer((socket) => {
    socket.setNoDelay(true);

    const correlationId = randomUUID();
    let secure = false;

    const connection: Connection = {
      session: undefined as unknown as SmtpSession,
      socket,
      idleTimer: null,
      lifetimeTimer: null,
      closed: false,
      feed: Promise.resolve(),
    };

    const clearTimers = (): void => {
      if (connection.idleTimer) {
        clearTimeout(connection.idleTimer);
        connection.idleTimer = null;
      }
      if (connection.lifetimeTimer) {
        clearTimeout(connection.lifetimeTimer);
        connection.lifetimeTimer = null;
      }
    };

    const resetIdle = (): void => {
      if (connection.idleTimer) clearTimeout(connection.idleTimer);
      const idle = options.idleTimeoutMs;
      if (idle && idle > 0) {
        connection.idleTimer = setTimeout(() => {
          // IR Rule S-9: on idle expiry the connection closes; a partial
          // message is discarded, never queued.
          connection.session.close("idle_timeout");
          connection.socket.destroy();
        }, idle);
        connection.idleTimer.unref?.();
      }
    };

    const transport: SmtpSessionTransport = {
      write(data: string | Buffer): void {
        if (!connection.socket.destroyed) connection.socket.write(data);
      },
      close(): void {
        connection.closed = true;
        clearTimers();
        connection.socket.end();
      },
      async upgradeToTls(): Promise<void> {
        const upgraded = await upgradeToTls(connection.socket, options.startTls);
        // The TLS socket now carries the protocol bytes; the plain socket's
        // data listener is replaced so the session sees exactly one stream.
        connection.socket.removeAllListeners("data");
        connection.socket = upgraded;
        wireSocketData(connection, upgraded, resetIdle);
        secure = true;
      },
      get isSecure(): boolean {
        return secure;
      },
    };

    connection.session = new SmtpSession({
      sourceIp: socket.remoteAddress ?? "unknown",
      correlationId,
      options,
      transport,
    });

    connections.add(connection);

    if (options.connectionLifetimeMs && options.connectionLifetimeMs > 0) {
      connection.lifetimeTimer = setTimeout(() => {
        connection.session.close("lifetime_expired");
        connection.socket.destroy();
      }, options.connectionLifetimeMs);
      connection.lifetimeTimer.unref?.();
    }

    wireSocketData(connection, socket, resetIdle);

    socket.on("error", () => {
      connection.closed = true;
      clearTimers();
      connections.delete(connection);
    });

    socket.on("close", () => {
      connection.closed = true;
      clearTimers();
      connections.delete(connection);
    });

    if (options.implicitTls) {
      // IR §2.3: greet only after a successful handshake.
      void bootstrapImplicitTls(connection, options.implicitTls);
      return;
    }

    resetIdle();
    connection.session.start();
  });

  const handle: SmtpServerHandle = {
    get address(): net.AddressInfo | null {
      const addr = server.address();
      return addr && typeof addr === "object" ? addr : null;
    },
    get port(): number {
      const addr = server.address();
      return addr && typeof addr === "object" ? addr.port : port;
    },
    async close(): Promise<void> {
      for (const connection of connections) {
        connection.session.close("server_shutdown");
        connection.socket.destroy();
      }
      connections.clear();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };

  return { server, handle };
}

/** Start the server and resolve with the bound handle. */
export async function startSmtpServer(options: SmtpServerOptions): Promise<SmtpServerHandle> {
  const { server, handle } = createSmtpServer(options);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, options.host ?? "0.0.0.0", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  return handle;
}

/**
 * Route a socket's bytes into the session.
 *
 * Chunks are fed to the session strictly in arrival order: the session's
 * command handling is asynchronous (policy hooks, store writes), so a naive
 * `await` per chunk could interleave two reads.
 */
function wireSocketData(
  connection: Connection,
  socket: net.Socket,
  resetIdle: () => void,
): void {
  socket.on("data", (chunk: Buffer) => {
    resetIdle();
    connection.feed = connection.feed
      .then(() => connection.session.handleData(chunk))
      .then((close) => {
        if (close) {
          connection.closed = true;
          socket.destroy();
        }
      });
  });
}

/**
 * Upgrade a plain socket to TLS in place.
 *
 * The original socket's `data` listener is removed and the TLS socket takes
 * over the byte stream. The promise resolves once the handshake completes.
 */
async function upgradeToTls(socket: net.Socket, options?: SmtpTlsOptions): Promise<tls.TLSSocket> {
  if (!options) {
    throw new Error("STARTTLS is not configured");
  }

  const tlsSocket = new tls.TLSSocket(socket, {
    isServer: true,
    cert: options.cert,
    key: options.key,
    passphrase: options.passphrase,
    minVersion: options.minVersion ?? "TLSv1.2",
  });

  await new Promise<void>((resolve, reject) => {
    const onSecure = (): void => {
      tlsSocket.removeListener("error", onError);
      resolve();
    };
    const onError = (error: Error): void => {
      tlsSocket.removeListener("secure", onSecure);
      reject(error);
    };
    tlsSocket.once("secure", onSecure);
    tlsSocket.once("error", onError);
  });

  return tlsSocket;
}

/**
 * Perform the implicit-TLS handshake before the greeting and then hand the
 * socket to the session (IR §2.3).
 */
async function bootstrapImplicitTls(
  connection: Connection,
  options: SmtpTlsOptions,
): Promise<void> {
  const tlsSocket = new tls.TLSSocket(connection.socket, {
    isServer: true,
    cert: options.cert,
    key: options.key,
    passphrase: options.passphrase,
    minVersion: options.minVersion ?? "TLSv1.2",
  });

  try {
    await new Promise<void>((resolve, reject) => {
      const onSecure = (): void => {
        tlsSocket.removeListener("error", onError);
        resolve();
      };
      const onError = (error: Error): void => {
        tlsSocket.removeListener("secure", onSecure);
        reject(error);
      };
      tlsSocket.once("secure", onSecure);
      tlsSocket.once("error", onError);
    });
  } catch {
    // IR Rule T-3: a failed handshake is a sanitized failure, then close.
    connection.socket.destroy();
    return;
  }

  connection.socket = tlsSocket;
  tlsSocket.on("data", (chunk: Buffer) => {
    connection.feed = connection.feed
      .then(() => connection.session.handleData(chunk))
      .then((close) => {
        if (close) {
          connection.closed = true;
          tlsSocket.destroy();
        }
      });
  });
  tlsSocket.on("error", () => {
    connection.closed = true;
  });
  connection.session.start();
}
