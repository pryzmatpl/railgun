// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * A local, throwaway SMTP relay used to exercise the live-delivery script
 * end to end without touching the public internet.
 *
 * It is a test fixture, not a deliverable: it exists so the credential-hygiene
 * proof of the live script can be demonstrated against a real socket.
 */
import net from "node:net";

/** What the relay observed. */
export interface RelayObservations {
  /** The AUTH command lines the relay received. */
  readonly auth: string[];
  /** Every command line the relay received. */
  readonly commands: string[];
  /** The message body the relay received. */
  body: string;
}

/** The handle of a running relay. */
export interface RelayHandle {
  readonly port: number;
  readonly seen: RelayObservations;
  close(): Promise<void>;
}

/** Start the relay and resolve with its port. */
export async function startRelay(): Promise<RelayHandle> {
  const seen: RelayObservations = { auth: [], commands: [], body: "" };
  const server = net.createServer((socket) => {
    let buffer = "";
    let inData = false;
    socket.write("220 relay.test ESMTP ready\r\n");
    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      for (;;) {
        const index = buffer.indexOf("\r\n");
        if (index === -1) break;
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        if (inData) {
          if (line === ".") {
            inData = false;
            socket.write("250 2.0.0 Accepted\r\n");
            continue;
          }
          seen.body += `${line}\r\n`;
          continue;
        }
        seen.commands.push(line);
        const verb = line.slice(0, 4).toUpperCase();
        if (verb === "EHLO") {
          socket.write("250-relay.test\r\n250 AUTH PLAIN\r\n");
        } else if (verb === "STARTTLS") {
          socket.write("220 2.0.0 Ready to start TLS\r\n");
        } else if (verb === "AUTH") {
          seen.auth.push(line);
          socket.write("235 2.7.0 Authentication successful\r\n");
        } else if (verb === "MAIL" || verb === "RCPT") {
          socket.write("250 2.1.0 Ok\r\n");
        } else if (verb === "DATA") {
          inData = true;
          socket.write("354 End data with <CRLF>.<CRLF>\r\n");
        } else if (verb === "QUIT") {
          socket.write("221 2.0.0 Bye\r\n");
          socket.end();
        } else {
          socket.write("250 2.0.0 Ok\r\n");
        }
      }
    });
    socket.on("error", () => {
      /* a client that hangs up is not a relay failure */
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;

  return {
    port,
    seen,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}
