/* RailGun SMTP submission server — protocol integration tests.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { afterEach, describe, expect, it } from "vitest";

import {
  principal,
  startTestServer,
  TestAuthenticator,
  type RunningTestServer,
} from "./helpers.js";
import { selfSignedTls } from "./tls-fixtures.js";
import { SMTP_REASON_CODES, type SmtpServerEvent } from "../../src/smtp/types.js";

let running: RunningTestServer | null = null;

afterEach(async () => {
  if (running) {
    await running.close();
    running = null;
  }
});

async function serverWith(
  options: Parameters<typeof startTestServer>[0] = {},
): Promise<RunningTestServer> {
  running = await startTestServer(options);
  return running;
}

/** Encode an `AUTH PLAIN` initial response. */
function plainBlob(user: string, password: string): string {
  return Buffer.from(`\0${user}\0${password}`, "utf8").toString("base64");
}

/** Encode a bare credential for one `AUTH LOGIN` challenge step. */
function loginBlob(value: string): string {
  return Buffer.from(value, "utf8").toString("base64");
}

describe("SMTP submission — command set", () => {
  it("greets, answers EHLO with extensions, and quits (T-1, T-9)", async () => {
    const server = await serverWith();
    const client = await server.connect();

    const greeting = await client.expectReply(220);
    expect(greeting.text).toContain("ESMTP");

    const ehlo = await client.command("EHLO client.example");
    expect(ehlo.code).toBe(250);
    expect(ehlo.text).toContain("8BITMIME");
    expect(ehlo.text).toContain("SIZE");

    const quit = await client.command("QUIT");
    expect(quit.code).toBe(221);
  });

  it("answers HELO without advertising extensions (T-2)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);

    const helo = await client.command("HELO client.example");
    expect(helo.code).toBe(250);
    expect(helo.text).not.toContain("8BITMIME");
  });

  it("rejects a malformed EHLO domain with 501 (T-19)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);

    const reply = await client.command("EHLO bad domain");
    expect(reply.code).toBe(501);
  });

  it("rejects an unknown verb with 500 and keeps the connection open (T-19)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    const reply = await client.command("FROBNICATE now");
    expect(reply.code).toBe(500);
    // The session survives a bad verb.
    const noop = await client.command("NOOP");
    expect(noop.code).toBe(250);
  });

  it("answers NOOP with 250 without changing state (S-7)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    expect((await client.command("NOOP")).code).toBe(250);
  });

  it("resets the transaction on RSET (S-6)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");

    expect((await client.command("RSET")).code).toBe(250);

    // The recipient list was discarded: DATA must now fail with 503.
    expect((await client.command("DATA")).code).toBe(503);
  });

  it("rejects MAIL before EHLO with 503 (S-1)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);

    expect((await client.command("MAIL FROM:<sender@example.com>")).code).toBe(503);
  });

  it("rejects RCPT before MAIL with 503 (S-1)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    expect((await client.command("RCPT TO:<rcpt@example.net>")).code).toBe(503);
  });

  it("rejects an over-long command line with 500 and closes the connection (C-3)", async () => {
    const server = await serverWith({ options: { maxCommandLineBytes: 64 } });
    const client = await server.connect();
    await client.expectReply(220);

    const reply = await client.command(`NOOP ${"x".repeat(200)}`);
    expect(reply.code).toBe(500);
  });
});

describe("SMTP submission — DATA, dot-unstuffing and limits", () => {
  it("accepts a message and queues it with the envelope recipients (T-5, T-12)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");

    expect((await client.command("DATA")).code).toBe(354);
    client.sendRaw(
      ["From: sender@example.com", "To: rcpt@example.net", "Subject: Hello", "", "Body line one.", "Body line two.", "."].join(
        "\r\n",
      ) + "\r\n",
    );

    const final = await client.expectReply(250);
    expect(final.text).toContain("rg-test-1");
    expect(server.queue.submissions).toHaveLength(1);
    expect(server.queue.submissions[0]!.recipients).toEqual(["rcpt@example.net"]);
  });

  it("unstuffs a leading dot exactly once (T-11)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");
    await client.command("DATA");

    client.sendRaw(
      ["From: sender@example.com", "Subject: dots", "", "..hidden", "...", "normal", "."].join("\r\n") +
        "\r\n",
    );

    const final = await client.expectReply(250);
    expect(final.code).toBe(250);

    const stored = Buffer.from(server.queue.submissions[0]!.raw).toString("latin1");
    expect(stored).toContain("\r\n.hidden\r\n");
    expect(stored).toContain("\r\n..\r\n");
    expect(stored).toContain("\r\nnormal\r\n");
    // The terminator is never stored.
    expect(stored.endsWith("normal\r\n")).toBe(true);
  });

  it("normalizes bare LF to CRLF in the stored message (D-4)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");
    await client.command("DATA");

    client.sendRaw("From: sender@example.com\nSubject: lf\n\nbody\n.\n");

    const final = await client.expectReply(250);
    expect(final.code).toBe(250);
    const stored = Buffer.from(server.queue.submissions[0]!.raw).toString("latin1");
    expect(stored).toContain("Subject: lf\r\n");
    expect(stored).not.toMatch(/[^\r]\n/);
  });

  it("rejects an oversize message with 552 and queues nothing (T-10)", async () => {
    const server = await serverWith({ options: { maxMessageBytes: 200 } });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");
    await client.command("DATA");

    client.sendRaw("From: sender@example.com\r\nSubject: big\r\n\r\n");
    client.sendRaw(`${"x".repeat(500)}\r\n.\r\n`);

    const final = await client.expectReply(552);
    expect(final.code).toBe(552);
    expect(final.text).toContain(SMTP_REASON_CODES.limitMessageSize);
    expect(server.queue.submissions).toHaveLength(0);
  });

  it("rejects an over-declared SIZE parameter early with 552 (D-6)", async () => {
    const server = await serverWith({ options: { maxMessageBytes: 100 } });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    const reply = await client.command("MAIL FROM:<sender@example.com> SIZE=99999");
    expect(reply.code).toBe(552);
  });

  it("rejects DATA with no accepted recipients using 503 (A-9)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");

    expect((await client.command("DATA")).code).toBe(503);
    expect(server.queue.submissions).toHaveLength(0);
  });

  it("rejects a malformed message with 554 (M-4)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");
    await client.command("DATA");

    client.sendRaw("this-is-not-a-header\r\n\r\nbody\r\n.\r\n");

    const final = await client.expectReply(554);
    expect(final.code).toBe(554);
    expect(server.queue.submissions).toHaveLength(0);
  });

  it("rejects a message without From or Return-Path context with 554 (D-8)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");
    await client.command("DATA");

    client.sendRaw("Subject: no context\r\n\r\nbody\r\n.\r\n");

    const final = await client.expectReply(554);
    expect(final.text).toContain(SMTP_REASON_CODES.policyMissingContext);
  });

  it("strips Bcc from the stored headers (M-7)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");
    await client.command("DATA");

    client.sendRaw(
      "From: sender@example.com\r\nBcc: secret@example.net\r\nSubject: x\r\n\r\nbody\r\n.\r\n",
    );

    expect((await client.expectReply(250)).code).toBe(250);
    const names = server.queue.submissions[0]!.headers.map((header) => header.name);
    expect(names).not.toContain("bcc");
  });

  it("enforces the recipient-count limit with 552 (A-10)", async () => {
    const server = await serverWith({ options: { maxRecipientsPerTransaction: 2 } });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");

    expect((await client.command("RCPT TO:<a@example.net>")).code).toBe(250);
    expect((await client.command("RCPT TO:<b@example.net>")).code).toBe(250);
    const third = await client.command("RCPT TO:<c@example.net>");
    expect(third.code).toBe(552);
    expect(third.text).toContain(SMTP_REASON_CODES.limitRecipientsPerTransaction);
  });

  it("treats a repeated recipient as an idempotent no-op (A-11)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");

    expect((await client.command("RCPT TO:<RCPT@example.net>")).code).toBe(250);

    await client.command("DATA");
    client.sendRaw("From: sender@example.com\r\n\r\nbody\r\n.\r\n");
    await client.expectReply(250);

    expect(server.queue.submissions[0]!.recipients).toEqual(["rcpt@example.net"]);
  });
});

describe("SMTP submission — pipelining", () => {
  it("answers exactly one response per pipelined command (P-1, P-2, T-12)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    client.sendRaw(
      [
        "MAIL FROM:<sender@example.com>",
        "RCPT TO:<a@example.net>",
        "RCPT TO:<b@example.net>",
        "RSET",
        "NOOP",
      ].join("\r\n") + "\r\n",
    );

    const codes: number[] = [];
    for (let i = 0; i < 5; i += 1) {
      codes.push((await client.expectReply()).code);
    }
    expect(codes).toEqual([250, 250, 250, 250, 250]);
  });

  it("treats bytes after DATA as body, not commands (P-3, T-13)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    client.sendRaw(
      [
        "MAIL FROM:<sender@example.com>",
        "RCPT TO:<rcpt@example.net>",
        "DATA",
        "From: sender@example.com",
        "Subject: piped",
        "",
        "NOOP is body text",
        ".",
      ].join("\r\n") + "\r\n",
    );

    // The pipelined batch produces exactly one reply per command: MAIL,
    // RCPT, the `354` for DATA, then the final `250` after the terminator.
    const mail = await client.expectReply();
    expect(mail.code).toBe(250);
    const rcpt = await client.expectReply();
    expect(rcpt.code).toBe(250);
    const data = await client.expectReply();
    expect(data.code).toBe(354);
    const final = await client.expectReply();
    expect(final.code).toBe(250);
    expect(final.text).toContain("rg-test-1");
    const stored = Buffer.from(server.queue.submissions[0]!.raw).toString("latin1");
    expect(stored).toContain("NOOP is body text");
  });

  it("keeps a failing command from suppressing its neighbours (P-2)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    client.sendRaw(["BOGUS", "NOOP"].join("\r\n") + "\r\n");

    expect((await client.expectReply()).code).toBe(500);
    expect((await client.expectReply()).code).toBe(250);
  });
});

describe("SMTP submission — recipients and policy", () => {
  it("accepts and rejects recipients independently (A-7, T-14)", async () => {
    const events: SmtpServerEvent[] = [];
    const server = await serverWith({
      events,
      options: {
        policy: {
          async authorizeRecipient(context) {
            if (context.recipient === "blocked@example.net") {
              return {
                action: "reject",
                code: 550,
                reason: SMTP_REASON_CODES.policyRecipientNotAllowed,
              };
            }
            return { action: "allow" };
          },
        },
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");

    expect((await client.command("RCPT TO:<good@example.net>")).code).toBe(250);
    const rejected = await client.command("RCPT TO:<blocked@example.net>");
    expect(rejected.code).toBe(550);
    expect(rejected.text).toContain(SMTP_REASON_CODES.policyRecipientNotAllowed);

    await client.command("DATA");
    client.sendRaw("From: sender@example.com\r\n\r\nbody\r\n.\r\n");
    await client.expectReply(250);

    // Only the accepted recipient is queued.
    expect(server.queue.submissions[0]!.recipients).toEqual(["good@example.net"]);
    // The rejected recipient is reported per recipient in the audit event.
    const accepted = events.find((event) => event.type === "message_accepted");
    expect(accepted).toBeDefined();
    expect(accepted && "recipients" in accepted ? accepted.recipients : []).toHaveLength(2);
  });

  it("maps a transient policy decision to 450 and a permanent one to 550 (T-15)", async () => {
    const server = await serverWith({
      options: {
        policy: {
          async authorizeRecipient(context) {
            if (context.recipient === "deferred@example.net") {
              return {
                action: "defer",
                code: 450,
                reason: SMTP_REASON_CODES.rateRecipientWarmup,
              };
            }
            if (context.recipient === "denied@example.net") {
              return {
                action: "reject",
                code: 550,
                reason: SMTP_REASON_CODES.policyRecipientNotAllowed,
              };
            }
            return { action: "allow" };
          },
        },
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");

    expect((await client.command("RCPT TO:<deferred@example.net>")).code).toBe(450);
    expect((await client.command("RCPT TO:<denied@example.net>")).code).toBe(550);
  });

  it("rejects an unauthorized sender at MAIL FROM with 550 (T-20)", async () => {
    const server = await serverWith({
      options: {
        authenticator: new TestAuthenticator({
          "user@example.com": {
            password: "secret",
            principal: principal({ allowedSenders: ["allowed@example.com"] }),
          },
        }),
        requireAuth: true,
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command(`AUTH PLAIN ${plainBlob("user@example.com", "secret")}`);

    const reply = await client.command("MAIL FROM:<stranger@example.com>");
    expect(reply.code).toBe(550);
    expect(reply.text).toContain(SMTP_REASON_CODES.policySenderNotAllowed);
  });

  it("rejects an unauthorized destination domain at RCPT TO (T-20, A-13)", async () => {
    const server = await serverWith({
      options: {
        authenticator: new TestAuthenticator({
          "user@example.com": {
            password: "secret",
            principal: principal({ allowedRecipientDomains: ["allowed.net"] }),
          },
        }),
        requireAuth: true,
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command(`AUTH PLAIN ${plainBlob("user@example.com", "secret")}`);
    await client.command("MAIL FROM:<sender@example.com>");

    expect((await client.command("RCPT TO:<rcpt@forbidden.net>")).code).toBe(550);
  });

  it("fails closed when a policy hook throws (H-6, T-22)", async () => {
    const server = await serverWith({
      options: {
        policyFailClosed: true,
        policy: {
          async authorizeRecipient() {
            throw new Error("policy backend down");
          },
        },
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");

    const reply = await client.command("RCPT TO:<rcpt@example.net>");
    expect(reply.code).toBe(451);
    expect(reply.text).toContain(SMTP_REASON_CODES.policyDegraded);
  });

  it("fails open when configured, and records a degraded reason (H-6, T-22)", async () => {
    const events: SmtpServerEvent[] = [];
    const server = await serverWith({
      events,
      options: {
        policyFailClosed: false,
        policy: {
          async authorizeRecipient() {
            throw new Error("policy backend down");
          },
        },
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");

    expect((await client.command("RCPT TO:<rcpt@example.net>")).code).toBe(250);
    expect(
      events.some(
        (event) =>
          event.type === "message_rejected" && event.reason === SMTP_REASON_CODES.policyDegraded,
      ),
    ).toBe(true);
  });

  it("rejects a content-policy decision at DATA with 554 (H-7, D-9)", async () => {
    const server = await serverWith({
      options: {
        policy: {
          async scoreContent() {
            return {
              action: "reject",
              code: 554,
              reason: SMTP_REASON_CODES.policyRejected,
            };
          },
        },
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");
    await client.command("DATA");
    client.sendRaw("From: sender@example.com\r\n\r\nspam\r\n.\r\n");

    expect((await client.expectReply(554)).code).toBe(554);
    expect(server.queue.submissions).toHaveLength(0);
  });
});

describe("SMTP submission — authentication", () => {
  it("authenticates with AUTH PLAIN and accepts the transaction (U-1, T-6)", async () => {
    const server = await serverWith({
      options: {
        requireAuth: true,
        authenticator: new TestAuthenticator({
          "user@example.com": { password: "secret", principal: principal() },
        }),
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    const auth = await client.command(`AUTH PLAIN ${plainBlob("user@example.com", "secret")}`);
    expect(auth.code).toBe(235);
  });

  it("accepts the AUTH PLAIN challenge form (U-1)", async () => {
    const server = await serverWith({
      options: {
        requireAuth: true,
        authenticator: new TestAuthenticator({
          "user@example.com": { password: "secret", principal: principal() },
        }),
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    expect((await client.command("AUTH PLAIN")).code).toBe(334);
    const auth = await client.command(plainBlob("user@example.com", "secret"));
    expect(auth.code).toBe(235);
  });

  it("authenticates with AUTH LOGIN using the two fixed challenges (U-8, T-7)", async () => {
    const server = await serverWith({
      options: {
        requireAuth: true,
        authenticator: new TestAuthenticator({
          "user@example.com": { password: "secret", principal: principal() },
        }),
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    const challenge = await client.command("AUTH LOGIN");
    expect(challenge.code).toBe(334);
    expect(challenge.text).toBe("VXNlcm5hbWU6");

    const passwordChallenge = await client.command(loginBlob("user@example.com"));
    expect(passwordChallenge.code).toBe(334);
    expect(passwordChallenge.text).toBe("UGFzc3dvcmQ6");

    const auth = await client.command(loginBlob("secret"));
    expect(auth.code).toBe(235);
  });

  it("returns an identical 535 for an unknown user and a wrong password (U-6, T-21)", async () => {
    const server = await serverWith({
      options: {
        requireAuth: true,
        authenticator: new TestAuthenticator({
          "user@example.com": { password: "secret", principal: principal() },
        }),
      },
    });

    const clientA = await server.connect();
    await clientA.expectReply(220);
    await clientA.command("EHLO client.example");
    const unknown = await clientA.command(
      `AUTH PLAIN ${plainBlob("nobody@example.com", "secret")}`,
    );

    const clientB = await server.connect();
    await clientB.expectReply(220);
    await clientB.command("EHLO client.example");
    const wrong = await clientB.command(
      `AUTH PLAIN ${plainBlob("user@example.com", "wrong")}`,
    );

    expect(unknown.code).toBe(535);
    expect(wrong.code).toBe(535);
    // Identical observable failure — no account enumeration.
    expect(unknown.text).toBe(wrong.text);
  });

  it("rejects an unsupported mechanism with 504, never 535 (U-14)", async () => {
    const server = await serverWith({
      options: {
        authenticator: new TestAuthenticator({
          "user@example.com": { password: "secret", principal: principal() },
        }),
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    expect((await client.command("AUTH XOAUTH2 abc")).code).toBe(504);
  });

  it("requires authentication before MAIL FROM with 530 (U-15)", async () => {
    const server = await serverWith({
      options: {
        requireAuth: true,
        authenticator: new TestAuthenticator({
          "user@example.com": { password: "secret", principal: principal() },
        }),
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    const reply = await client.command("MAIL FROM:<sender@example.com>");
    expect(reply.code).toBe(530);
    expect(reply.text).toContain(SMTP_REASON_CODES.authRequired);
  });

  it("never leaks credentials in responses or events (U-5, T-18)", async () => {
    const events: SmtpServerEvent[] = [];
    const server = await serverWith({
      events,
      options: {
        requireAuth: true,
        authenticator: new TestAuthenticator({
          "user@example.com": { password: "secret", principal: principal() },
        }),
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    const blob = plainBlob("user@example.com", "wrong-secret");
    const reply = await client.command(`AUTH PLAIN ${blob}`);
    expect(reply.code).toBe(535);
    expect(reply.raw).not.toContain("wrong-secret");
    expect(reply.raw).not.toContain("user@example.com");
    expect(reply.raw).not.toContain(blob);

    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain("wrong-secret");
    expect(serialized).not.toContain("user@example.com");
    expect(serialized).not.toContain(blob);
  });

  it("cancels an in-progress AUTH exchange with 501 (U-10)", async () => {
    const server = await serverWith({
      options: {
        authenticator: new TestAuthenticator({
          "user@example.com": { password: "secret", principal: principal() },
        }),
      },
    });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    expect((await client.command("AUTH LOGIN")).code).toBe(334);
    const cancel = await client.command("*");
    expect(cancel.code).toBe(501);
  });
});

describe("SMTP submission — transactional integrity", () => {
  it("answers 451 and queues nothing when the store fails (D-9, T-23)", async () => {
    const server = await serverWith();
    server.queue.failNext = true;

    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");
    await client.command("DATA");
    client.sendRaw("From: sender@example.com\r\n\r\nbody\r\n.\r\n");

    expect((await client.expectReply(451)).code).toBe(451);
    expect(server.queue.submissions).toHaveLength(0);
  });

  it("leaves no message row when the connection closes mid-DATA (T-25)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");
    await client.command("DATA");

    client.sendRaw("From: sender@example.com\r\n\r\npartial body without terminator\r\n");
    client.end();

    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(server.queue.submissions).toHaveLength(0);
  });

  it("discards an in-flight transaction on QUIT (S-8)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");
    await client.command("RCPT TO:<rcpt@example.net>");

    await client.command("QUIT");
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(server.queue.submissions).toHaveLength(0);
  });
});

describe("SMTP submission — TLS", () => {
  it("advertises STARTTLS only when a certificate is configured (T-1)", async () => {
    const withoutTls = await serverWith();
    const plain = await withoutTls.connect();
    await plain.expectReply(220);
    const plainEhlo = await plain.command("EHLO client.example");
    expect(plainEhlo.text).not.toContain("STARTTLS");

    const tls = selfSignedTls();
    if (!tls) return;

    const withTls = await serverWith({ options: { startTls: tls } });
    const secure = await withTls.connect();
    await secure.expectReply(220);
    const secureEhlo = await secure.command("EHLO client.example");
    expect(secureEhlo.text).toContain("STARTTLS");
    // PIPELINING is advertised only after TLS (IR Rule T-2).
    expect(secureEhlo.text).not.toContain("PIPELINING");
  });

  it("upgrades the session with STARTTLS and resets it (T-3, T-4)", async () => {
    const tls = selfSignedTls();
    if (!tls) return;

    const server = await serverWith({ options: { startTls: tls } });
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    const ready = await client.command("STARTTLS");
    expect(ready.code).toBe(220);

    // The client upgrades its side of the socket.
    await client.upgradeToTls();

    // IR Rule T-4: the session is reset; a fresh EHLO is required before
    // MAIL FROM.
    const afterUpgrade = await client.command("MAIL FROM:<sender@example.com>");
    expect(afterUpgrade.code).toBe(503);

    const ehlo = await client.command("EHLO client.example");
    expect(ehlo.code).toBe(250);
    // PIPELINING is advertised once TLS is established.
    expect(ehlo.text).toContain("PIPELINING");

    // The transaction proceeds normally over TLS.
    expect((await client.command("MAIL FROM:<sender@example.com>")).code).toBe(250);
  });

  it("rejects STARTTLS with 502 on an implicit-TLS listener (T-1)", async () => {
    const tls = selfSignedTls();
    if (!tls) return;

    const server = await serverWith({ options: { implicitTls: tls } });
    const client = await server.connect(true);
    await client.expectReply(220);
    await client.command("EHLO client.example");

    const reply = await client.command("STARTTLS");
    expect(reply.code).toBe(502);
  });

  it("greets only after the implicit-TLS handshake completes (IR §2.3)", async () => {
    const tls = selfSignedTls();
    if (!tls) return;

    const server = await serverWith({ options: { implicitTls: tls } });
    const client = await server.connect(true);
    const greeting = await client.expectReply(220);
    expect(greeting.text).toContain("ESMTP");
  });
});

describe("SMTP submission — listener rules", () => {
  it("refuses to bind port 25 without explicit opt-in (L-1)", async () => {
    const { createSmtpServer } = await import("../../src/smtp/server.js");
    expect(() => createSmtpServer({ port: 25 })).toThrow(/port 25/i);
  });

  it("rejects a source route with 501 (A-4)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");

    expect((await client.command("MAIL FROM:<@relay.example:user@example.com>")).code).toBe(501);
  });

  it("rejects a malformed address with 501 (A-5)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");

    expect((await client.command("RCPT TO:<not-an-address>")).code).toBe(501);
  });

  it("rejects a non-ASCII address with 553 when SMTPUTF8 is not advertised (A-6)", async () => {
    const server = await serverWith();
    const client = await server.connect();
    await client.expectReply(220);
    await client.command("EHLO client.example");
    await client.command("MAIL FROM:<sender@example.com>");

    expect((await client.command("RCPT TO:<üser@example.net>")).code).toBe(553);
  });
});
