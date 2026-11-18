/* RailGun SMTP submission server — session state machine.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * The per-connection SMTP session.
 *
 * This class owns the wire state machine described in
 * `docs/design/84df18ec-8e87-47cb-9d64-b804c4205cb3-railgun-smtp-submission-server-ir.md`
 * §3–§8. It performs no socket I/O itself: the transport adapter feeds it
 * bytes and writes back whatever it returns, which keeps the protocol logic
 * testable without a network listener.
 */

import {
  DataAccumulator,
  SmtpParseError,
  isNonAsciiAddress,
  parseCommand,
  parseHeaders,
} from "./parser.js";
import {
  SMTP_REASON_CODES,
  type PolicyDecisionContext,
  type PolicyHookResult,
  type RecipientOutcome,
  type SmtpHeader,
  type SmtpPolicyHooks,
  type SmtpPrincipal,
  type SmtpQueuePort,
  type SmtpServerEvent,
  type SmtpServerOptions,
  type SmtpSessionState,
} from "./types.js";

/** Callbacks the transport adapter provides to the session. */
export interface SmtpSessionTransport {
  /** Write raw bytes to the peer. */
  write(data: string | Buffer): void;
  /** Close the connection. */
  close(): void;
  /** Upgrade the underlying socket to TLS. */
  upgradeToTls(): Promise<void>;
  /** True once the connection is protected by TLS. */
  readonly isSecure: boolean;
}

export interface SmtpSessionInit {
  readonly sourceIp: string;
  readonly correlationId: string;
  readonly options: SmtpServerOptions;
  readonly transport: SmtpSessionTransport;
}

interface AcceptedRecipient {
  readonly address: string;
  readonly code: number;
  readonly reason: string;
}

interface RejectedRecipient {
  readonly address: string;
  readonly code: number;
  readonly reason: string;
}

const DEFAULTS = {
  maxMessageBytes: 25 * 1024 * 1024,
  maxRecipientsPerTransaction: 100,
  maxRecipientsPerMessage: 50,
  maxCommandLineBytes: 512,
  maxHeaderCount: 100,
  maxHeaderBytes: 64 * 1024,
  maxCredentialBytes: 1024,
  maxCommandRatePerMinute: 600,
  idleTimeoutMs: 300_000,
  connectionLifetimeMs: 3_600_000,
  authTimeoutMs: 60_000,
};

/** Fixed base64 challenge constants for `AUTH LOGIN` (IR Rules U-8, U-9). */
export const AUTH_LOGIN_USERNAME_CHALLENGE = "VXNlcm5hbWU6";
export const AUTH_LOGIN_PASSWORD_CHALLENGE = "UGFzc3dvcmQ6";

type AuthStage = "none" | "plain" | "login-username" | "login-password";

export class SmtpSession {
  private readonly sourceIp: string;
  private readonly correlationId: string;
  private readonly options: SmtpServerOptions;
  private readonly transport: SmtpSessionTransport;
  /** The durable queue port (H9). `null` disables submission entirely. */
  private readonly queue: SmtpQueuePort | null;

  private state: SmtpSessionState = "GREETING_SENT";
  private principal: SmtpPrincipal | null = null;
  private envelopeSender: string | null = null;
  private accepted: AcceptedRecipient[] = [];
  private rejected: RejectedRecipient[] = [];
  private accumulator: DataAccumulator | null = null;
  private authStage: AuthStage = "none";
  private authUsername: string | null = null;
  private sawEhlo = false;
  private tlsActive = false;
  private closed = false;
  private commandTimestamps: number[] = [];
  private declaredSize: number | null = null;

  constructor(init: SmtpSessionInit) {
    this.sourceIp = init.sourceIp;
    this.correlationId = init.correlationId;
    this.options = init.options;
    this.transport = init.transport;
    this.queue = init.options.queue ?? null;
  }

  /** Current session state. */
  get sessionState(): SmtpSessionState {
    return this.state;
  }

  /** True when the connection is closed. */
  get isClosed(): boolean {
    return this.closed;
  }

  /** The authenticated principal, if any. */
  get authenticatedPrincipal(): SmtpPrincipal | null {
    return this.principal;
  }

  /** Emit the greeting (IR §2.3, implicit-TLS listeners greet after handshake). */
  start(): void {
    this.reply(220, `${this.hostname()} ESMTP RailGun ready`);
  }

  private hostname(): string {
    return this.options.hostname ?? "railgun";
  }

  // ---------------------------------------------------------------- replies

  /** Write a single-line reply (IR Rule R-1). */
  private reply(code: number, text: string): void {
    this.transport.write(`${code} ${text}\r\n`);
  }

  /** Write a multi-line reply; the final line uses `<code> ` (IR Rule R-1). */
  private replyMultiline(code: number, lines: readonly string[]): void {
    if (lines.length === 0) {
      this.reply(code, "OK");
      return;
    }
    for (let i = 0; i < lines.length - 1; i += 1) {
      this.transport.write(`${code}-${lines[i]}\r\n`);
    }
    this.transport.write(`${code} ${lines[lines.length - 1]}\r\n`);
  }

  /**
   * Write a rejection carrying its stable reason code (IR Rules R-2, R-3).
   * The reply text never contains credential material, envelope addresses of
   * other recipients, or stack traces.
   */
  private replyError(code: number, reason: string, text: string): void {
    this.reply(code, `${text} (reason=${reason})`);
  }

  // ------------------------------------------------------------ entry point

  /**
   * Feed raw socket bytes into the session.
   *
   * Returns `true` when the connection should be closed.
   */
  async handleData(chunk: Buffer): Promise<boolean> {
    if (this.closed) return true;

    let buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    this.buffer = Buffer.alloc(0);

    for (;;) {
      if (this.accumulator) {
        // DATA body mode: bytes are content, never commands (IR Rule P-3).
        // The accumulator consumes everything that is left in this chunk.
        const remaining = buffer;
        buffer = Buffer.alloc(0);
        if (this.accumulator.push(remaining)) {
          await this.finishData();
        }
        break;
      }

      const idx = buffer.indexOf(0x0a);
      if (idx === -1) break;
      let line = buffer.subarray(0, idx);
      buffer = buffer.subarray(idx + 1);
      if (line.length > 0 && line[line.length - 1] === 0x0d) {
        line = line.subarray(0, line.length - 1);
      }

      const maxLine = this.options.maxCommandLineBytes ?? DEFAULTS.maxCommandLineBytes;
      if (line.length + 2 > maxLine) {
        // IR Rule C-3: the server cannot find the next boundary reliably.
        this.replyError(
          500,
          SMTP_REASON_CODES.limitCommandLineBytes,
          "Command line too long",
        );
        this.close("command_line_too_long");
        return true;
      }

      // Commands are processed strictly in arrival order, even when the
      // handler is asynchronous (policy hooks, store writes). Pipelining
      // still yields exactly one response per command (IR Rules P-1, P-2).
      this.pending.push(line.toString("latin1"));

      // Await the drain so that a `DATA` command has fully switched the
      // session into body mode before the split loop looks at the next
      // byte. Without this, the message body that follows `DATA` in the
      // same TCP segment would be parsed as commands (IR Rule P-3).
      await this.drainCommands();

      // The `DATA` command switches the session into body mode. The bytes
      // that follow it in the same chunk are message content, not commands,
      // so the split loop must stop here and let the accumulator take over.
      if (this.accumulator) {
        continue;
      }
    }

    this.buffer = buffer;
    // Guard against unbounded buffering of an unterminated command line.
    const maxLine = this.options.maxCommandLineBytes ?? DEFAULTS.maxCommandLineBytes;
    if (!this.accumulator && this.buffer.length + 2 > maxLine) {
      this.replyError(500, SMTP_REASON_CODES.limitCommandLineBytes, "Command line too long");
      this.close("command_line_too_long");
      return true;
    }
    return this.closed;
  }

  private buffer: Buffer = Buffer.alloc(0);
  private readonly pending: string[] = [];

  /**
   * Process queued command lines one at a time.
   *
   * The drain is re-entrant safe: a handler that awaits yields back to the
   * event loop, and the next command is only started once the previous one
   * has fully completed, so session state stays consistent.
   */
  private async drainCommands(): Promise<void> {
    if (this.drainPromise) {
      // Another drain is in flight; it owns the queue.
      await this.drainPromise;
      return;
    }
    const run = this.drainLoop();
    this.drainPromise = run;
    try {
      await run;
    } finally {
      if (this.drainPromise === run) this.drainPromise = null;
    }
  }

  private async drainLoop(): Promise<void> {
    try {
      while (this.pending.length > 0 && !this.closed) {
        const line = this.pending.shift()!;
        const done = await this.handleLine(line);
        if (done) break;
      }
    } finally {
      // The drain released; `drainPromise` is cleared by `drainCommands`.
    }
    // A command may have queued more work (e.g. the AUTH continuation
    // challenge); pick it up now that the drain is released.
    if (!this.closed && this.pending.length > 0) {
      await this.drainCommands();
    }
  }

  /** The in-flight drain, if any. */
  private drainPromise: Promise<void> | null = null;

  /**
   * Process one complete command line.
   *
   * @returns `true` when the connection must be closed.
   */
  private async handleLine(line: string): Promise<boolean> {
    // An in-progress authentication exchange consumes the next line as a
    // credential response, not as a command (IR Rules U-1, U-8).
    if (this.authStage !== "none") {
      return this.handleAuthContinuation(line);
    }

    if (line.trim().length === 0) {
      this.replyError(500, SMTP_REASON_CODES.commandSyntax, "Syntax error");
      return false;
    }

    if (!this.checkCommandRate()) {
      this.replyError(451, SMTP_REASON_CODES.limitCommandRate, "Too many commands, slow down");
      this.close("command_rate_exceeded");
      return true;
    }

    let command;
    try {
      command = parseCommand(line);
    } catch (error) {
      if (error instanceof SmtpParseError) {
        this.replyError(error.code, error.reason, "Syntax error");
        return false;
      }
      throw error;
    }

    if (command.kind === "unknown") {
      this.replyError(500, SMTP_REASON_CODES.commandSyntax, "Command not recognized");
      return false;
    }

    // Command gating (IR Rule S-1).
    if (!this.isPermitted(command.kind)) {
      this.replyError(
        503,
        SMTP_REASON_CODES.commandOutOfSequence,
        "Bad sequence of commands",
      );
      return false;
    }

    switch (command.kind) {
      case "ehlo":
        return this.handleEhlo(command.domain, true);
      case "helo":
        return this.handleEhlo(command.domain, false);
      case "starttls":
        return this.handleStartTls();
      case "auth":
        return await this.handleAuth(command.mechanism, command.initialResponse);
      case "mail":
        return await this.handleMail(command.path.address, command.path.params);
      case "rcpt":
        return await this.handleRcpt(command.path.address, command.path.params);
      case "data":
        return this.handleDataCommand();
      case "rset":
        return this.handleRset();
      case "noop":
        this.reply(250, "OK");
        return false;
      case "quit":
        this.reply(221, `${this.hostname()} Closing connection`);
        this.close("quit");
        return true;
      default:
        this.replyError(500, SMTP_REASON_CODES.commandSyntax, "Syntax error");
        return false;
    }
  }

  // --------------------------------------------------------------- gating

  private isPermitted(kind: string): boolean {
    switch (this.state) {
      case "GREETING_SENT":
        return kind === "ehlo" || kind === "helo" || kind === "quit";
      case "GREETED":
      case "AUTHENTICATED":
        return true;
      case "TLS_ACTIVE":
        // IR Rule T-4: after a successful `STARTTLS` the session is reset.
        // A fresh `EHLO` is required before `MAIL FROM`; until then only
        // the greeting and housekeeping commands are permitted.
        if (!this.sawEhlo) {
          return kind === "ehlo" || kind === "helo" || kind === "noop" || kind === "rset" || kind === "quit";
        }
        return true;
      case "MAIL_RECEIVED":
        return kind === "rcpt" || kind === "data" || kind === "rset" || kind === "noop" || kind === "quit";
      case "RCPT_RECEIVED":
        return (
          kind === "rcpt" || kind === "data" || kind === "rset" || kind === "noop" || kind === "quit"
        );
      case "DATA_RECEIVED":
        return false;
      case "CLOSED":
        return false;
      default:
        return false;
    }
  }

  // ------------------------------------------------------------- commands

  private handleEhlo(domain: string, extended: boolean): boolean {
    // Re-greeting resets the transaction but preserves authentication
    // (IR Rules S-4, U-16).
    this.resetTransaction();
    this.sawEhlo = true;

    if (!extended) {
      this.state = this.tlsActive ? "TLS_ACTIVE" : this.principal ? "AUTHENTICATED" : "GREETED";
      this.reply(250, `${this.hostname()}`);
      return false;
    }

    const lines: string[] = [`${this.hostname()} greets ${domain}`];

    if (this.options.startTls && !this.tlsActive) {
      lines.push("STARTTLS");
    }
    if (this.options.authenticator) {
      lines.push("AUTH PLAIN LOGIN");
    }
    if (this.options.advertiseSize !== false) {
      lines.push(`SIZE ${this.options.maxMessageBytes ?? DEFAULTS.maxMessageBytes}`);
    }
    if (this.options.smtpUtf8) {
      lines.push("SMTPUTF8");
    }
    lines.push("8BITMIME");
    if (this.tlsActive) {
      // PIPELINING is advertised only after TLS (IR Rule T-2).
      lines.push("PIPELINING");
    }

    this.state = this.tlsActive ? "TLS_ACTIVE" : this.principal ? "AUTHENTICATED" : "GREETED";
    this.replyMultiline(250, lines);
    return false;
  }

  private handleStartTls(): boolean {
    if (this.tlsActive || this.options.implicitTls) {
      // IR Rule T-1: never advertised on an implicit-TLS listener.
      this.replyError(
        502,
        SMTP_REASON_CODES.commandNotImplemented,
        "STARTTLS not implemented",
      );
      return false;
    }
    if (!this.options.startTls) {
      this.replyError(454, SMTP_REASON_CODES.commandNotImplemented, "TLS not available");
      return false;
    }
    if (this.state === "MAIL_RECEIVED" || this.state === "RCPT_RECEIVED") {
      this.replyError(503, SMTP_REASON_CODES.commandOutOfSequence, "Bad sequence of commands");
      return false;
    }

    this.reply(220, "Ready to start TLS");
    void this.upgrade();
    return false;
  }

  private async upgrade(): Promise<void> {
    try {
      await this.transport.upgradeToTls();
      this.tlsActive = true;
      // IR Rule T-4: the session resets to its pre-EHLO state.
      this.principal = null;
      this.sawEhlo = false;
      this.resetTransaction();
      this.authStage = "none";
      this.authUsername = null;
      this.state = "TLS_ACTIVE";
      this.emit({
        type: "tls_established",
        sourceIp: this.sourceIp,
        correlationId: this.correlationId,
      });
    } catch {
      // IR Rule T-3: sanitized transient failure, then close.
      this.replyError(454, SMTP_REASON_CODES.internalError, "TLS negotiation failed");
      this.close("tls_handshake_failed");
    }
  }

  private async handleAuth(mechanism: string, initialResponse: string | null): Promise<boolean> {
    if (!this.options.authenticator) {
      this.replyError(
        504,
        SMTP_REASON_CODES.authMechanismUnsupported,
        "Authentication not supported",
      );
      return false;
    }
    if (this.state === "MAIL_RECEIVED" || this.state === "RCPT_RECEIVED") {
      this.replyError(503, SMTP_REASON_CODES.commandOutOfSequence, "Bad sequence of commands");
      return false;
    }

    if (mechanism === "PLAIN") {
      if (initialResponse === null) {
        this.authStage = "plain";
        this.reply(334, "");
        return false;
      }
      await this.finishPlain(initialResponse);
      return false;
    }

    if (mechanism === "LOGIN") {
      this.authStage = "login-username";
      if (initialResponse !== null) {
        this.authUsername = decodeCredential(initialResponse);
        this.authStage = "login-password";
        this.reply(334, AUTH_LOGIN_PASSWORD_CHALLENGE);
        return false;
      }
      this.reply(334, AUTH_LOGIN_USERNAME_CHALLENGE);
      return false;
    }

    // IR Rule U-14: an unsupported mechanism is `504`, never `535`.
    this.replyError(
      504,
      SMTP_REASON_CODES.authMechanismUnsupported,
      "Authentication mechanism not supported",
    );
    return false;
  }

  /**
   * Feed a continuation line for an in-progress authentication exchange
   * (`AUTH PLAIN` challenge response or `AUTH LOGIN` steps).
   */
  private async handleAuthContinuation(line: string): Promise<boolean> {
    if (this.authStage === "none") {
      this.replyError(500, SMTP_REASON_CODES.commandSyntax, "Syntax error");
      return false;
    }
    if (line.trim() === "*") {
      // IR Rule U-10: cancellation.
      this.authStage = "none";
      this.authUsername = null;
      this.replyError(501, SMTP_REASON_CODES.commandSyntax, "Authentication cancelled");
      return false;
    }

    if (this.authStage === "plain") {
      await this.finishPlain(line.trim());
      return false;
    }

    if (this.authStage === "login-username") {
      const decoded = decodeCredential(line.trim());
      if (decoded === null) {
        this.authStage = "none";
        this.replyError(501, SMTP_REASON_CODES.commandSyntax, "Invalid base64 response");
        return false;
      }
      this.authUsername = decoded;
      this.authStage = "login-password";
      this.reply(334, AUTH_LOGIN_PASSWORD_CHALLENGE);
      return false;
    }

    // login-password
    const password = decodeCredential(line.trim());
    const username = this.authUsername;
    this.authStage = "none";
    this.authUsername = null;
    if (password === null || username === null) {
      this.replyError(501, SMTP_REASON_CODES.commandSyntax, "Invalid base64 response");
      return false;
    }
    await this.finishLogin(username, password);
    return false;
  }

  private async finishPlain(initialResponse: string): Promise<void> {
    const max = this.options.maxCredentialBytes ?? DEFAULTS.maxCredentialBytes;
    if (initialResponse.length > max * 2) {
      // IR Rule U-12: reject before any comparison.
      this.replyError(501, SMTP_REASON_CODES.commandSyntax, "Invalid authentication response");
      return;
    }
    const decoded = decodeCredential(initialResponse);
    if (decoded === null) {
      this.replyError(501, SMTP_REASON_CODES.commandSyntax, "Invalid authentication response");
      return;
    }
    const parts = decoded.split("\0");
    if (parts.length < 3) {
      this.replyError(501, SMTP_REASON_CODES.commandSyntax, "Invalid authentication response");
      return;
    }
    const authzid = parts[0] ?? "";
    const authcid = parts[1] ?? "";
    const passwd = parts.slice(2).join("\0");
    if (authcid.length === 0 || authcid.length > max || passwd.length > max) {
      this.replyError(501, SMTP_REASON_CODES.commandSyntax, "Invalid authentication response");
      return;
    }
    await this.verify(authcid, passwd, authzid);
  }

  private async finishLogin(username: string, password: string): Promise<void> {
    const max = this.options.maxCredentialBytes ?? DEFAULTS.maxCredentialBytes;
    if (username.length > max || password.length > max) {
      this.replyError(501, SMTP_REASON_CODES.commandSyntax, "Invalid authentication response");
      return;
    }
    await this.verify(username, password, "");
  }

  private async verify(
    username: string,
    password: string,
    authzid: string,
  ): Promise<void> {
    const authenticator = this.options.authenticator;
    if (!authenticator) {
      this.replyError(
        504,
        SMTP_REASON_CODES.authMechanismUnsupported,
        "Authentication not supported",
      );
      return;
    }

    // IR Rule U-7: a throttled attempt yields `451`, not `535`.
    if (authenticator.checkRateLimit) {
      try {
        const waitSeconds = await authenticator.checkRateLimit(this.sourceIp, username);
        if (waitSeconds > 0) {
          this.emitAuthFailure(SMTP_REASON_CODES.authRateLimited);
          this.replyError(
            451,
            SMTP_REASON_CODES.authRateLimited,
            "Too many authentication attempts",
          );
          return;
        }
      } catch {
        this.emitAuthFailure(SMTP_REASON_CODES.authFailed);
        this.replyError(535, SMTP_REASON_CODES.authFailed, "Authentication failed");
        return;
      }
    }

    let principal: SmtpPrincipal | null = null;
    try {
      principal = await authenticator.verify(username, password, { sourceIp: this.sourceIp });
    } catch {
      principal = null;
    }

    // IR Rule U-3: an authzid that differs from the principal's identity is
    // refused unless the principal is explicitly authorized to act for it.
    if (principal && authzid.length > 0 && authzid !== username && !principal.allowAuthzId) {
      principal = null;
    }

    if (!principal) {
      // IR Rule U-6: uniform failure, no account enumeration.
      this.emitAuthFailure(SMTP_REASON_CODES.authFailed);
      this.replyError(535, SMTP_REASON_CODES.authFailed, "Authentication failed");
      return;
    }

    this.principal = principal;
    this.authStage = "none";
    this.authUsername = null;
    this.state = "AUTHENTICATED";
    this.emit({
      type: "auth_succeeded",
      principalId: principal.id,
      sourceIp: this.sourceIp,
      correlationId: this.correlationId,
    });
    this.reply(235, "Authentication successful");
  }

  private emitAuthFailure(reason: string): void {
    // IR Rule U-5: never the username, password, or base64 blob.
    this.emit({
      type: "auth_failed",
      reason,
      sourceIp: this.sourceIp,
      correlationId: this.correlationId,
    });
  }

  private async handleMail(
    address: string | null,
    params: ReadonlyMap<string, string>,
  ): Promise<boolean> {
    const requireAuth = this.options.requireAuth !== false;
    if (requireAuth && !this.principal) {
      this.replyError(530, SMTP_REASON_CODES.authRequired, "Authentication required");
      return false;
    }

    // A new MAIL resets the prior transaction (IR Rule S-3).
    this.resetTransaction();

    if (address === null) {
      // IR Rule A-3: the null reverse path is only for authorized bounce senders.
      if (!this.principal || this.principal.allowedSenders.length > 0) {
        this.replyError(550, SMTP_REASON_CODES.policySenderNotAllowed, "Sender not allowed");
        return false;
      }
    } else if (this.principal) {
      const allowed = this.principal.allowedSenders;
      if (allowed.length > 0 && !allowed.includes(address.toLowerCase())) {
        this.replyError(550, SMTP_REASON_CODES.policySenderNotAllowed, "Sender not allowed");
        return false;
      }
    }

    const sizeParam = params.get("SIZE");
    if (sizeParam !== undefined) {
      const declared = Number.parseInt(sizeParam, 10);
      if (!Number.isFinite(declared) || declared < 0) {
        this.replyError(555, SMTP_REASON_CODES.commandSyntax, "Malformed MAIL parameters");
        return false;
      }
      // IR Rule D-6: an over-declared size is rejected early, but the actual
      // size is still enforced.
      if (declared > (this.options.maxMessageBytes ?? DEFAULTS.maxMessageBytes)) {
        this.replyError(552, SMTP_REASON_CODES.limitMessageSize, "Message size exceeds limit");
        return false;
      }
      this.declaredSize = declared;
    }

    const decision = await this.runHook("authorizeSender", {
      envelopeSender: address,
      recipient: null,
      declaredSize: this.declaredSize,
    });
    if (decision) {
      this.replyError(decision.code, decision.reason, "Sender not allowed");
      return false;
    }

    this.envelopeSender = address ?? "";
    this.state = "MAIL_RECEIVED";
    this.reply(250, "Sender OK");
    return false;
  }

  private async handleRcpt(
    address: string | null,
    params: ReadonlyMap<string, string>,
  ): Promise<boolean> {
    if (this.state !== "MAIL_RECEIVED" && this.state !== "RCPT_RECEIVED") {
      this.replyError(503, SMTP_REASON_CODES.commandOutOfSequence, "Bad sequence of commands");
      return false;
    }
    if (!address) {
      this.replyError(501, SMTP_REASON_CODES.commandSyntax, "Malformed recipient address");
      return false;
    }
    // IR Rule A-6: non-ASCII addresses need SMTPUTF8.
    if (!this.options.smtpUtf8 && isNonAsciiAddress(address)) {
      this.replyError(553, SMTP_REASON_CODES.policyRecipientNotAllowed, "Address not allowed");
      return false;
    }

    // IR Rule A-11: a repeated recipient is an idempotent no-op.
    const lower = address.toLowerCase();
    if (this.accepted.some((entry) => entry.address.toLowerCase() === lower)) {
      this.reply(250, "Recipient OK (duplicate)");
      return false;
    }

    // IR Rule A-10: the transaction recipient cap is a hard limit.
    if (this.accepted.length >= (this.options.maxRecipientsPerTransaction ?? DEFAULTS.maxRecipientsPerTransaction)) {
      this.replyError(
        552,
        SMTP_REASON_CODES.limitRecipientsPerTransaction,
        "Too many recipients",
      );
      return false;
    }

    // IR Rule A-13: unauthorized destination domains are rejected here, not
    // silently dropped.
    if (this.principal && this.principal.allowedRecipientDomains.length > 0) {
      const domain = lower.slice(lower.lastIndexOf("@") + 1);
      if (!this.principal.allowedRecipientDomains.includes(domain)) {
        this.replyError(550, SMTP_REASON_CODES.policyRecipientNotAllowed, "Recipient not allowed");
        return false;
      }
    }

    // IR Rule A-7: every recipient is evaluated independently.
    const context = { recipient: address };
    for (const hook of [
      "authorizeRecipient",
      "checkRateLimit",
      "checkSuppression",
      "checkBlocklist",
      "checkRoleAddress",
    ] as const) {
      const decision = await this.runHook(hook, context);
      if (decision) {
        this.rejected.push({ address, code: decision.code, reason: decision.reason });
        this.replyError(decision.code, decision.reason, "Recipient rejected");
        return false;
      }
    }

    this.accepted.push({ address, code: 250, reason: SMTP_REASON_CODES.accepted });
    this.state = "RCPT_RECEIVED";
    this.reply(250, "Recipient OK");
    return false;
  }

  private handleDataCommand(): boolean {
    // IR Rule A-9: DATA with zero accepted recipients is `503`.
    if (this.state !== "MAIL_RECEIVED" && this.state !== "RCPT_RECEIVED") {
      this.replyError(503, SMTP_REASON_CODES.commandOutOfSequence, "Bad sequence of commands");
      return false;
    }
    if (this.accepted.length === 0) {
      this.replyError(503, SMTP_REASON_CODES.commandOutOfSequence, "No valid recipients");
      return false;
    }
    if (
      this.accepted.length >
      (this.options.maxRecipientsPerMessage ?? DEFAULTS.maxRecipientsPerMessage)
    ) {
      this.replyError(552, SMTP_REASON_CODES.limitRecipientsPerMessage, "Too many recipients");
      return false;
    }
    if (!this.queue) {
      this.replyError(451, SMTP_REASON_CODES.storeUnavailable, "Queue unavailable");
      return false;
    }

    this.state = "DATA_RECEIVED";
    this.accumulator = new DataAccumulator(this.options.maxMessageBytes ?? DEFAULTS.maxMessageBytes);
    this.reply(354, "End data with <CR><LF>.<CR><LF>");
    return false;
  }

  private async finishData(): Promise<void> {
    const accumulator = this.accumulator;
    this.accumulator = null;
    if (!accumulator) return;

    if (accumulator.tooLarge) {
      // IR Rule D-5: `552`, and the message is not queued.
      this.resetTransaction();
      this.state = this.tlsActive ? "TLS_ACTIVE" : this.principal ? "AUTHENTICATED" : "GREETED";
      this.replyError(552, SMTP_REASON_CODES.limitMessageSize, "Message size exceeds limit");
      return;
    }

    const raw = accumulator.bytes();

    // IR Rule H-8 / M-3: shape validation.
    const parsed = parseHeaders(raw);
    if (parsed.malformed) {
      this.rejectAfterData(554, SMTP_REASON_CODES.policyMalformedMessage, "Malformed message");
      return;
    }
    if (parsed.headerCount > (this.options.maxHeaderCount ?? DEFAULTS.maxHeaderCount)) {
      this.rejectAfterData(554, SMTP_REASON_CODES.limitHeaderCount, "Too many headers");
      return;
    }
    for (const header of parsed.headers) {
      if (Buffer.byteLength(header.raw, "latin1") > (this.options.maxHeaderBytes ?? DEFAULTS.maxHeaderBytes)) {
        this.rejectAfterData(554, SMTP_REASON_CODES.limitHeaderSize, "Header too large");
        return;
      }
      // IR Rule M-8 / D-7: header injection is a policy rejection.
      if (/[\r\n]/.test(header.value.replace(/^\s+/, "")) && header.raw.includes("\r\n ")) {
        // Folding is legitimate; a bare CR/LF is not. parseHeaders already
        // splits on line boundaries, so a raw value containing CR or LF means
        // the value itself carried an embedded newline.
        if (/[\r\n]/.test(header.value)) {
          this.rejectAfterData(554, SMTP_REASON_CODES.policyHeaderInjection, "Header injection rejected");
          return;
        }
      }
    }

    // IR Rule D-8: a From or Return-Path context is required.
    const hasContext = parsed.headers.some(
      (header) => header.name === "from" || header.name === "return-path",
    );
    if (!hasContext) {
      this.rejectAfterData(554, SMTP_REASON_CODES.policyMissingContext, "Missing From context");
      return;
    }

    // IR Rule M-7: Bcc is stripped from the stored header set.
    const headers = parsed.headers.filter((header) => header.name !== "bcc");

    const context = {
      recipient: null,
      rawMessage: raw,
      headers,
      receivedSize: raw.length,
    };

    for (const hook of ["validateShape", "scoreContent"] as const) {
      const decision = await this.runHook(hook, context);
      if (decision) {
        this.rejectAfterData(decision.code, decision.reason, "Message rejected by policy");
        return;
      }
    }

    const tenantId = this.principal?.tenantId ?? "local";
    const principalId = this.principal?.id ?? "local";

    const queue = this.queue;
    if (!queue) {
      this.rejectAfterData(451, SMTP_REASON_CODES.storeUnavailable, "Queue unavailable");
      return;
    }

    let messageId: string;
    try {
      // IR Rule D-10: the durable write commits before the `250` is emitted.
      const result = await queue.enqueue({
        tenantId,
        principalId,
        correlationId: this.correlationId,
        envelopeSender: this.envelopeSender ?? "",
        recipients: this.accepted.map((entry) => entry.address),
        rejectedRecipients: this.rejected.map(
          (entry): RecipientOutcome => ({
            recipient: entry.address,
            accepted: false,
            code: entry.code,
            reason: entry.reason,
          }),
        ),
        raw,
        headers: headers as readonly SmtpHeader[],
        size: raw.length,
        receivedAt: new Date().toISOString(),
      });
      messageId = result.messageId;
    } catch {
      // IR Rule D-9 / T-23: a store failure is `451`, never `500`.
      this.resetTransaction();
      this.state = this.tlsActive ? "TLS_ACTIVE" : this.principal ? "AUTHENTICATED" : "GREETED";
      this.emit({
        type: "message_rejected",
        reason: SMTP_REASON_CODES.storeUnavailable,
        tenantId,
        principalId,
        correlationId: this.correlationId,
      });
      this.replyError(451, SMTP_REASON_CODES.storeUnavailable, "Message could not be queued");
      return;
    }

    this.emit({
      type: "message_accepted",
      messageId,
      tenantId,
      principalId,
      recipients: [
        ...this.accepted.map(
          (entry): RecipientOutcome => ({
            recipient: entry.address,
            accepted: true,
            code: entry.code,
            reason: entry.reason,
          }),
        ),
        ...this.rejected.map(
          (entry): RecipientOutcome => ({
            recipient: entry.address,
            accepted: false,
            code: entry.code,
            reason: entry.reason,
          }),
        ),
      ],
      correlationId: this.correlationId,
    });

    this.resetTransaction();
    this.state = this.tlsActive ? "TLS_ACTIVE" : this.principal ? "AUTHENTICATED" : "GREETED";
    // IR Rule D-12: the `250` carries the RailGun message ID.
    this.reply(250, `2.0.0 <${messageId}> queued`);
  }

  private rejectAfterData(code: number, reason: string, text: string): void {
    this.resetTransaction();
    this.state = this.tlsActive ? "TLS_ACTIVE" : this.principal ? "AUTHENTICATED" : "GREETED";
    this.emit({
      type: "message_rejected",
      reason,
      tenantId: this.principal?.tenantId ?? "local",
      principalId: this.principal?.id ?? "local",
      correlationId: this.correlationId,
    });
    this.replyError(code, reason, text);
  }

  private handleRset(): boolean {
    this.resetTransaction();
    this.state = this.tlsActive ? "TLS_ACTIVE" : this.principal ? "AUTHENTICATED" : "GREETED";
    this.reply(250, "OK");
    return false;
  }

  private resetTransaction(): void {
    this.envelopeSender = null;
    this.accepted = [];
    this.rejected = [];
    this.accumulator = null;
    this.declaredSize = null;
  }

  // ---------------------------------------------------------------- policy

  private policyContext(overrides: Partial<PolicyDecisionContext> = {}): PolicyDecisionContext {
    return {
      tenantId: this.principal?.tenantId ?? "local",
      principalId: this.principal?.id ?? "local",
      sourceIp: this.sourceIp,
      tls: this.tlsActive,
      envelopeSender: this.envelopeSender,
      recipient: overrides.recipient ?? null,
      declaredSize: overrides.declaredSize ?? this.declaredSize,
      receivedSize: overrides.receivedSize ?? null,
      rawMessage: overrides.rawMessage ?? null,
      headers: overrides.headers ?? [],
      correlationId: this.correlationId,
    };
  }

  /**
   * Run a policy hook. Returns `null` when the hook allows the action, or a
   * rejection descriptor when it does not.
   *
   * A hook that throws is handled per IR Rule H-6: fail-closed rejects, and
   * fail-open allows while recording a degraded reason code.
   */
  private async runHook(
    name: keyof SmtpPolicyHooks,
    overrides: Partial<PolicyDecisionContext> = {},
  ): Promise<{ code: number; reason: string } | null> {
    const hooks = this.options.policy;
    if (!hooks) return null;
    const hook = hooks[name];
    if (!hook) return null;

    const context = this.policyContext(overrides);
    let result: PolicyHookResult;
    try {
      result = await hook(context);
    } catch {
      if (this.options.policyFailClosed !== false) {
        return { code: 451, reason: SMTP_REASON_CODES.policyDegraded };
      }
      this.emit({
        type: "message_rejected",
        reason: SMTP_REASON_CODES.policyDegraded,
        tenantId: context.tenantId,
        principalId: context.principalId,
        correlationId: this.correlationId,
      });
      return null;
    }

    if (!result || typeof result !== "object" || !("action" in result)) {
      // IR Rule H-7: absence of a decision is an error, not an allow.
      if (this.options.policyFailClosed !== false) {
        return { code: 451, reason: SMTP_REASON_CODES.policyDegraded };
      }
      return null;
    }

    switch (result.action) {
      case "allow":
        return null;
      case "reject":
        return { code: result.code, reason: result.reason };
      case "defer":
        return { code: result.code, reason: result.reason };
      case "quarantine":
        // A quarantine accepts the message but flags it; the queue port owns
        // that behaviour, so the submission is not rejected here.
        return null;
      default:
        return { code: 451, reason: SMTP_REASON_CODES.policyDegraded };
    }
  }

  // --------------------------------------------------------------- limits

  private checkCommandRate(): boolean {
    const limit = this.options.maxCommandRatePerMinute ?? DEFAULTS.maxCommandRatePerMinute;
    if (limit <= 0) return true;
    const now = Date.now();
    this.commandTimestamps = this.commandTimestamps.filter((ts) => now - ts < 60_000);
    if (this.commandTimestamps.length >= limit) {
      return false;
    }
    this.commandTimestamps.push(now);
    return true;
  }

  // --------------------------------------------------------------- close

  /** Close the session and notify the transport. */
  close(reason: string): void {
    if (this.closed) return;
    this.closed = true;
    this.state = "CLOSED";
    this.emit({
      type: "session_closed",
      sourceIp: this.sourceIp,
      correlationId: this.correlationId,
      reason,
    });
    this.transport.close();
  }

  private emit(event: SmtpServerEvent): void {
    try {
      this.options.onEvent?.(event);
    } catch {
      // Event sinks must never break the protocol path.
    }
  }
}

/**
 * Decode a base64 credential blob into a UTF-8 string.
 *
 * Returns `null` when the blob is not valid base64. The decoded value is
 * never logged or echoed (IR Rule U-5).
 */
function decodeCredential(value: string): string | null {
  if (value.length === 0) return null;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null;
  try {
    const decoded = Buffer.from(value, "base64");
    if (decoded.toString("base64").replace(/=+$/, "") !== value.replace(/=+$/, "")) {
      return null;
    }
    return decoded.toString("utf8");
  } catch {
    return null;
  }
}
