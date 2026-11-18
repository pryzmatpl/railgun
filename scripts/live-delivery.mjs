#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The opt-in live delivery run (T5).
 *
 * The script sends exactly one message to exactly one explicitly approved
 * recipient through an operator-configured SMTP relay, using credentials that
 * exist only in the environment. It then proves that the credential never
 * reached stdout, stderr, the audit log or the working tree.
 *
 * Preconditions (all fail closed, before any socket is opened):
 *
 *   - `RAILGUN_LIVE=1`
 *   - `RAILGUN_LIVE_SMTP_PASSWORD` — the credential, environment-only
 *   - `RAILGUN_LIVE_APPROVED_RECIPIENT` — one approved recipient address
 *   - `RAILGUN_LIVE_SMTP_HOST` — the relay host
 *   - `RAILGUN_LIVE_SMTP_PORT` — the relay port (default 587)
 *   - `RAILGUN_LIVE_SMTP_USERNAME` — the relay username (optional)
 *   - `RAILGUN_LIVE_FROM` — the envelope sender (optional, defaults to the
 *     approved recipient's domain)
 *
 * The script never prints the credential. Every artefact it writes is passed
 * through the redaction function first, and the run finishes with a
 * zero-match scan over the source tree, the log file and the audit file.
 *
 * Contract: `docs/design/481de2b7-e002-4cdc-95e0-0adc9068e2c4.md` §4.1-§4.3.
 */

import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import tls from "node:tls";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const { evaluateLiveGate, redactSecret, scanForSecrets } = await import(
  path.join(packageRoot, "dist", "verification", "index.js")
);

/** The environment the gate reads. */
const environment = process.env;

/** Run the gate; refuse to continue when it denies the run. */
let decision;
try {
  decision = evaluateLiveGate(environment);
} catch (error) {
  // The gate error names the failed checks only — never a credential.
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.stderr.write("The live delivery run was refused. No connection was opened.\n");
  process.exit(2);
}

const credential = process.env.RAILGUN_LIVE_SMTP_PASSWORD ?? "";
const recipient = decision.recipient ?? "";
const host = process.env.RAILGUN_LIVE_SMTP_HOST ?? "";
const port = Number.parseInt(process.env.RAILGUN_LIVE_SMTP_PORT ?? "587", 10);
const username = process.env.RAILGUN_LIVE_SMTP_USERNAME ?? "";
const from =
  process.env.RAILGUN_LIVE_FROM ?? `${recipient.split("@")[1] ?? "example.com"}@example.com`;
const subject = process.env.RAILGUN_LIVE_SUBJECT ?? "RailGun live delivery check";
const body =
  process.env.RAILGUN_LIVE_BODY ??
  "RailGun live delivery check. This message was sent by the opt-in live gate.";

if (!host || !Number.isInteger(port) || port <= 0) {
  process.stderr.write(
    "RAILGUN_LIVE_SMTP_HOST and a valid RAILGUN_LIVE_SMTP_PORT are required.\n",
  );
  process.exit(2);
}

/** The working directory for the run's artefacts. */
const workDir = mkdtempSync(path.join(tmpdir(), "railgun-live-"));
const logPath = path.join(workDir, "live.log");
const auditPath = path.join(workDir, "audit.ndjson");

/** Write an artefact through the redactor so a credential can never be stored. */
function writeRedacted(target, content) {
  writeFileSync(target, redactSecret(content, credential), { mode: 0o600 });
}

/** The sanitized log lines of this run. */
const logLines = [];

/** Record a log line, redacted. */
function log(message) {
  logLines.push(redactSecret(message, credential));
}

/**
 * A minimal SMTP client for the live run.
 *
 * It speaks enough SMTP to authenticate and deliver one message, and it only
 * ever sends the credential after the session is encrypted.
 */
class LiveSmtpSession {
  constructor(options) {
    this.options = options;
    this.socket = null;
    this.buffer = "";
    this.pending = null;
    this.failure = null;
  }

  async connect() {
    const socket = net.connect({ host: this.options.host, port: this.options.port });
    socket.setTimeout(this.options.timeoutMs);
    await new Promise((resolve, reject) => {
      const onError = (error) => {
        socket.destroy();
        reject(error);
      };
      socket.once("error", onError);
      socket.once("timeout", () => {
        socket.destroy();
        reject(new Error("The live SMTP connection timed out"));
      });
      socket.once("connect", () => {
        socket.removeListener("error", onError);
        socket.setTimeout(0);
        socket.on("data", (chunk) => this.onData(chunk));
        socket.on("error", (error) => this.onFailure(error));
        socket.on("close", () => this.onFailure(new Error("The live SMTP connection closed")));
        resolve();
      });
    });
    this.socket = socket;
    const greeting = await this.readLine();
    if (!greeting.startsWith("220")) {
      throw new Error(`Unexpected SMTP greeting: ${greeting.slice(0, 32)}`);
    }
  }

  async startTls() {
    const reply = await this.command("STARTTLS");
    if (!reply.startsWith("220")) throw new Error("The live relay refused STARTTLS");
    const socket = this.socket;
    if (!socket) throw new Error("The live SMTP session is not connected");
    const secure = tls.connect(
      {
        socket,
        servername: this.options.host,
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
      },
      () => {
        /* the secureConnect callback resolves the handshake promise */
      },
    );
    await new Promise((resolve, reject) => {
      secure.once("secureConnect", () => resolve());
      secure.once("error", reject);
    });
    secure.setTimeout(0);
    secure.on("data", (chunk) => this.onData(chunk));
    secure.on("error", (error) => this.onFailure(error));
    secure.on("close", () => this.onFailure(new Error("The live SMTP connection closed")));
    this.socket = secure;
    this.buffer = "";
  }

  async command(verb, args = "") {
    const socket = this.socket;
    if (!socket) throw new Error("The live SMTP session is not connected");
    const line = args ? `${verb} ${args}` : verb;
    const reply = this.readLine();
    socket.write(`${line}\r\n`);
    return reply;
  }

  async data(payload) {
    const socket = this.socket;
    if (!socket) throw new Error("The live SMTP session is not connected");
    const reply = this.readLine();
    const stuffed = payload
      .split("\r\n")
      .map((line) => (line.startsWith(".") ? `.${line}` : line))
      .join("\r\n");
    socket.write(`${stuffed}\r\n.\r\n`);
    return reply;
  }

  async quit() {
    try {
      await this.command("QUIT");
    } catch {
      /* the peer may hang up first; that is not an error */
    }
    this.socket?.destroy();
    this.socket = null;
  }

  onData(chunk) {
    this.buffer += chunk.toString("utf8");
    this.drain();
  }

  drain() {
    if (!this.pending) return;
    const index = this.buffer.indexOf("\r\n");
    if (index === -1) return;
    const line = this.buffer.slice(0, index);
    this.buffer = this.buffer.slice(index + 2);
    const resolve = this.pending;
    this.pending = null;
    resolve(line);
  }

  onFailure(error) {
    if (this.failure) return;
    this.failure = error;
    const resolve = this.pending;
    this.pending = null;
    resolve?.(`421 ${error.message}`);
  }

  readLine() {
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        reject(new Error("The live SMTP command timed out"));
      }, 30_000);
      if (typeof timer.unref === "function") timer.unref();
      this.pending = (line) => {
        clearTimeout(timer);
        resolve(line);
      };
      this.drain();
    });
  }
}

/** The result of the live run. */
const result = {
  status: "failed",
  smtpCode: null,
  recipientHash: "",
  reason: undefined,
};

try {
  result.recipientHash = createHash("sha256").update(recipient).digest("hex").slice(0, 16);

  const session = new LiveSmtpSession({ host, port, timeoutMs: 20_000 });
  await session.connect();
  log(`connected to ${host}:${port}`);
  await session.startTls();
  log("TLS established");
  const ehlo = await session.command("EHLO", "railgun.live.check");
  log(`EHLO reply: ${ehlo.slice(0, 64)}`);

  if (username) {
    const encoded = Buffer.from(`\0${username}\0${credential}`, "utf8").toString("base64");
    const authReply = await session.command("AUTH", `PLAIN ${encoded}`);
    if (!authReply.startsWith("235")) {
      throw new Error(`The live relay refused authentication (${authReply.slice(0, 32)})`);
    }
    log("authentication accepted");
  }

  const mailReply = await session.command("MAIL", `FROM:<${from}>`);
  if (!mailReply.startsWith("250")) {
    throw new Error(`MAIL FROM was refused (${mailReply.slice(0, 32)})`);
  }
  const rcptReply = await session.command("RCPT", `TO:<${recipient}>`);
  if (!rcptReply.startsWith("250")) {
    throw new Error(`RCPT TO was refused (${rcptReply.slice(0, 32)})`);
  }
  const dataReply = await session.command("DATA");
  if (!dataReply.startsWith("354")) {
    throw new Error(`DATA was refused (${dataReply.slice(0, 32)})`);
  }
  const finalReply = await session.data(
    `From: ${from}\r\nTo: ${recipient}\r\nSubject: ${subject}\r\nMessage-ID: <live-${Date.now()}@railgun.local>\r\n\r\n${body}\r\n`,
  );
  const code = Number.parseInt(finalReply.slice(0, 3), 10);
  result.smtpCode = Number.isInteger(code) ? code : null;
  if (!finalReply.startsWith("250")) {
    throw new Error(`The live relay refused the message (${finalReply.slice(0, 32)})`);
  }
  result.status = "sent";
  await session.quit();
} catch (error) {
  result.reason = error instanceof Error ? error.message : String(error);
  log(`live run failed: ${result.reason}`);
} finally {
  writeRedacted(logPath, `${logLines.join("\n")}\n`);
  writeRedacted(
    auditPath,
    `${JSON.stringify({
      action: "live_delivery_check",
      status: result.status,
      smtp_code: result.smtpCode,
      recipient_hash: result.recipientHash,
      at: new Date().toISOString(),
    })}\n`,
  );
}

/* -------------------------------------------------------------------------- */
/* Credential-hygiene proof                                                    */
/* -------------------------------------------------------------------------- */

const sourceScan = scanForSecrets({
  root: path.join(packageRoot, "src"),
  secret: credential,
  ignoredDirectories: ["node_modules", ".git", "dist", "data", "coverage"],
});

const scriptScan = scanForSecrets({
  root: path.join(packageRoot, "scripts"),
  secret: credential,
  ignoredDirectories: [],
});

const logScan = scanForSecrets({
  root: workDir,
  secret: credential,
  ignoredDirectories: [],
});

const sourceMatches = sourceScan.matches + scriptScan.matches;

/** The sanitized evidence report. */
const evidence = {
  status: result.status,
  smtp_code: result.smtpCode,
  recipient_hash: result.recipientHash,
  source_scan_matches: sourceMatches,
  artefact_scan_matches: logScan.matches,
  log_scan_matches: logScan.matches,
  source_leak: sourceMatches > 0,
  reason: result.reason ?? null,
};

writeRedacted(path.join(workDir, "evidence.json"), `${JSON.stringify(evidence, null, 2)}\n`);

process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);

if (sourceMatches > 0 || logScan.matches > 0) {
  process.stderr.write(
    "Credential hygiene check failed: the credential was observed in an artefact. " +
      "Rotate it before continuing.\n",
  );
  rmSync(workDir, { recursive: true, force: true });
  process.exit(3);
}

if (result.status !== "sent") {
  rmSync(workDir, { recursive: true, force: true });
  process.exit(1);
}

rmSync(workDir, { recursive: true, force: true });
process.exit(0);
