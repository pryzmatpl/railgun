/* RailGun SMTP submission server — wire parser.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { SmtpHeader } from "./types.js";

/**
 * Pure parsing helpers for the RFC 5321 submission subset.
 *
 * Everything in this module is side-effect free so it can be unit-tested
 * without a socket. Rules implemented here: C-1…C-5, A-3…A-6, D-2…D-4.
 */

/** A parsed `MAIL FROM` / `RCPT TO` path plus its ESMTP parameters. */
export interface ParsedPath {
  /** `null` for the null reverse path (`<>`). */
  readonly address: string | null;
  readonly params: ReadonlyMap<string, string>;
}

/** Result of parsing a command line. */
export type ParsedCommand =
  | {
      readonly kind: "mail";
      readonly path: ParsedPath;
    }
  | {
      readonly kind: "rcpt";
      readonly path: ParsedPath;
    }
  | {
      readonly kind: "ehlo";
      readonly domain: string;
    }
  | {
      readonly kind: "helo";
      readonly domain: string;
    }
  | {
      readonly kind: "auth";
      readonly mechanism: string;
      readonly initialResponse: string | null;
    }
  | { readonly kind: "starttls" }
  | { readonly kind: "data" }
  | { readonly kind: "rset" }
  | { readonly kind: "noop" }
  | { readonly kind: "quit" }
  | { readonly kind: "unknown"; readonly verb: string };

export class SmtpParseError extends Error {
  /** SMTP reply code the parse failure maps to. */
  readonly code: number;
  /** Stable reason code (IR Rule R-3). */
  readonly reason: string;

  constructor(code: number, reason: string, message: string) {
    super(message);
    this.name = "SmtpParseError";
    this.code = code;
    this.reason = reason;
  }
}

/**
 * Split a raw command line into verb and argument text.
 *
 * The verb is matched case-insensitively (IR Rule C-2). The argument text is
 * returned verbatim — it is never lower-cased, because only the auth
 * mechanism name is case-insensitive.
 */
export function splitCommand(line: string): { verb: string; args: string } {
  const trimmed = line.replace(/^[\s]+/, "");
  const space = trimmed.indexOf(" ");
  if (space === -1) return { verb: trimmed.toUpperCase(), args: "" };
  return { verb: trimmed.slice(0, space).toUpperCase(), args: trimmed.slice(space + 1).trim() };
}

/**
 * Parse an ESMTP path (`<addr>` plus optional `KEY=VALUE` parameters).
 *
 * Handles the RFC 5321 §4.1.2 forms:
 *   - `<user@host>`
 *   - `<>` (null reverse path — `MAIL FROM` only)
 *   - `<user@host> SIZE=1234 BODY=8BITMIME`
 *   - source routes (`@a,@b:user@host`) — parsed, then rejected with `501`
 *     by the caller per IR Rule A-4.
 */
export function parsePath(args: string, allowNull: boolean): ParsedPath {
  const text = args.trim();
  if (text.length === 0) {
    throw new SmtpParseError(501, "command.syntax", "missing path");
  }

  let rest = text;
  if (rest.startsWith("<")) {
    const close = rest.indexOf(">");
    if (close === -1) {
      throw new SmtpParseError(501, "command.syntax", "unterminated path");
    }
    const inner = rest.slice(1, close);
    rest = rest.slice(close + 1).trim();
    if (rest.length > 0 && !/^[A-Za-z]/.test(rest)) {
      throw new SmtpParseError(501, "command.syntax", "malformed path parameters");
    }
    return buildPath(inner, rest, allowNull);
  }

  // Bare (non-bracketed) path — accepted by RFC 5321 but many servers reject
  // it. RailGun requires the bracketed form for MAIL/RCPT.
  throw new SmtpParseError(501, "command.syntax", "path must be angle-bracketed");
}

function buildPath(inner: string, paramText: string, allowNull: boolean): ParsedPath {
  const trimmedInner = inner.trim();

  if (trimmedInner.length === 0) {
    if (!allowNull) {
      throw new SmtpParseError(501, "command.syntax", "null reverse path not allowed here");
    }
    return { address: null, params: parseParams(paramText) };
  }

  // Source route: "@a,@b:user@host" (IR Rule A-4).
  if (trimmedInner.startsWith("@")) {
    const colon = trimmedInner.indexOf(":");
    if (colon === -1) {
      throw new SmtpParseError(501, "command.syntax", "malformed source route");
    }
    throw new SmtpParseError(501, "command.syntax", "source routes are not supported");
  }

  if (trimmedInner.includes(",")) {
    throw new SmtpParseError(501, "command.syntax", "multiple paths are not supported");
  }

  // Exactly one `@` separates the local part from the domain (A-5).
  if (trimmedInner.indexOf("@") !== trimmedInner.lastIndexOf("@")) {
    throw new SmtpParseError(501, "command.syntax", "malformed address");
  }
  const at = trimmedInner.indexOf("@");
  if (at <= 0 || at === trimmedInner.length - 1) {
    throw new SmtpParseError(501, "command.syntax", "malformed address");
  }
  const local = trimmedInner.slice(0, at);
  const domain = trimmedInner.slice(at + 1);
  if (local.length === 0 || domain.length === 0 || /\s/.test(trimmedInner)) {
    throw new SmtpParseError(501, "command.syntax", "malformed address");
  }
  if (domain.includes("..")) {
    throw new SmtpParseError(501, "command.syntax", "malformed address domain");
  }

  return { address: `${local}@${domain}`, params: parseParams(paramText) };
}

/**
 * Parse ESMTP parameters as whitespace-separated `KEY=VALUE` pairs
 * (IR Rule C-5). A malformed parameter yields `555`.
 */
export function parseParams(text: string): ReadonlyMap<string, string> {
  const params = new Map<string, string>();
  const trimmed = text.trim();
  if (trimmed.length === 0) return params;

  for (const token of trimmed.split(/\s+/)) {
    if (token.length === 0) continue;
    const eq = token.indexOf("=");
    if (eq <= 0) {
      throw new SmtpParseError(555, "command.syntax", "malformed ESMTP parameter");
    }
    const key = token.slice(0, eq).toUpperCase();
    const value = token.slice(eq + 1);
    if (!/^[A-Za-z0-9][A-Za-z0-9\-]*$/.test(key)) {
      throw new SmtpParseError(555, "command.syntax", "malformed ESMTP parameter name");
    }
    params.set(key, value);
  }
  return params;
}

/**
 * Parse a full command line into a structured command.
 *
 * @throws {SmtpParseError} with the SMTP code the failure maps to.
 */
export function parseCommand(line: string): ParsedCommand {
  const { verb, args } = splitCommand(line);

  switch (verb) {
    case "EHLO": {
      const domain = requireDomain(args);
      return { kind: "ehlo", domain };
    }
    case "HELO": {
      const domain = requireDomain(args);
      return { kind: "helo", domain };
    }
    case "STARTTLS": {
      if (args.length > 0) {
        throw new SmtpParseError(501, "command.syntax", "STARTTLS takes no arguments");
      }
      return { kind: "starttls" };
    }
    case "AUTH": {
      if (args.length === 0) {
        throw new SmtpParseError(501, "command.syntax", "AUTH requires a mechanism");
      }
      const space = args.indexOf(" ");
      const mechanism = (space === -1 ? args : args.slice(0, space)).toUpperCase();
      const initial = space === -1 ? "" : args.slice(space + 1).trim();
      return { kind: "auth", mechanism, initialResponse: initial.length > 0 ? initial : null };
    }
    case "MAIL":
      return { kind: "mail", path: parsePath(stripKeyword(args, "FROM"), true) };
    case "RCPT":
      return { kind: "rcpt", path: parsePath(stripKeyword(args, "TO"), false) };
    case "DATA": {
      if (args.length > 0) {
        throw new SmtpParseError(501, "command.syntax", "DATA takes no arguments");
      }
      return { kind: "data" };
    }
    case "RSET": {
      if (args.length > 0) {
        throw new SmtpParseError(501, "command.syntax", "RSET takes no arguments");
      }
      return { kind: "rset" };
    }
    case "NOOP": {
      if (args.length > 0) {
        throw new SmtpParseError(501, "command.syntax", "NOOP takes no arguments");
      }
      return { kind: "noop" };
    }
    case "QUIT": {
      if (args.length > 0) {
        throw new SmtpParseError(501, "command.syntax", "QUIT takes no arguments");
      }
      return { kind: "quit" };
    }
    default:
      return { kind: "unknown", verb };
  }
}

/**
 * Strip the `FROM` / `TO` keyword that follows `MAIL` / `RCPT`.
 *
 * RFC 5321 spells these commands as two words (`MAIL FROM:<path>`,
 * `RCPT TO:<path>`), so the verb splitter leaves the keyword in the argument
 * text. The keyword is case-insensitive (IR Rule C-2).
 */
function stripKeyword(args: string, keyword: string): string {
  const trimmed = args.trim();
  if (!trimmed.toUpperCase().startsWith(keyword)) {
    throw new SmtpParseError(501, "command.syntax", `missing ${keyword} keyword`);
  }
  const rest = trimmed.slice(keyword.length);
  // RFC 5321 permits `MAIL FROM:<path>` with no space after the keyword, and
  // the colon may be attached to the keyword (`FROM:<path>`). The keyword
  // must therefore be followed by whitespace, a colon, or the opening angle
  // bracket — never glued to the path itself.
  if (rest.length > 0 && !/^[\s:<]/.test(rest)) {
    throw new SmtpParseError(501, "command.syntax", `malformed ${keyword} path`);
  }
  return rest.trim().replace(/^:/, "").trim();
}

function requireDomain(args: string): string {
  const domain = args.trim();
  if (domain.length === 0) {
    throw new SmtpParseError(501, "command.syntax", "missing domain argument");
  }
  if (domain.includes(" ")) {
    throw new SmtpParseError(501, "command.syntax", "malformed domain argument");
  }
  if (!/^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$/.test(domain)) {
    throw new SmtpParseError(501, "command.syntax", "malformed domain argument");
  }
  return domain;
}

/**
 * True when the address contains non-ASCII bytes (IR Rule A-6). Such an
 * address is rejected with `553` unless `SMTPUTF8` was advertised.
 */
export function isNonAsciiAddress(address: string): boolean {
  // eslint-disable-next-line no-control-regex
  return /[^\x00-\x7F]/.test(address);
}

/** A chunk of body bytes plus whether the terminator was reached. */
export interface DataChunkResult {
  /** Unstuffed, CRLF-normalized body bytes accumulated so far. */
  readonly body: Buffer;
  /** True when the `.\r\n` terminator has been consumed. */
  readonly complete: boolean;
  /** True when the size limit was exceeded. */
  readonly tooLarge: boolean;
  /** Number of received bytes counted toward the size limit. */
  readonly received: number;
}

/**
 * Incremental DATA body accumulator implementing dot-unstuffing (IR Rule D-3)
 * and CRLF normalization (IR Rule D-4).
 *
 * Contract table (IR §4.5):
 *
 * | Wire line | Stored body line |
 * |---|---|
 * | `..hidden` | `.hidden` |
 * | `.` (alone)   | *(terminator — not stored)* |
 * | `...`         | `..` |
 * | `normal`      | `normal` |
 */
export class DataAccumulator {
  private readonly chunks: Buffer[] = [];
  private pending: Buffer = Buffer.alloc(0);
  private done = false;
  private overflow = false;
  private received = 0;

  constructor(private readonly maxBytes: number) {}

  get complete(): boolean {
    return this.done;
  }

  get tooLarge(): boolean {
    return this.overflow;
  }

  get receivedBytes(): number {
    return this.received;
  }

  /** Feed raw socket bytes. Returns `true` when the terminator was seen. */
  push(chunk: Buffer): boolean {
    if (this.done) return true;
    this.received += chunk.length;
    this.pending = this.pending.length === 0 ? chunk : Buffer.concat([this.pending, chunk]);

    // Process whole lines only; a partial trailing line stays in `pending`.
    let start = 0;
    for (;;) {
      const idx = this.pending.indexOf(0x0a, start);
      if (idx === -1) break;
      let lineEnd = idx + 1;
      let line = this.pending.subarray(start, idx);
      start = lineEnd;
      // Strip a trailing CR for terminator detection only; CRLF normalization
      // re-adds it for stored lines.
      const bare = line.length > 0 && line[line.length - 1] === 0x0d;
      const content = bare ? line.subarray(0, line.length - 1) : line;

      if (content.length === 1 && content[0] === 0x2e) {
        // Terminator: `.` alone.
        this.pending = Buffer.alloc(0);
        this.done = true;
        return true;
      }

      let stored: Buffer;
      if (content.length > 0 && content[0] === 0x2e) {
        // Dot-unstuffing: remove exactly one leading dot (IR Rule D-3).
        stored = content.subarray(1);
      } else {
        stored = content;
      }

      // CRLF normalization (IR Rule D-4).
      const normalized = Buffer.concat([stored, Buffer.from([0x0d, 0x0a])]);
      this.chunks.push(normalized);
      if (this.totalBytes() > this.maxBytes) {
        this.overflow = true;
      }
      lineEnd = lineEnd;
    }

    if (start > 0) {
      this.pending = this.pending.subarray(start);
    }
    return this.done;
  }

  /** Total stored body bytes. */
  totalBytes(): number {
    let total = 0;
    for (const chunk of this.chunks) total += chunk.length;
    return total;
  }

  /** The accumulated, canonical body bytes. */
  bytes(): Buffer {
    if (this.chunks.length === 0) return Buffer.alloc(0);
    return Buffer.concat(this.chunks);
  }
}

/**
 * Parse the captured raw message into a header list (IR Rules M-1, M-2).
 *
 * The header block is the contiguous run of lines before the first empty line.
 * A line starting with whitespace continues the previous header (folding).
 */
export function parseHeaders(raw: Buffer): SmtpHeaderParseResult {
  const text = raw.toString("latin1");
  const lines = text.split(/\r\n|\n|\r/);
  const headers: SmtpHeader[] = [];
  let current: { name: string; value: string; raw: string } | null = null;
  let sawBlank = false;
  let headerCount = 0;

  for (const line of lines) {
    if (line.length === 0) {
      sawBlank = true;
      break;
    }
    if (/^[ \t]/.test(line)) {
      if (current) {
        current.value += ` ${line.trim()}`;
        current.raw += `\r\n${line}`;
      }
      continue;
    }
    const colon = line.indexOf(":");
    if (colon <= 0) {
      // A header line without a colon is malformed; the caller rejects it.
      return { headers, malformed: true, headerCount };
    }
    if (current) {
      headers.push({ name: current.name, value: current.value, raw: current.raw });
    }
    headerCount += 1;
    current = {
      name: line.slice(0, colon).trim().toLowerCase(),
      value: line.slice(colon + 1).trim(),
      raw: line,
    };
  }
  if (current && !sawBlank) {
    headers.push({ name: current.name, value: current.value, raw: current.raw });
  }
  if (current && sawBlank) {
    headers.push({ name: current.name, value: current.value, raw: current.raw });
  }

  return { headers, malformed: false, headerCount };
}

export interface SmtpHeaderParseResult {
  readonly headers: Array<{ name: string; value: string; raw: string }>;
  readonly malformed: boolean;
  readonly headerCount: number;
}
