// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// DKIM canonicalization (RFC 6376 §3.4.2, §3.4.3).
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §7.1.4 and
// verification obligation V-2.
//
// Pure module — no runtime imports.

/** Header canonicalization algorithms (IR R-7.1.4). */
export type HeaderCanonicalization = "relaxed" | "simple";

/** Body canonicalization algorithms (IR R-7.1.4). */
export type BodyCanonicalization = "relaxed" | "simple";

/** The canonicalization pair used for a signature. */
export interface Canonicalization {
  readonly header: HeaderCanonicalization;
  readonly body: BodyCanonicalization;
}

/** The default canonicalization (IR R-7.1.4). */
export const DEFAULT_CANONICALIZATION: Canonicalization = Object.freeze({
  header: "relaxed",
  body: "relaxed",
});

/** One raw header, split into name and unfolded value. */
export interface RawHeader {
  readonly name: string;
  readonly value: string;
}

/**
 * Parses a raw header block into individual headers, preserving the order
 * and the original spelling of the names.
 *
 * Unfolding (removing the CRLF plus trailing whitespace of a folded header)
 * happens here so that both the signer and the verifier see identical input.
 */
export function parseHeaderBlock(raw: string): RawHeader[] {
  const headers: RawHeader[] = [];
  const lines = raw.split(/\r?\n/);
  let current: string[] = [];
  const flush = (): void => {
    if (current.length === 0) {
      return;
    }
    // RFC 5322 §2.2.3 unfolding: remove the CRLF, keep the folding whitespace.
    const joined = current.join("").replace(/\r?\n[ \t]+/g, "");
    const idx = joined.indexOf(":");
    if (idx > 0) {
      headers.push({
        name: joined.slice(0, idx),
        value: joined.slice(idx + 1).trim(),
      });
    }
    current = [];
  };
  for (const line of lines) {
    if (line.length === 0) {
      break; // end of the header block
    }
    if (/^[ \t]/.test(line) && current.length > 0) {
      current.push(line);
      continue;
    }
    flush();
    current = [line];
  }
  flush();
  return headers;
}

/**
 * Applies relaxed header canonicalization to one header (RFC 6376 §3.4.2):
 * lowercase the name, unfold the value, collapse runs of whitespace, and
 * strip the leading and trailing whitespace of the value.
 */
export function canonicalizeRelaxedHeader(header: RawHeader): string {
  const name = header.name.toLowerCase().trim();
  const value = header.value
    .replace(/\r?\n[ \t]+/g, "")
    .replace(/[ \t]+/g, " ")
    .trim();
  return `${name}:${value}`;
}

/**
 * Applies simple header canonicalization (RFC 6376 §3.4.2): the header is
 * left exactly as it appeared, with only the line terminator removed.
 */
export function canonicalizeSimpleHeader(header: RawHeader): string {
  return `${header.name}:${header.value}`;
}

/** Canonicalizes one header according to the mode. */
export function canonicalizeHeader(
  header: RawHeader,
  mode: HeaderCanonicalization,
): string {
  return mode === "simple"
    ? canonicalizeSimpleHeader(header)
    : canonicalizeRelaxedHeader(header);
}

/**
 * Canonicalizes a header set. The order of the headers is preserved, and
 * repeated header names are signed bottom-up (the last occurrence first),
 * as RFC 6376 §3.5 requires.
 */
export function canonicalizeHeaderSet(
  headers: readonly RawHeader[],
  mode: HeaderCanonicalization,
): string {
  const canonical = headers.map((h) => canonicalizeHeader(h, mode));
  // Sign repeated headers bottom-up.
  const seen = new Set<string>();
  const ordered: string[] = [];
  for (let i = canonical.length - 1; i >= 0; i--) {
    const entry = canonical[i];
    if (entry === undefined) {
      continue;
    }
    const name = entry.slice(0, entry.indexOf(":"));
    if (seen.has(name)) {
      continue;
    }
    seen.add(name);
    ordered.unshift(entry);
  }
  return ordered.join("\r\n");
}

/**
 * Applies relaxed body canonicalization (RFC 6376 §3.4.3): strip trailing
 * whitespace from every line, reduce all line endings to CRLF, and ensure the
 * body ends with exactly one CRLF. An empty body canonicalizes to a single
 * CRLF.
 */
export function canonicalizeRelaxedBody(body: string): string {
  if (body.length === 0) {
    return "\r\n";
  }
  const lines = body.split(/\r?\n/);
  const trimmed = lines.map((line) => line.replace(/[ \t]+$/, ""));
  // A trailing empty element from a final newline is dropped; the canonical
  // form always ends with exactly one CRLF.
  while (trimmed.length > 0 && trimmed[trimmed.length - 1] === "") {
    trimmed.pop();
  }
  return `${trimmed.join("\r\n")}\r\n`;
}

/**
 * Applies simple body canonicalization (RFC 6376 §3.4.3): the body is left
 * byte-for-byte as it appeared, minus any trailing empty line.
 */
export function canonicalizeSimpleBody(body: string): string {
  if (body.length === 0) {
  return "";
  }
  const lines = body.split(/\r?\n/);
  while (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines.join("\r\n");
}

/** Canonicalizes the body according to the mode. */
export function canonicalizeBody(body: string, mode: BodyCanonicalization): string {
  return mode === "simple" ? canonicalizeSimpleBody(body) : canonicalizeRelaxedBody(body);
}
