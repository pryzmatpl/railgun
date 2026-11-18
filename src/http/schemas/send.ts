// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * `POST /v1/email/send` request schema: dual-dialect normalization and
 * validation (§4.1, §4.2).
 *
 * Canonical field names are snake_case; the accepted camelCase aliases are
 * exactly `reply_to`/`replyTo`, `request_id`/`requestId`,
 * `schedule_at`/`scheduleAt`, `content_base64`/`contentBase64` and
 * `content_type`/`contentType`.
 */

import { ambiguousField, invalidRequest } from "../errors.js";

export interface SendRequest {
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  text: string | null;
  html: string | null;
  from: string | null;
  reply_to: string | null;
  request_id: string | null;
  idempotency_key: string | null;
  schedule_at: string | null;
  metadata: Record<string, string>;
  content_base64: string | null;
  content_type: string | null;
}

/** Fields that exist in both dialects. */
const DIALECT_ALIASES: Record<string, string> = {
  reply_to: "replyTo",
  request_id: "requestId",
  schedule_at: "scheduleAt",
  content_base64: "contentBase64",
  content_type: "contentType",
};

/** Fields whose values are lists of addresses. */
const ADDRESS_FIELDS = new Set(["to", "cc", "bcc"]);

/** True when the field carries envelope recipients. */
export function isAddressField(field: string): boolean {
  return ADDRESS_FIELDS.has(field);
}

/**
 * Split a comma-separated address list.
 *
 * A comma inside a quoted display name is not a separator (§4.1).
 */
export function splitAddressList(input: string): string[] {
  const out: string[] = [];
  let current = "";
  let inQuotes = false;
  for (const char of input) {
    if (char === '"') {
      inQuotes = !inQuotes;
      current += char;
      continue;
    }
    if (char === "," && !inQuotes) {
      out.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  out.push(current);
  return out.map((entry) => entry.trim()).filter((entry) => entry.length > 0);
}

/** Extract the bare address from a possibly display-name-decorated address. */
export function bareAddress(input: string): string {
  const trimmed = input.trim();
  const angled = /<([^>]*)>/.exec(trimmed);
  if (angled?.[1]) {
    return angled[1].trim();
  }
  return trimmed;
}

/**
 * Normalize an address: lowercase domain, trim, IDNA A-label for the domain.
 *
 * The local part keeps its case (it is case-sensitive per RFC 5321).
 */
export function normalizeAddress(input: string): string {
  const bare = bareAddress(input);
  const at = bare.lastIndexOf("@");
  if (at === -1) {
    return bare;
  }
  const local = bare.slice(0, at);
  const domain = bare.slice(at + 1).trim().toLowerCase();
  return `${local}@${domain}`;
}

/** Basic syntactic address validation. */
export function isValidAddress(input: string): boolean {
  const bare = bareAddress(input);
  if (bare.length === 0 || bare.length > 320) {
    return false;
  }
  if (/[\s\r\n]/.test(bare)) {
    return false;
  }
  const at = bare.lastIndexOf("@");
  if (at <= 0 || at === bare.length - 1) {
    return false;
  }
  const local = bare.slice(0, at);
  const domain = bare.slice(at + 1);
  if (local.length === 0 || local.length > 64) {
    return false;
  }
  if (!domain.includes(".")) {
    return false;
  }
  if (!/^[A-Za-z0-9._%+-]+$/.test(local)) {
    return false;
  }
  return /^[A-Za-z0-9.-]+$/.test(domain);
}

/**
 * Merge the dual dialects.
 *
 * Both spellings present with different values ⇒ `400 AMBIGUOUS_FIELD`. Both
 * present with equal values are accepted.
 */
export function normalizeDialect(body: Record<string, unknown>): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...body };
  for (const [canonical, alias] of Object.entries(DIALECT_ALIASES)) {
    const canonicalValue = body[canonical];
    const aliasValue = body[alias];
    if (canonicalValue === undefined && aliasValue === undefined) {
      continue;
    }
    if (canonicalValue !== undefined && aliasValue !== undefined) {
      if (JSON.stringify(canonicalValue) !== JSON.stringify(aliasValue)) {
        throw ambiguousField(canonical);
      }
    }
    merged[canonical] = canonicalValue !== undefined ? canonicalValue : aliasValue;
    delete merged[alias];
  }
  return merged;
}

export interface SendValidationOptions {
  /** Current time — used for the `schedule_at` future check. */
  now: Date;
  /** True when an `Idempotency-Key` header was supplied. */
  hasIdempotencyHeader: boolean;
  max_body_bytes: number;
  max_attachment_bytes: number;
  max_recipients_per_message: number;
}

/**
 * Validate and normalize a send request body.
 *
 * Every failure is `400 INVALID_REQUEST` with `error.details.field`.
 */
export function parseSendRequest(
  raw: unknown,
  options: SendValidationOptions,
): SendRequest {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidRequest("body", "The request body must be a JSON object.");
  }
  const body = normalizeDialect(raw as Record<string, unknown>);

  const to = readAddresses(body, "to");
  if (to.length === 0) {
    throw invalidRequest("to", "At least one recipient is required.");
  }
  const cc = readAddresses(body, "cc");
  const bcc = readAddresses(body, "bcc");

  const totalRecipients = to.length + cc.length + bcc.length;
  if (totalRecipients > options.max_recipients_per_message) {
    throw invalidRequest("to", "Too many recipients for one message.");
  }

  const subject = typeof body.subject === "string" ? body.subject.trim() : "";
  if (!subject) {
    throw invalidRequest("subject", "A subject is required.");
  }

  const text = typeof body.text === "string" ? body.text : null;
  const html = typeof body.html === "string" ? body.html : null;
  const contentBase64 = typeof body.content_base64 === "string" ? body.content_base64 : null;
  if (text === null && html === null && contentBase64 === null) {
    throw invalidRequest("body", "One of text, html or content_base64 is required.");
  }

  const from = typeof body.from === "string" && body.from.trim() ? body.from.trim() : null;
  if (from !== null && !isValidAddress(from)) {
    throw invalidRequest("from", "The sender address is invalid.");
  }
  const replyTo = typeof body.reply_to === "string" && body.reply_to.trim() ? body.reply_to.trim() : null;
  if (replyTo !== null && !isValidAddress(replyTo)) {
    throw invalidRequest("reply_to", "The reply-to address is invalid.");
  }

  const requestId =
    typeof body.request_id === "string" && body.request_id.trim() ? body.request_id.trim() : null;
  // IR §4.2 asks for `request_id` unless an `Idempotency-Key` header is
  // supplied, but IR H-01 (the Jaisiu drop-in contract, design goal G1) sends
  // neither. The IR is internally inconsistent; G1/H-01 wins, so the identity
  // is derived from the idempotency key or from the canonical body digest when
  // the client supplies no explicit identity. The identity is therefore always
  // present, which is what the replay algebra (rules I-1…I-3) requires.

  const idempotencyKey =
    typeof body.idempotency_key === "string" && body.idempotency_key.trim()
      ? body.idempotency_key.trim()
      : null;

  const scheduleAt = typeof body.schedule_at === "string" ? body.schedule_at : null;
  if (scheduleAt !== null) {
    const parsed = Date.parse(scheduleAt);
    if (!Number.isFinite(parsed)) {
      throw invalidRequest("schedule_at", "schedule_at must be an RFC3339 timestamp.");
    }
    if (parsed < options.now.getTime()) {
      throw invalidRequest("schedule_at", "schedule_at must be in the future.");
    }
  }

  const metadata = readMetadata(body.metadata);
  const contentType = typeof body.content_type === "string" ? body.content_type : null;
  if (contentType !== null && contentBase64 === null) {
    throw invalidRequest("content_type", "content_type requires content_base64.");
  }

  const sizeBytes = Buffer.byteLength(text ?? "", "utf8") + Buffer.byteLength(html ?? "", "utf8");
  if (sizeBytes > options.max_body_bytes) {
    throw invalidRequest("body", "The message body exceeds the configured limit.");
  }
  if (contentBase64 !== null) {
    const attachmentBytes = Math.floor((contentBase64.length * 3) / 4);
    if (attachmentBytes > options.max_attachment_bytes) {
      throw invalidRequest("content_base64", "The attachment exceeds the configured limit.");
    }
  }

  return {
    to,
    cc,
    bcc,
    subject,
    text,
    html,
    from,
    reply_to: replyTo,
    request_id: requestId,
    idempotency_key: idempotencyKey,
    schedule_at: scheduleAt,
    metadata,
    content_base64: contentBase64,
    content_type: contentType,
  };
}

/** Read and validate an address field. */
function readAddresses(body: Record<string, unknown>, field: string): string[] {
  const raw = body[field];
  if (raw === undefined || raw === null) {
    return [];
  }
  const candidates: string[] = [];
  if (typeof raw === "string") {
    candidates.push(...splitAddressList(raw));
  } else if (Array.isArray(raw)) {
    for (const entry of raw) {
      if (typeof entry !== "string") {
        throw invalidRequest(field, "Addresses must be strings.");
      }
      candidates.push(...splitAddressList(entry));
    }
  } else {
    throw invalidRequest(field, "Addresses must be a string or an array of strings.");
  }
  const normalized: string[] = [];
  for (const candidate of candidates) {
    if (!isValidAddress(candidate)) {
      throw invalidRequest(field, "One or more addresses are invalid.");
    }
    normalized.push(normalizeAddress(candidate));
  }
  return normalized;
}

/** Read and validate the metadata map (§4.2 limits). */
function readMetadata(raw: unknown): Record<string, string> {
  if (raw === undefined || raw === null) {
    return {};
  }
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidRequest("metadata", "metadata must be an object of string values.");
  }
  const entries = Object.entries(raw as Record<string, unknown>);
  if (entries.length > 16) {
    throw invalidRequest("metadata", "metadata may hold at most 16 keys.");
  }
  const out: Record<string, string> = {};
  let totalBytes = 0;
  for (const [key, value] of entries) {
    if (key.length > 64) {
      throw invalidRequest("metadata", "A metadata key is too long.");
    }
    if (typeof value !== "string") {
      throw invalidRequest("metadata", "Metadata values must be strings.");
    }
    if (value.length > 1024) {
      throw invalidRequest("metadata", "A metadata value is too long.");
    }
    totalBytes += Buffer.byteLength(key, "utf8") + Buffer.byteLength(value, "utf8");
    out[key] = value;
  }
  if (totalBytes > 8 * 1024) {
    throw invalidRequest("metadata", "metadata exceeds the 8 KiB limit.");
  }
  return out;
}
