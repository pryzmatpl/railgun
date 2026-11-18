// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * MCP tool input schemas and canonical result envelopes (IR §3–§6).
 *
 * The `email_send` input is a strict superset of the frozen Jaisiu schema:
 * it accepts every Jaisiu field unchanged (`to`, `subject`, `text`, `html`,
 * `from`, `replyTo`, `cc`, `bcc`, `requestId`) plus the bounded `metadata`
 * extension. Unknown properties are rejected so typos surface instead of
 * being silently ignored.
 */

import { z } from "zod";

import { RailGunError } from "./errors.js";

export const DEFAULT_MAX_SUBJECT_BYTES = 998;
export const DEFAULT_MAX_REQUEST_ID_LENGTH = 128;
export const DEFAULT_MAX_RECIPIENTS = 50;
export const DEFAULT_MAX_MESSAGE_BYTES = 10 * 1024 * 1024;
export const DEFAULT_MAX_METADATA_KEYS = 32;
export const DEFAULT_MAX_METADATA_KEY_LENGTH = 64;
export const DEFAULT_MAX_METADATA_VALUE_LENGTH = 256;
export const DEFAULT_MAX_METADATA_TOTAL_BYTES = 4 * 1024;
export const DEFAULT_MAX_BOUNCE_LIMIT = 200;
export const DEFAULT_BOUNCE_LIMIT = 50;

/** Characters that must never appear in an address or subject line. */
const INJECTION_CHARS = /[\r\n\0]/;

/**
 * Pragmatic address syntax check. Deliberately permissive about the local
 * part (RFC 5322 allows quoted strings and comments) but strict about the
 * obvious breakage: exactly one `@`, a non-empty local part, and a dotted
 * domain with a valid TLD-ish label set.
 */
const ADDRESS_PATTERN = /^[^\s@<>()[\],;:\\"]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/;

export interface SendToolLimits {
  readonly maxSubjectBytes: number;
  readonly maxRequestIdLength: number;
  readonly maxRecipients: number;
  readonly maxMessageBytes: number;
  readonly maxMetadataKeys: number;
  readonly maxMetadataKeyLength: number;
  readonly maxMetadataValueLength: number;
  readonly maxMetadataTotalBytes: number;
}

export const DEFAULT_SEND_LIMITS: SendToolLimits = {
  maxSubjectBytes: DEFAULT_MAX_SUBJECT_BYTES,
  maxRequestIdLength: DEFAULT_MAX_REQUEST_ID_LENGTH,
  maxRecipients: DEFAULT_MAX_RECIPIENTS,
  maxMessageBytes: DEFAULT_MAX_MESSAGE_BYTES,
  maxMetadataKeys: DEFAULT_MAX_METADATA_KEYS,
  maxMetadataKeyLength: DEFAULT_MAX_METADATA_KEY_LENGTH,
  maxMetadataValueLength: DEFAULT_MAX_METADATA_VALUE_LENGTH,
  maxMetadataTotalBytes: DEFAULT_MAX_METADATA_TOTAL_BYTES,
};

function validationError(message: string, field: string): RailGunError {
  return new RailGunError("VALIDATION_FAILED", message, { field });
}

/**
 * Split a `string | string[]` recipient field into individual addresses.
 * A single string may itself be a comma-separated list.
 */
export function splitAddresses(value: string | readonly string[]): string[] {
  const raw = Array.isArray(value) ? value : [value as string];
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== "string") {
      throw validationError("Address entries must be strings.", "to");
    }
    for (const part of entry.split(",")) {
      const trimmed = part.trim();
      if (trimmed.length > 0) out.push(trimmed);
    }
  }
  return out;
}

export interface NormalizedAddress {
  readonly address: string;
  /** Lower-cased form used for de-duplication and comparison. */
  readonly key: string;
}

/**
 * Validate one address field. Rejects empty values, malformed addresses and
 * header-injection characters.
 */
export function validateAddressField(
  value: string | readonly string[] | undefined,
  field: string,
): NormalizedAddress[] {
  if (value === undefined) return [];
  if (typeof value !== "string" && !Array.isArray(value)) {
    throw validationError(`Field "${field}" must be a string or an array of strings.`, field);
  }
  const parts = splitAddresses(value);
  if (parts.length === 0) {
    throw validationError(`Field "${field}" must contain at least one address.`, field);
  }
  return parts.map((address) => {
    if (INJECTION_CHARS.test(address)) {
      throw validationError(
        `Field "${field}" contains characters that are not allowed in an address.`,
        field,
      );
    }
    if (!ADDRESS_PATTERN.test(address)) {
      throw validationError(`Field "${field}" contains an invalid address.`, field);
    }
    return { address, key: address.toLowerCase() };
  });
}

/** Collapse duplicates case-insensitively, preserving first-seen order. */
export function dedupeAddresses(addresses: readonly NormalizedAddress[]): NormalizedAddress[] {
  const seen = new Set<string>();
  const out: NormalizedAddress[] = [];
  for (const entry of addresses) {
    if (seen.has(entry.key)) continue;
    seen.add(entry.key);
    out.push(entry);
  }
  return out;
}

export const emailSendInputSchema = z
  .object({
    to: z.union([z.string(), z.array(z.string())]),
    subject: z.string(),
    text: z.string().optional(),
    html: z.string().optional(),
    from: z.string().optional(),
    replyTo: z.string().optional(),
    cc: z.union([z.string(), z.array(z.string())]).optional(),
    bcc: z.union([z.string(), z.array(z.string())]).optional(),
    requestId: z.string(),
    metadata: z.record(z.string(), z.string()).optional(),
  })
  .strict();

export const emailStatusInputSchema = z
  .object({
    id: z.string().optional(),
    requestId: z.string().optional(),
    includeBody: z.boolean().optional(),
  })
  .strict()
  .refine((value) => Boolean(value.id) !== Boolean(value.requestId), {
    message: "Exactly one of id or requestId must be supplied.",
  });

export const emailBouncesInputSchema = z
  .object({
    limit: z.number().int().positive().optional(),
    cursor: z.string().optional(),
    since: z.string().optional(),
    until: z.string().optional(),
    recipientHash: z.string().optional(),
    reason: z.string().optional(),
  })
  .strict();

export const emailStatsInputSchema = z
  .object({
    from: z.string().optional(),
    to: z.string().optional(),
    groupBy: z.enum(["none", "day", "domain"]).optional(),
  })
  .strict();

export interface EmailSendInput {
  readonly to: string | string[];
  readonly subject: string;
  readonly text?: string;
  readonly html?: string;
  readonly from?: string;
  readonly replyTo?: string;
  readonly cc?: string | string[];
  readonly bcc?: string | string[];
  readonly requestId: string;
  readonly metadata?: Record<string, string>;
}

export interface NormalizedSendInput {
  readonly to: readonly string[];
  readonly cc: readonly string[];
  readonly bcc: readonly string[];
  readonly subject: string;
  readonly text?: string;
  readonly html?: string;
  readonly from?: string;
  readonly replyTo?: string;
  readonly requestId: string;
  readonly metadata?: Readonly<Record<string, string>>;
}

/**
 * Validate and normalize an `email_send` payload.
 *
 * Validation happens before policy, rate limiting, idempotency reservation,
 * audit and queueing — a validation failure creates no message and performs
 * no SMTP or DNS activity (IR §3.1).
 */
export function normalizeSendInput(
  input: unknown,
  limits: SendToolLimits = DEFAULT_SEND_LIMITS,
): NormalizedSendInput {
  const parsed = emailSendInputSchema.safeParse(input);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const field = issue?.path.length ? String(issue.path[0]) : "arguments";
    throw validationError(issue?.message ?? "Invalid email_send arguments.", field);
  }

  const data = parsed.data;

  const subject = data.subject.trim();
  if (subject.length === 0) {
    throw validationError('Field "subject" must not be empty.', "subject");
  }
  if (INJECTION_CHARS.test(subject)) {
    throw validationError(
      'Field "subject" contains characters that are not allowed.',
      "subject",
    );
  }
  if (Buffer.byteLength(subject, "utf8") > limits.maxSubjectBytes) {
    throw new RailGunError(
      "PAYLOAD_TOO_LARGE",
      "The subject exceeds the maximum allowed length.",
      { field: "subject" },
    );
  }

  const text = data.text;
  const html = data.html;
  if (text !== undefined && text.length === 0) {
    throw validationError('Field "text" must not be empty when present.', "text");
  }
  if (html !== undefined && html.length === 0) {
    throw validationError('Field "html" must not be empty when present.', "html");
  }
  if (text === undefined && html === undefined) {
    throw validationError(
      'At least one of "text" or "html" must be provided.',
      "text|html",
    );
  }

  const requestId = data.requestId.trim();
  if (requestId.length === 0) {
    throw validationError('Field "requestId" must not be empty.', "requestId");
  }
  if (requestId.length > limits.maxRequestIdLength) {
    throw validationError(
      `Field "requestId" must be at most ${limits.maxRequestIdLength} characters.`,
      "requestId",
    );
  }
  if (INJECTION_CHARS.test(requestId)) {
    throw validationError(
      'Field "requestId" contains characters that are not allowed.',
      "requestId",
    );
  }

  const to = dedupeAddresses(validateAddressField(data.to, "to"));
  const cc = dedupeAddresses(validateAddressField(data.cc, "cc"));
  const bcc = dedupeAddresses(validateAddressField(data.bcc, "bcc"));

  if (to.length === 0) {
    throw validationError('Field "to" must contain at least one address.', "to");
  }

  const totalRecipients = to.length + cc.length + bcc.length;
  if (totalRecipients > limits.maxRecipients) {
    throw new RailGunError(
      "PAYLOAD_TOO_LARGE",
      `The message has more than ${limits.maxRecipients} recipients.`,
      { field: "to|cc|bcc" },
    );
  }

  let from: string | undefined;
  if (data.from !== undefined) {
    const parsedFrom = validateAddressField(data.from, "from");
    from = parsedFrom[0]?.address;
  }

  let replyTo: string | undefined;
  if (data.replyTo !== undefined) {
    const parsedReplyTo = validateAddressField(data.replyTo, "replyTo");
    replyTo = parsedReplyTo[0]?.address;
  }

  const metadata = normalizeMetadata(data.metadata, limits);

  const bodyBytes =
    Buffer.byteLength(subject, "utf8") +
    Buffer.byteLength(text ?? "", "utf8") +
    Buffer.byteLength(html ?? "", "utf8");
  if (bodyBytes > limits.maxMessageBytes) {
    throw new RailGunError(
      "PAYLOAD_TOO_LARGE",
      "The message exceeds the maximum allowed size.",
      { field: "text|html" },
    );
  }

  return {
    to: to.map((entry) => entry.address),
    cc: cc.map((entry) => entry.address),
    bcc: bcc.map((entry) => entry.address),
    subject,
    text,
    html,
    from,
    replyTo,
    requestId,
    metadata,
  };
}

/**
 * Validate the bounded `metadata` extension: a flat string→string map with
 * key, value and total-size caps.
 */
export function normalizeMetadata(
  metadata: Readonly<Record<string, string>> | undefined,
  limits: SendToolLimits = DEFAULT_SEND_LIMITS,
): Readonly<Record<string, string>> | undefined {
  if (metadata === undefined) return undefined;
  const keys = Object.keys(metadata);
  if (keys.length > limits.maxMetadataKeys) {
    throw validationError(
      `Field "metadata" must have at most ${limits.maxMetadataKeys} keys.`,
      "metadata",
    );
  }
  const normalized: Record<string, string> = {};
  let total = 0;
  for (const key of keys) {
    if (key.length > limits.maxMetadataKeyLength) {
      throw validationError(
        `Field "metadata" keys must be at most ${limits.maxMetadataKeyLength} characters.`,
        "metadata",
      );
    }
    const value = metadata[key];
    if (typeof value !== "string") {
      throw validationError('Field "metadata" values must be strings.', "metadata");
    }
    if (value.length > limits.maxMetadataValueLength) {
      throw validationError(
        `Field "metadata" values must be at most ${limits.maxMetadataValueLength} characters.`,
        "metadata",
      );
    }
    total += Buffer.byteLength(key, "utf8") + Buffer.byteLength(value, "utf8");
    normalized[key] = value;
  }
  if (total > limits.maxMetadataTotalBytes) {
    throw new RailGunError(
      "PAYLOAD_TOO_LARGE",
      'Field "metadata" exceeds the maximum allowed size.',
      { field: "metadata" },
    );
  }
  return normalized;
}

/** Normalized, stable representation used for idempotency payload comparison. */
export function sendInputFingerprint(input: NormalizedSendInput): string {
  return JSON.stringify({
    to: input.to,
    cc: input.cc,
    bcc: input.bcc,
    subject: input.subject,
    text: input.text ?? null,
    html: input.html ?? null,
    from: input.from ?? null,
    replyTo: input.replyTo ?? null,
  });
}
