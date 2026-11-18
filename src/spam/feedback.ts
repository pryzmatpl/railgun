// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Authenticated feedback ingestion (DSN / FBL).
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §10.4 and
// verification obligation V-22.
//
// Feedback MUST be authenticated before it may change policy state
// (IR R-10.4.1). The suppression scope is bounded to the **reported
// recipient address** (IR R-10.4.3, pipeline IR Rule F-3) — feedback can
// never create a wildcard suppression. A `4.x.x` DSN MUST NOT create an
// indefinite suppression; it MAY increment a soft-bounce counter that, past a
// threshold, produces a time-bounded `soft_bounce` suppression.

import { createHmac, timingSafeEqual } from "node:crypto";

import {
  DEFAULT_SUPPRESSION_EXPIRY_HOURS,
  type SuppressionReason,
} from "../domain/identity.js";
import { parseAddress } from "../security/address.js";
import type { FeedbackOutcome, SuppressionStore } from "../ports/index.js";

/** The maximum feedback payload the parser will accept. */
export const MAX_FEEDBACK_BYTES = 64 * 1024;

/** The soft-bounce count at which a time-bounded suppression is created. */
export const SOFT_BOUNCE_THRESHOLD = 3;

/** The parsed content of a feedback report. */
export interface ParsedFeedback {
  /** The reported recipient address, when it could be extracted. */
  readonly recipient: string | null;
  /** The DSN status code, e.g. `5.1.1`. */
  readonly status: string | null;
  /** The reported sending domain. */
  readonly domain: string | null;
  /** Whether the report is a complaint rather than a bounce. */
  readonly complaint: boolean;
}

/**
 * Compares two secrets in constant time. The length check happens **before**
 * the comparison, so a length mismatch does not leak through timing
 * (IR R-10.4.1).
 */
export function secretsMatch(provided: string, expected: string): boolean {
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * Verifies an HMAC-signed feedback request.
 */
export function verifyFeedbackSignature(
  payload: string,
  signature: string,
  secret: string,
): boolean {
  const expected = createHmac("sha256", secret).update(payload, "utf8").digest("hex");
  return secretsMatch(signature.toLowerCase(), expected);
}

/**
 * Extracts a DSN status code such as `5.1.1` from a feedback payload.
 */
export function extractStatus(payload: string): string | null {
  // Bounded search over a payload that is already length-capped.
  const match = /\b([245])\.(\d{1,3})\.(\d{1,3})\b/.exec(payload);
  return match?.[0] ?? null;
}

/**
 * Extracts the reported recipient from a feedback payload.
 *
 * The parser is deliberately defensive: it looks for an `Original-Recipient`
 * or `Final-Recipient` header and validates the address. A malformed or
 * absent address yields `null`, and the caller then changes no state.
 */
export function extractRecipient(payload: string): string | null {
  const patterns = [
    /final-recipient:\s*[^;]*;\s*([^\s\r\n]+)/i,
    /original-recipient:\s*[^;]*;\s*([^\s\r\n]+)/i,
    /reported-domain[^\r\n]*\r?\n[^\r\n]*recipient[^\r\n]*:\s*([^\s\r\n]+)/i,
    /to:\s*([^\s\r\n]+)/i,
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(payload);
    const candidate = match?.[1];
    if (candidate === undefined) {
      continue;
    }
    const parsed = parseAddress(candidate.replace(/^<|>$/g, ""));
    if (parsed !== null) {
      return `${parsed.local}@${parsed.domain}`;
    }
  }
  return null;
}

/**
 * Extracts the sending domain from a feedback payload.
 */
export function extractDomain(payload: string): string | null {
  const match = /reported-domain[^\r\n]*:\s*([^\s\r\n]+)/i.exec(payload);
  const candidate = match?.[1];
  if (candidate !== undefined) {
    return candidate.toLowerCase();
  }
  const recipient = extractRecipient(payload);
  return recipient === null ? null : recipient.split("@")[1] ?? null;
}

/**
 * Detects a complaint (feedback-loop) report rather than a bounce.
 */
export function isComplaint(payload: string): boolean {
  // A feedback-loop report identifies itself with a `Feedback-Type` header
  // (usually `abuse`) or a feedback-loop / complaint marker in the body.
  return /feedback-loop|feedback[\s-]?type|abuse-report|complaint/i.test(payload);
}

/**
 * Parses a feedback payload defensively.
 */
export function parseFeedback(payload: string): ParsedFeedback {
  const capped = payload.slice(0, MAX_FEEDBACK_BYTES);
  return {
    recipient: extractRecipient(capped),
    status: extractStatus(capped),
    domain: extractDomain(capped),
    complaint: isComplaint(capped),
  };
}

/**
 * Classifies a DSN status into a suppression reason.
 *
 * A `5.x.x` code is a permanent failure → `hard_bounce`. A `4.x.x` code is a
 * transient failure and MUST NOT create an indefinite suppression; it only
 * increments the soft-bounce counter (IR R-10.4.3).
 */
export function classifyFeedback(
  status: string | null,
  complaint: boolean,
): SuppressionReason | null {
  if (complaint) {
    return "complaint";
  }
  if (status === null) {
    return null;
  }
  const major = Number.parseInt(status.split(".")[0] ?? "", 10);
  if (Number.isNaN(major)) {
    return null;
  }
  if (major >= 5) {
    return "hard_bounce";
  }
  if (major === 4) {
    // Transient — the caller may only count it toward the soft-bounce
    // threshold.
    return "soft_bounce";
  }
  return null;
}

/** The soft-bounce counter store. */
export interface SoftBounceCounter {
  /** Increments and returns the new count for the recipient. */
  increment(tenantId: string, recipient: string): Promise<number>;
}

/**
 * Ingests an authenticated feedback report.
 *
 * The behaviour is:
 *
 * - An unauthenticated or malformed payload changes **no** policy state and
 *   is still audited (IR R-10.4.5).
 * - A `5.x.x` DSN creates a `hard_bounce` suppression for the reported
 *   recipient.
 * - A `4.x.x` DSN creates **no** indefinite suppression; it increments the
 *   soft-bounce counter, and only past the threshold does it create a
 *   time-bounded `soft_bounce` suppression.
 * - A complaint creates a `complaint` suppression and increments the abuse
 *   counters.
 */
export async function ingestFeedback(
  store: SuppressionStore,
  counters: SoftBounceCounter | null,
  payload: string,
  tenantId: string,
  nowMs: number,
  options: {
    /** The secret presented with the feedback request. */
    readonly presented_secret: string;
    /** The secret the endpoint expects. */
    readonly expected_secret: string;
    readonly domain?: string | null;
    readonly audit?: (outcome: FeedbackOutcome) => Promise<void>;
  },
): Promise<FeedbackOutcome> {
  const audit = options.audit ?? (async () => {});

  if (payload.length > MAX_FEEDBACK_BYTES) {
    const outcome: FeedbackOutcome = {
      accepted: false,
      reason: "payload_too_large",
      created: [],
    };
    await audit(outcome);
    return outcome;
  }

  // Feedback MUST be authenticated before it may change any policy state
  // (IR R-10.4.1). The comparison is length-checked and constant time.
  if (
    options.expected_secret.length === 0 ||
    !secretsMatch(options.presented_secret, options.expected_secret)
  ) {
    const outcome: FeedbackOutcome = {
      accepted: false,
      reason: "unauthenticated",
      created: [],
    };
    await audit(outcome);
    return outcome;
  }

  const parsed = parseFeedback(payload);
  if (parsed.recipient === null) {
    const outcome: FeedbackOutcome = {
      accepted: false,
      reason: "no_recipient",
      created: [],
    };
    await audit(outcome);
    return outcome;
  }

  const reason = classifyFeedback(parsed.status, parsed.complaint);
  if (reason === null) {
    const outcome: FeedbackOutcome = {
      accepted: false,
      reason: "unclassifiable_status",
      created: [],
    };
    await audit(outcome);
    return outcome;
  }

  const nowIso = new Date(nowMs).toISOString();

  if (reason === "soft_bounce") {
    // A transient failure never creates an indefinite suppression. It only
    // counts toward the threshold (IR R-10.4.3).
    const count = counters === null ? 1 : await counters.increment(tenantId, parsed.recipient);
    if (count < SOFT_BOUNCE_THRESHOLD) {
      const outcome: FeedbackOutcome = {
        accepted: true,
        reason: "soft_bounce_counted",
        created: [],
        suppression_reason: "soft_bounce",
      };
      await audit(outcome);
      return outcome;
    }
    const expiryHours = DEFAULT_SUPPRESSION_EXPIRY_HOURS.soft_bounce ?? 24;
    const entry = {
      id: `sup-${tenantId}-${parsed.recipient}-${nowMs}`,
      tenant_id: tenantId,
      scope: "global" as const,
      domain: null,
      recipient: parsed.recipient,
      reason: "soft_bounce" as const,
      created_at: nowIso,
      expires_at: new Date(nowMs + expiryHours * 3_600_000).toISOString(),
      source: "bounce" as const,
    };
    await store.add(entry);
    const outcome: FeedbackOutcome = {
      accepted: true,
      reason: "soft_bounce_suppressed",
      created: [entry],
      suppression_reason: "soft_bounce",
    };
    await audit(outcome);
    return outcome;
  }

  const expiryHours = DEFAULT_SUPPRESSION_EXPIRY_HOURS[reason];
  const entry = {
    id: `sup-${tenantId}-${parsed.recipient}-${nowMs}`,
    tenant_id: tenantId,
    scope: "global" as const,
    domain: null,
    recipient: parsed.recipient,
    reason,
    created_at: nowIso,
    expires_at: expiryHours === null ? null : new Date(nowMs + expiryHours * 3_600_000).toISOString(),
    source: reason === "complaint" ? ("feedback" as const) : ("bounce" as const),
  };
  await store.add(entry);
  const outcome: FeedbackOutcome = {
    accepted: true,
    reason: `${reason}_suppressed`,
    created: [entry],
    suppression_reason: reason,
  };
  await audit(outcome);
  return outcome;
}
