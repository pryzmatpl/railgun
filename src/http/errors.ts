// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * Canonical error registry and the single sanitized error envelope (§8).
 *
 * Every non-2xx response produced by the HTTP surface has exactly this shape:
 *
 * ```json
 * { "error": { "code": "SUPPRESSED", "message": "…", "details": { … } },
 *   "request_id": "rq_…" }
 * ```
 *
 * Stack traces, file paths, credentials, raw SMTP transcripts and raw DSN
 * bodies are never part of the payload.
 */

export const ERROR_CODES = {
  INVALID_REQUEST: 400,
  AMBIGUOUS_FIELD: 400,
  AMBIGUOUS_AUTH: 400,
  UNKNOWN_FILTER: 400,
  INVALID_CURSOR: 400,
  INVALID_LIMIT: 400,
  UNAUTHENTICATED: 401,
  INSUFFICIENT_SCOPE: 403,
  ACTION_NOT_PERMITTED: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  DOMAIN_NOT_VERIFIED: 409,
  MESSAGE_NOT_RETRYABLE: 409,
  SUPPRESSION_CONFLICT: 409,
  IDEMPOTENCY_KEY_REUSED: 409,
  PAYLOAD_TOO_LARGE: 413,
  SUPPRESSED: 422,
  BLOCKED: 422,
  SPAM_POLICY_DENIED: 422,
  POLICY_CONTRADICTION: 422,
  RATE_LIMITED: 429,
  RATE_LIMITED_BY_POLICY: 429,
  INTERNAL_ERROR: 500,
  UPSTREAM_UNAVAILABLE: 502,
  NOT_READY: 503,
  UPSTREAM_TIMEOUT: 504,
} as const;

export type ErrorCode = keyof typeof ERROR_CODES;

/** Anti-spam / validation IR spellings accepted as aliases (§0.4, OI-3). */
export const ERROR_CODE_ALIASES: Record<string, ErrorCode> = {
  UNAUTHORIZED: "UNAUTHENTICATED",
  FORBIDDEN: "INSUFFICIENT_SCOPE",
  IDEMPOTENCY_CONFLICT: "IDEMPOTENCY_KEY_REUSED",
  QUOTA_EXCEEDED: "RATE_LIMITED",
};

export interface ErrorEnvelope {
  error: {
    code: ErrorCode;
    message: string;
    details?: Record<string, unknown>;
  };
  request_id: string;
}

/**
 * An error that is safe to render to a client.
 *
 * `details` is merged into the response as-is; callers MUST only put
 * non-secret context in it. The renderer performs a final defensive scrub of
 * the serialized payload (§8.1 "Forbidden in any error payload").
 */
export class HttpError extends Error {
  readonly status: number;
  readonly code: ErrorCode;
  readonly details?: Record<string, unknown>;
  readonly headers: Record<string, string>;

  constructor(
    status: number,
    code: ErrorCode,
    message: string,
    details?: Record<string, unknown>,
    headers?: Record<string, string>,
  ) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
    this.details = details;
    this.headers = headers ?? {};
  }

  toEnvelope(request_id: string): ErrorEnvelope {
    const error: ErrorEnvelope["error"] = { code: this.code, message: this.message };
    if (this.details && Object.keys(this.details).length > 0) {
      error.details = this.details;
    }
    return { error, request_id };
  }
}

/** `401` — missing or invalid credential. */
export function unauthenticated(
  message = "Authentication required.",
  headers?: Record<string, string>,
): HttpError {
  return new HttpError(
    401,
    "UNAUTHENTICATED",
    message,
    undefined,
    headers ?? { "www-authenticate": "Bearer" },
  );
}

/** `403` — authenticated but lacking the required scope. */
export function insufficientScope(required_scope: string, reason?: string): HttpError {
  return new HttpError(403, "INSUFFICIENT_SCOPE", "Insufficient scope for this action.", {
    required_scope,
    ...(reason ? { reason } : {}),
  });
}

/** `403` — deny-all default for an unknown action. */
export function actionNotPermitted(): HttpError {
  return new HttpError(403, "ACTION_NOT_PERMITTED", "Action is not permitted.");
}

/** `404` — absent *or* not visible to the tenant; deliberately identical. */
export function notFound(message = "Resource not found."): HttpError {
  return new HttpError(404, "NOT_FOUND", message);
}

/** `400` — malformed body or parameters. */
export function invalidRequest(field: string, message?: string, extra?: Record<string, unknown>): HttpError {
  return new HttpError(400, "INVALID_REQUEST", message ?? `Invalid request field: ${field}.`, {
    field,
    ...extra,
  });
}

/** `400` — both camelCase and snake_case supplied with different values. */
export function ambiguousField(field: string): HttpError {
  return new HttpError(
    400,
    "AMBIGUOUS_FIELD",
    `Field ${field} was supplied in both snake_case and camelCase with different values.`,
    { field },
  );
}

/** `409` — same idempotency key with a different request body. */
export function idempotencyKeyReused(): HttpError {
  return new HttpError(
    409,
    "IDEMPOTENCY_KEY_REUSED",
    "Idempotency key was already used with a different request body.",
  );
}

/** `429` — rate limited; carries `Retry-After` and `details.limit`. */
export function rateLimited(
  limit: "api_key_minute" | "daily_cap" | "recipient_hourly_cap" | "warmup_daily_cap",
  retry_after_s: number,
  reset_at?: string,
): HttpError {
  return new HttpError(
    429,
    "RATE_LIMITED",
    "Rate limit exceeded.",
    { limit, ...(reset_at ? { reset_at } : {}) },
    { "retry-after": String(Math.max(1, Math.ceil(retry_after_s))) },
  );
}

/** `500` — unexpected failure. The payload carries only `code` + `request_id`. */
export function internalError(): HttpError {
  return new HttpError(500, "INTERNAL_ERROR", "Internal error.");
}

/** `503` — a readiness dependency is down. */
export function notReady(checks: string[]): HttpError {
  return new HttpError(503, "NOT_READY", "Service is not ready.", { checks });
}

/**
 * Final defensive scrub before a body is written to the wire.
 *
 * Removes absolute filesystem paths, stack frames and obvious source
 * references. It is intentionally conservative: it never rewrites a legitimate
 * message but guarantees that an unexpected exception cannot leak internals.
 */
export function sanitizePayload(value: unknown): unknown {
  if (typeof value === "string") {
    return value
      .replaceAll(/[A-Za-z]:\\[^\s"']+/g, "[redacted-path]")
      .replaceAll(/\/(?:[\w.-]+\/)+[\w.-]+\.(?:ts|js|mjs|cjs)(?::\d+)?/g, "[redacted-path]")
      .replaceAll(/\n\s+at\s+[^\n]+/g, "");
  }
  if (Array.isArray(value)) {
    return value.map((entry) => sanitizePayload(entry));
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      out[key] = sanitizePayload(entry);
    }
    return out;
  }
  return value;
}
