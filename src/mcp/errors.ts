// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * Canonical MCP error vocabulary and sanitized error envelope (IR §8).
 *
 * Errors returned through MCP never carry stack traces, file paths, SQL,
 * raw credentials, raw SMTP responses, or another tenant's identifiers.
 */

export const RAILGUN_ERROR_CODES = [
  "VALIDATION_FAILED",
  "UNAUTHENTICATED",
  "AMBIGUOUS_AUTH",
  "FORBIDDEN",
  "ACTION_NOT_PERMITTED",
  "NOT_FOUND",
  "IDEMPOTENCY_KEY_REUSED",
  "RATE_LIMITED",
  "POLICY_REJECTED",
  "SPAM_REJECTED",
  "SUPPRESSED",
  "PAYLOAD_TOO_LARGE",
  "INTERNAL_ERROR",
] as const;

export type RailGunErrorCode = (typeof RAILGUN_ERROR_CODES)[number];

export interface RailGunErrorBody {
  readonly code: RailGunErrorCode;
  readonly message: string;
  readonly required_scope?: string;
  readonly retry_after_seconds?: number | null;
  readonly field?: string;
  readonly request_id?: string | null;
}

export interface McpToolError {
  readonly error: RailGunErrorBody;
}

/**
 * HTTP status mapping for the streamable HTTP transport. The MCP protocol
 * layer itself uses JSON-RPC semantics; this map is used by the HTTP
 * transport to answer unauthenticated/forbidden requests at the transport
 * boundary before a JSON-RPC response is produced.
 */
export const ERROR_HTTP_STATUS: Record<RailGunErrorCode, number> = {
  VALIDATION_FAILED: 400,
  UNAUTHENTICATED: 401,
  AMBIGUOUS_AUTH: 401,
  FORBIDDEN: 403,
  ACTION_NOT_PERMITTED: 403,
  NOT_FOUND: 404,
  IDEMPOTENCY_KEY_REUSED: 409,
  RATE_LIMITED: 429,
  POLICY_REJECTED: 403,
  SPAM_REJECTED: 403,
  SUPPRESSED: 403,
  PAYLOAD_TOO_LARGE: 413,
  INTERNAL_ERROR: 500,
};

/** Error carrying a stable machine code; thrown by validation and auth. */
export class RailGunError extends Error {
  readonly code: RailGunErrorCode;
  readonly requiredScope?: string;
  readonly retryAfterSeconds?: number | null;
  readonly field?: string;
  readonly requestId?: string | null;

  constructor(
    code: RailGunErrorCode,
    message: string,
    options: {
      readonly requiredScope?: string;
      readonly retryAfterSeconds?: number | null;
      readonly field?: string;
      readonly requestId?: string | null;
    } = {},
  ) {
    super(message);
    this.name = "RailGunError";
    this.code = code;
    this.requiredScope = options.requiredScope;
    this.retryAfterSeconds = options.retryAfterSeconds;
    this.field = options.field;
    this.requestId = options.requestId;
  }

  /** Build the sanitized wire envelope for this error. */
  toBody(): RailGunErrorBody {
    const body: {
      code: RailGunErrorCode;
      message: string;
      required_scope?: string;
      retry_after_seconds?: number | null;
      field?: string;
      request_id?: string | null;
    } = { code: this.code, message: this.message };

    if (this.requiredScope !== undefined) body.required_scope = this.requiredScope;
    if (this.retryAfterSeconds !== undefined) {
      body.retry_after_seconds = this.retryAfterSeconds;
    }
    if (this.field !== undefined) body.field = this.field;
    body.request_id = this.requestId ?? null;

    return body;
  }
}

/**
 * Convert an unknown thrown value into a sanitized error. Unexpected failures
 * collapse to `INTERNAL_ERROR`; details are logged, never returned.
 */
export function toRailGunError(error: unknown, requestId?: string | null): RailGunError {
  if (error instanceof RailGunError) return error;
  return new RailGunError(
    "INTERNAL_ERROR",
    "The request could not be completed.",
    { requestId: requestId ?? null },
  );
}
