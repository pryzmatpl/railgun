// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Stable machine error codes shared by the CLI and the HTTP/MCP surfaces.
 *
 * Codes are additive-only within a major version. A consumer must treat an
 * unknown code as a generic failure governed by the accompanying exit code.
 */
export const ERROR_CODES = [
  "USAGE_INVALID",
  "CONFIG_INVALID",
  "CONFIG_UNREADABLE",
  "DEPENDENCY_UNAVAILABLE",
  "NOT_READY",
  "AUTH_REQUIRED",
  "AUTH_INVALID",
  "INSUFFICIENT_SCOPE",
  "NOT_FOUND",
  "CONFLICT",
  "INVALID_REQUEST",
  "RATE_LIMITED",
  "UPSTREAM_UNAVAILABLE",
  "UPSTREAM_TIMEOUT",
  "INTERNAL_ERROR",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

/** Stable CLI exit-code contract (operator CLI IR §3.4). */
export const EXIT = {
  /** Command completed. Queued/accepted is never presented as delivered. */
  SUCCESS: 0,
  /** Permanent operation failure or unexpected internal failure. */
  OPERATION_FAILED: 1,
  /** Usage error: unknown command, bad argument, incompatible serve flags. */
  USAGE: 2,
  /** Configuration invalid: unreadable/invalid config, missing setting. */
  CONFIG: 3,
  /** Dependency/readiness failure: store, queue, listener, outbound dependency. */
  DEPENDENCY: 4,
  /** Authentication or authorization denied. */
  AUTH: 5,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

/**
 * A failure that can be rendered as the stable CLI error envelope.
 *
 * `details` may name a configuration field or a resource identifier but must
 * never carry a secret or a secret-bearing value.
 */
export class CliError extends Error {
  readonly code: ErrorCode;
  readonly exitCode: ExitCode;
  readonly details: Record<string, unknown> | undefined;
  readonly requestId: string | undefined;

  constructor(options: {
    code: ErrorCode;
    message: string;
    exitCode: ExitCode;
    details?: Record<string, unknown>;
    requestId?: string;
    cause?: unknown;
  }) {
    super(options.message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "CliError";
    this.code = options.code;
    this.exitCode = options.exitCode;
    this.details = options.details;
    this.requestId = options.requestId;
  }

  static usage(message: string, details?: Record<string, unknown>): CliError {
    return new CliError({ code: "USAGE_INVALID", message, exitCode: EXIT.USAGE, details });
  }

  static config(message: string, details?: Record<string, unknown>): CliError {
    return new CliError({ code: "CONFIG_INVALID", message, exitCode: EXIT.CONFIG, details });
  }

  static dependency(message: string, details?: Record<string, unknown>): CliError {
    return new CliError({
      code: "DEPENDENCY_UNAVAILABLE",
      message,
      exitCode: EXIT.DEPENDENCY,
      details,
    });
  }

  static auth(message: string, details?: Record<string, unknown>): CliError {
    return new CliError({ code: "AUTH_REQUIRED", message, exitCode: EXIT.AUTH, details });
  }

  static notFound(message: string, details?: Record<string, unknown>): CliError {
    return new CliError({ code: "NOT_FOUND", message, exitCode: EXIT.OPERATION_FAILED, details });
  }

  static conflict(message: string, details?: Record<string, unknown>): CliError {
    return new CliError({ code: "CONFLICT", message, exitCode: EXIT.OPERATION_FAILED, details });
  }
}

/**
 * The stable error envelope (operator CLI IR §3.3).
 *
 * Field names use snake_case at the boundary so JSON output matches the HTTP
 * response shape.
 */
export interface ErrorEnvelope {
  error: {
    code: ErrorCode;
    message: string;
    details?: Record<string, unknown>;
    request_id?: string;
  };
}

export function toErrorEnvelope(error: unknown): ErrorEnvelope {
  if (error instanceof CliError) {
    const envelope: ErrorEnvelope = {
      error: {
        code: error.code,
        message: error.message,
      },
    };
    if (error.details && Object.keys(error.details).length > 0) {
      envelope.error.details = error.details;
    }
    if (error.requestId) {
      envelope.error.request_id = error.requestId;
    }
    return envelope;
  }

  // Internal exceptions collapse to a generic error: no stack trace, no
  // secret, no internal topology in the operator-facing output.
  return {
    error: {
      code: "INTERNAL_ERROR",
      message: "The command failed with an internal error",
    },
  };
}

/** Map an unknown thrown value onto the stable exit-code contract. */
export function exitCodeFor(error: unknown): ExitCode {
  if (error instanceof CliError) {
    return error.exitCode;
  }
  return EXIT.OPERATION_FAILED;
}
