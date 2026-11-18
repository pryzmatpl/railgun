// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The mapping from application-service failures onto the stable CLI error
 * contract.
 *
 * The mapping lives in one place so every command classifies a service
 * failure identically.
 */
import { CliError, EXIT } from "./errors.js";
import { ServiceError } from "../services/operator.js";

/** Convert a service failure into the stable CLI error contract. */
export function toCliError(cause: unknown): CliError {
  if (cause instanceof CliError) {
    return cause;
  }
  if (cause instanceof ServiceError) {
    switch (cause.code) {
      case "NOT_FOUND":
        return CliError.notFound(cause.message, cause.details);
      case "SUPPRESSION_CONFLICT":
      case "MESSAGE_NOT_RETRYABLE":
        return CliError.conflict(cause.message, cause.details);
      case "INSUFFICIENT_SCOPE":
        return new CliError({
          code: "INSUFFICIENT_SCOPE",
          message: cause.message,
          exitCode: EXIT.AUTH,
          details: cause.details,
        });
      default:
        return new CliError({
          code: "INTERNAL_ERROR",
          message: cause.message,
          exitCode: EXIT.OPERATION_FAILED,
          details: cause.details,
        });
    }
  }
  return new CliError({
    code: "INTERNAL_ERROR",
    message: "The command failed with an internal error",
    exitCode: EXIT.OPERATION_FAILED,
  });
}
