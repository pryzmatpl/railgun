/* RailGun domain errors. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

export type PersistenceErrorCode =
  | "NOT_FOUND"
  | "CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "INVALID_TRANSITION"
  | "STALE_VERSION"
  | "STALE_LEASE"
  | "INVALID_ARGUMENT";

export class PersistenceError extends Error {
  readonly code: PersistenceErrorCode;

  constructor(code: PersistenceErrorCode, message: string) {
    super(message);
    this.name = "PersistenceError";
    this.code = code;
  }
}

export class IdempotencyConflictError extends PersistenceError {
  constructor(key: string) {
    super("IDEMPOTENCY_CONFLICT", `Idempotency key ${key} was used with a different request digest.`);
    this.name = "IdempotencyConflictError";
  }
}
