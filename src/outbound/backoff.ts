// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Bounded exponential backoff for the delivery engine.
 *
 * Contract: `docs/design/railgun-direct-mx-delivery-engine-ir.md` §3.10
 * (R-RET-1 … R-RET-8).
 *
 * The curve is exponential from a one-minute base, doubled per attempt, with
 * full jitter and a six-hour ceiling. The attempt ceiling is the *smaller* of
 * the operator-facing `queue.max_attempts` and the engine's own maximum.
 */

import { createHash } from "node:crypto";

/** The first backoff window, in milliseconds. */
export const BASE_BACKOFF_MS = 60_000;

/** The ceiling of a single backoff window, in milliseconds (six hours). */
export const MAX_BACKOFF_MS = 6 * 60 * 60 * 1000;

/** The engine's own attempt ceiling, used when the operator sets a larger one. */
export const DEFAULT_MAX_ATTEMPTS = 8;

/** The backoff options. */
export interface BackoffOptions {
  /** The attempt number, starting at 1. */
  readonly attempt: number;
  /** The first window; defaults to one minute. */
  readonly baseMs?: number | undefined;
  /** The ceiling of a window; defaults to six hours. */
  readonly maxMs?: number | undefined;
  /**
   * The jitter source in `[0, 1)`.
   *
   * Full jitter means the window is drawn uniformly from `[0, ceiling]`.
   */
  readonly random?: (() => number) | undefined;
}

/**
 * The ceiling of the backoff window for an attempt, before jitter.
 *
 * The window doubles per attempt and is capped at six hours.
 */
export function backoffCeiling(
  attempt: number,
  baseMs: number = BASE_BACKOFF_MS,
  maxMs: number = MAX_BACKOFF_MS,
): number {
  const exponent = Math.max(0, attempt - 1);
  const raw = baseMs * 2 ** exponent;
  return Math.min(maxMs, raw);
}

/**
 * The backoff delay for an attempt, with full jitter.
 *
 * The delay is drawn uniformly from `[0, ceiling]`, so a fleet of workers
 * retrying the same host does not synchronise onto the same second.
 */
export function backoffDelay(options: BackoffOptions): number {
  const base = options.baseMs ?? BASE_BACKOFF_MS;
  const max = options.maxMs ?? MAX_BACKOFF_MS;
  const ceiling = backoffCeiling(options.attempt, base, max);
  const random = options.random ?? Math.random;
  const factor = random();
  const clamped = Number.isFinite(factor) ? Math.min(Math.max(factor, 0), 0.999999) : 0;
  return Math.floor(ceiling * clamped);
}

/**
 * The deterministic jitter factor for an attempt.
 *
 * The factor is derived from the attempt number and the message id, so a
 * retry of the same message keeps a stable window while different messages
 * spread out. The engine uses this when no random source is injected.
 */
export function deterministicJitter(attempt: number, seed: string): number {
  const digest = createHash("sha256").update(`${seed}:${attempt}`, "utf8").digest();
  const value = digest.readUInt32BE(0);
  return value / 0x1_0000_0000;
}

/**
 * The effective attempt ceiling.
 *
 * The smaller of the operator-facing `queue.max_attempts` and the engine's
 * own maximum applies (R-RET-1).
 */
export function effectiveMaxAttempts(
  configuredMaxAttempts: number,
  engineMaxAttempts: number = DEFAULT_MAX_ATTEMPTS,
): number {
  return Math.max(1, Math.min(configuredMaxAttempts, engineMaxAttempts));
}

/**
 * The ISO timestamp of the next attempt.
 */
export function nextAttemptAt(now: Date, delayMs: number): string {
  return new Date(now.getTime() + delayMs).toISOString();
}
