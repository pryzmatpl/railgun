// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Rate limits, quotas and recipient warmup.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §9 and
// verification obligations V-9, V-10, V-11.
//
// A rate-limit denial is a **throttle**, never a permanent deny, and always
// carries a `retry_at` (IR R-9.1.4). No SMTP connection is opened for a
// throttled request (IR R-15.2.1).

import { warmupCapForDay } from "../domain/identity.js";
import type { WarmupPolicy } from "../domain/identity.js";
import type { RateLimitStore, WarmupStore } from "../ports/index.js";
import type { RateLimitConfig } from "./config.js";

/** The outcome of a rate-limit or quota check. */
export interface LimitOutcome {
  /** Whether the request may proceed. */
  readonly allowed: boolean;
  /** The dimension token, e.g. `tenant.messages_per_day`. */
  readonly dimension: string;
  /** The configured limit that was hit. */
  readonly limit_value: number;
  /** The moment the budget resets, in epoch milliseconds. */
  readonly reset_at_ms: number;
  /** The seconds a client should wait, for `Retry-After`. */
  readonly retry_after_seconds: number;
}

const ALLOWED: LimitOutcome = Object.freeze({
  allowed: true,
  dimension: "",
  limit_value: 0,
  reset_at_ms: 0,
  retry_after_seconds: 0,
});

/** The contexts a limit check runs in. */
export interface LimitContext {
  readonly tenant_id: string;
  readonly principal_id: string;
  readonly sender_domain: string;
  readonly recipient: string;
  /** Whether the recipient has been seen before by this tenant. */
  readonly recipient_is_new: boolean;
  readonly now_ms: number;
}

/**
 * Checks the token buckets and the durable quotas.
 *
 * Every dimension is checked and charged atomically by the store, so a
 * concurrent burst cannot overshoot (IR R-9.2.3).
 */
export async function checkLimits(
  store: RateLimitStore,
  config: RateLimitConfig,
  context: LimitContext,
  recipientCount: number,
  sizeBytes: number,
): Promise<LimitOutcome> {
  const { tenant_id, principal_id, sender_domain, recipient, now_ms } = context;

  // Buckets are refilled per second; the capacity is the per-window limit.
  const buckets: {
    dimension: string;
    key: string;
    capacity: number;
    windowSeconds: number;
    cost: number;
  }[] = [
    {
      dimension: "principal.messages_per_minute",
      key: `bucket:principal:${principal_id}`,
      capacity: config.messages_per_minute,
      windowSeconds: 60,
      cost: 1,
    },
    {
      dimension: "tenant.messages_per_minute",
      key: `bucket:tenant:${tenant_id}`,
      capacity: config.messages_per_minute,
      windowSeconds: 60,
      cost: 1,
    },
    {
      dimension: "tenant.messages_per_hour",
      key: `bucket:tenant-hour:${tenant_id}`,
      capacity: config.messages_per_hour,
      windowSeconds: 3600,
      cost: 1,
    },
    {
      dimension: "recipient.messages_per_hour",
      key: `bucket:recipient:${tenant_id}:${recipient}`,
      capacity: config.recipient_messages_per_hour,
      windowSeconds: 3600,
      cost: 1,
    },
  ];

  if (context.recipient_is_new) {
    buckets.push({
      dimension: "recipient.new_per_hour",
      key: `bucket:new-recipient:${tenant_id}:${recipient}`,
      capacity: config.new_recipients_per_hour,
      windowSeconds: 3600,
      cost: 1,
    });
  }

  for (const bucket of buckets) {
    const refillPerSecond = bucket.capacity / bucket.windowSeconds;
    const result = await store.consume(
      bucket.key,
      bucket.capacity,
      refillPerSecond,
      bucket.cost,
      now_ms,
    );
    if (!result.allowed) {
      return {
        allowed: false,
        dimension: bucket.dimension,
        limit_value: bucket.capacity,
        reset_at_ms: now_ms + result.retryAfterSeconds * 1000,
        retry_after_seconds: result.retryAfterSeconds,
      };
    }
  }

  // Durable quotas (IR R-9.2).
  const dayMs = 86_400_000;
  const quotas: readonly {
    dimension: string;
    key: string;
    limit: number;
    cost: number;
  }[] = [
    {
      dimension: "tenant.messages_per_day",
      key: `quota:tenant-messages:${tenant_id}`,
      limit: config.messages_per_day,
      cost: 1,
    },
    {
      dimension: "tenant.recipients_per_day",
      key: `quota:tenant-recipients:${tenant_id}`,
      limit: config.messages_per_day * config.recipients_per_message,
      cost: recipientCount,
    },
    {
      dimension: "tenant.bytes_per_day",
      key: `quota:tenant-bytes:${tenant_id}`,
      limit: config.bytes_per_day,
      cost: sizeBytes,
    },
    {
      dimension: "principal.messages_per_day",
      key: `quota:principal-messages:${principal_id}`,
      limit: config.principal_messages_per_day,
      cost: 1,
    },
    {
      dimension: "domain.messages_per_day",
      key: `quota:domain-messages:${tenant_id}:${sender_domain}`,
      limit: config.domain_messages_per_day,
      cost: 1,
    },
  ];

  for (const quota of quotas) {
    const result = await store.reserveQuota(
      quota.key,
      quota.limit,
      quota.cost,
      dayMs,
      now_ms,
    );
    if (!result.allowed) {
      return {
        allowed: false,
        dimension: quota.dimension,
        limit_value: quota.limit,
        reset_at_ms: result.resetAtMs,
        retry_after_seconds: Math.max(1, Math.ceil((result.resetAtMs - now_ms) / 1000)),
      };
    }
  }

  return ALLOWED;
}

/**
 * The outcome of a warmup check.
 */
export interface WarmupOutcome {
  readonly allowed: boolean;
  /** `WARMUP_LIMITED` when the ramp is exceeded. */
  readonly reason_code: string;
  /** The effective cap for the current warmup day. */
  readonly limit_value: number;
  /** The moment the warmup window resets. */
  readonly reset_at_ms: number;
  readonly retry_after_seconds: number;
}

/**
 * The UTC day key used for the warmup window. Deterministic and injectable.
 */
export function warmupDayKey(nowMs: number): string {
  return new Date(nowMs).toISOString().slice(0, 10);
}

/**
 * The number of days a sending domain has been in warmup.
 *
 * `created_at` is the domain's creation timestamp; the day index is
 * deterministic given the clock.
 */
export function warmupDayIndex(createdAtMs: number, nowMs: number): number {
  const dayMs = 86_400_000;
  const elapsed = nowMs - createdAtMs;
  if (elapsed < 0) {
    return 1;
  }
  return Math.floor(elapsed / dayMs) + 1;
}

/**
 * Enforces the per-domain warmup ramp (IR §9.3).
 *
 * Exceeding the ramp yields a **throttle** with `WARMUP_LIMITED` and a
 * `retry_at`. It never silently discards the message and never opens an SMTP
 * connection (IR R-9.3.3).
 */
export async function checkWarmup(
  store: WarmupStore,
  policy: WarmupPolicy,
  tenantId: string,
  domain: string,
  domainCreatedAtMs: number,
  nowMs: number,
  recipientCount: number,
): Promise<WarmupOutcome> {
  const day = warmupDayIndex(domainCreatedAtMs, nowMs);
  const cap = warmupCapForDay(policy, day);
  const recipientCap = policy.warmup_recipient_cap * Math.min(day, policy.warmup_days);
  const dayKey = warmupDayKey(nowMs);

  const resetAtMs = Date.parse(`${dayKey}T00:00:00.000Z`) + 86_400_000;

  const messageUsage = await store.reserve(tenantId, domain, `msgs:${dayKey}`, 1, cap);
  if (!messageUsage.allowed) {
    return {
      allowed: false,
      reason_code: "WARMUP_LIMITED",
      limit_value: cap,
      reset_at_ms: resetAtMs,
      retry_after_seconds: Math.max(1, Math.ceil((resetAtMs - nowMs) / 1000)),
    };
  }

  const recipientUsage = await store.reserve(
    tenantId,
    domain,
    `recips:${dayKey}`,
    recipientCount,
    recipientCap,
  );
  if (!recipientUsage.allowed) {
    return {
      allowed: false,
      reason_code: "WARMUP_LIMITED",
      limit_value: recipientCap,
      reset_at_ms: resetAtMs,
      retry_after_seconds: Math.max(1, Math.ceil((resetAtMs - nowMs) / 1000)),
    };
  }

  return {
    allowed: true,
    reason_code: "QUEUED",
    limit_value: cap,
    reset_at_ms: resetAtMs,
    retry_after_seconds: 0,
  };
}
