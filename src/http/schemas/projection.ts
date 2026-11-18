// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * Read projections for messages, bounces and statistics (§6.2–§6.4).
 *
 * Projections never expose: BCC recipients, raw SMTP transcripts, raw DSN
 * bodies, message bodies (without `body:read` + `include_body=true`) or
 * credentials.
 */

import type { BounceRecord, MessageRecord, StatsBucket } from "../types.js";

export interface MessageProjection {
  message_id: string;
  id: string;
  request_id: string;
  from_addr: string;
  to_addr: string;
  subject: string;
  status: string;
  delivery: string;
  deliveryConfirmed: boolean;
  smtp_code: number | null;
  smtp_response: string | null;
  dkim_signed: boolean;
  mode: string;
  attempts: number;
  last_error: { code: string; message: string } | null;
  tags: string[];
  created_at: string;
  queued_at: string | null;
  accepted_at: string | null;
  delivered_at: string | null;
  updated_at: string;
  text?: string | null;
  html?: string | null;
}

/**
 * Project a message record.
 *
 * @param includeBody whether the caller is authorized to see the body. When
 * `false`, the body fields are **omitted entirely** — not nulled (§6.2).
 */
export function projectMessage(record: MessageRecord, includeBody: boolean): MessageProjection {
  const projection: MessageProjection = {
    message_id: record.id,
    id: record.id,
    request_id: record.request_id,
    from_addr: record.from_addr,
    to_addr: record.to_addr,
    subject: record.subject,
    status: record.status,
    delivery: record.delivery,
    deliveryConfirmed: record.deliveryConfirmed,
    smtp_code: record.smtp_code,
    smtp_response: record.smtp_response,
    dkim_signed: record.dkim_signed,
    mode: record.mode,
    attempts: record.attempts,
    last_error: record.last_error,
    tags: record.tags,
    created_at: record.created_at,
    queued_at: record.queued_at,
    accepted_at: record.accepted_at,
    delivered_at: record.delivered_at,
    updated_at: record.updated_at,
  };
  if (includeBody) {
    projection.text = record.body_text;
    projection.html = record.body_html;
  }
  return projection;
}

export interface BounceProjection {
  id: string;
  message_id: string;
  request_id: string;
  recipient_hash: string;
  code: string;
  enhanced_code: string;
  class: string;
  reason: string;
  remote_mta: string;
  action_taken: string;
  occurred_at: string;
}

/** Project a bounce record — the raw remote response text is never included. */
export function projectBounce(record: BounceRecord): BounceProjection {
  return {
    id: record.id,
    message_id: record.message_id,
    request_id: record.request_id,
    recipient_hash: record.recipient_hash,
    code: record.code,
    enhanced_code: record.enhanced_code,
    class: record.class,
    reason: record.reason,
    remote_mta: record.remote_mta,
    action_taken: record.action_taken,
    occurred_at: record.occurred_at,
  };
}

export interface StatsProjection {
  from: string | null;
  to: string | null;
  totals: Record<string, number>;
  buckets: StatsBucket[];
}

/**
 * Compute the delivery rate (§6.4).
 *
 * The denominator excludes `queued`/`accepted` (not yet terminal). A zero
 * denominator yields `null` — "no data" and "zero delivery" are different
 * facts.
 */
export function deliveryRate(counts: {
  delivered: number;
  deferred: number;
  bounced: number;
  suppressed: number;
  rejected: number;
}): number | null {
  const denominator =
    counts.delivered +
    counts.deferred +
    counts.bounced +
    counts.suppressed +
    counts.rejected;
  if (denominator === 0) {
    return null;
  }
  return counts.delivered / denominator;
}
