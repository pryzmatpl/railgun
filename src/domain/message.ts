// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * Shared domain types used by the RailGun MCP surface.
 *
 * These mirror the canonical RailGun message model (ARCHITECTURE.md §4.1) in
 * the subset the MCP projection needs. They are intentionally dependency-free
 * so the package remains standalone-installable.
 */

import type { RailGunStatus } from "./status.js";

export interface RecipientEnvelope {
  /** Raw recipient address. Never returned through MCP output. */
  readonly address: string;
  readonly status: RailGunStatus;
  readonly attempts: number;
}

export interface MessageEnvelope {
  readonly sender: string | null;
  readonly recipients: readonly RecipientEnvelope[];
}

export interface AttemptRecord {
  readonly attemptedAt: string;
  readonly attempt: number;
  readonly outcome: RailGunStatus;
  /** Sanitized SMTP reply code, e.g. "451". Raw remote text is never kept here. */
  readonly smtpCode: string | null;
  readonly reason: string | null;
}

export interface StoredMessage {
  readonly id: string;
  readonly tenantId: string;
  readonly principalId: string;
  readonly requestId: string;
  readonly messageId: string;
  readonly subject: string;
  readonly body: { readonly text?: string; readonly html?: string } | null;
  readonly envelope: MessageEnvelope;
  readonly status: RailGunStatus;
  readonly attempts: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly nextAttemptAt: string | null;
  readonly lastSmtpCode: string | null;
  readonly lastErrorClass: string | null;
  readonly reason: string | null;
  readonly attemptHistory: readonly AttemptRecord[];
}

export interface BounceRecord {
  readonly messageId: string;
  readonly tenantId: string;
  readonly principalId: string;
  /** Raw recipient address; MCP surfaces only expose the salted hash. */
  readonly recipient: string;
  readonly occurredAt: string;
  /** Sanitized DSN code, e.g. "5.1.1". */
  readonly code: string;
  /** Stable machine reason code, e.g. "mailbox_unavailable". */
  readonly reason: string;
  readonly permanent: boolean;
  /** Human-safe, fixed-vocabulary summary. Never raw DSN text. */
  readonly diagnostic: string;
}

export interface StatsTotals {
  readonly received: number;
  readonly policy_evaluated: number;
  readonly rejected: number;
  readonly suppressed: number;
  readonly queued: number;
  readonly accepted: number;
  readonly delivered: number;
  readonly deferred: number;
  readonly failed: number;
  readonly bounced: number;
}

export interface StatsSeriesPoint {
  readonly bucket: string;
  readonly delivered: number;
  readonly bounced: number;
  readonly deferred: number;
  readonly queued: number;
}

export interface StatsQuery {
  readonly tenantId: string;
  readonly principalId: string;
  readonly from?: string;
  readonly to?: string;
  readonly groupBy?: "none" | "day" | "domain";
}

export interface StatsResult {
  readonly window: { readonly from: string; readonly to: string };
  readonly totals: StatsTotals;
  readonly series: readonly StatsSeriesPoint[];
  readonly tenantId: string;
}
