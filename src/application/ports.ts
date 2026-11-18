// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * Application ports consumed by the RailGun MCP surface.
 *
 * The MCP handlers are projections of these use cases (IR §1.1): they
 * translate MCP requests into application commands and translate application
 * results into the MCP envelopes. Policy, rate limiting, spam scoring,
 * idempotency, tenant filtering and audit are implemented behind these ports
 * — never inside the MCP layer.
 */

import type {
  BounceRecord,
  MessageEnvelope,
  StatsQuery,
  StatsResult,
  StoredMessage,
} from "../domain/message.js";
import type { RailGunStatus } from "../domain/status.js";

export interface SendCommand {
  readonly tenantId: string;
  readonly principalId: string;
  readonly to: readonly string[];
  readonly cc: readonly string[];
  readonly bcc: readonly string[];
  readonly subject: string;
  readonly text?: string;
  readonly html?: string;
  readonly from?: string;
  readonly replyTo?: string;
  readonly requestId: string;
  readonly metadata?: Readonly<Record<string, string>>;
}

export interface SendRecipientOutcome {
  readonly address: string;
  readonly status: RailGunStatus;
}

export interface SendOutcome {
  readonly id: string;
  readonly status: RailGunStatus;
  readonly messageId: string;
  readonly requestId: string;
  readonly recipients: readonly SendRecipientOutcome[];
  readonly reason: string | null;
  readonly warnings: readonly string[];
  /** True when the command was an idempotent replay of an earlier send. */
  readonly replayed: boolean;
}

export interface MessageLookup {
  readonly tenantId: string;
  readonly principalId: string;
  readonly id?: string;
  readonly requestId?: string;
}

export interface BounceQuery {
  readonly tenantId: string;
  readonly principalId: string;
  readonly limit?: number;
  readonly cursor?: string;
  readonly since?: string;
  readonly until?: string;
  readonly recipientHash?: string;
  readonly reason?: string;
}

export interface BouncePage {
  readonly items: readonly BounceRecord[];
  readonly nextCursor: string | null;
  readonly count: number;
}

/** Tenant-scoped message/bounce/stats access for one authenticated principal. */
export interface EmailApplication {
  send(command: SendCommand): Promise<SendOutcome>;
  status(lookup: MessageLookup): Promise<StoredMessage | null>;
  bounces(query: BounceQuery): Promise<BouncePage>;
  stats(query: StatsQuery): Promise<StatsResult>;
}

export interface MessageStore {
  findById(id: string): Promise<StoredMessage | null>;
  findByRequestId(requestId: string): Promise<StoredMessage | null>;
  save(message: StoredMessage): Promise<void>;
}

export interface BounceStore {
  list(query: BounceQuery): Promise<BouncePage>;
}

export interface StatsStore {
  aggregate(query: StatsQuery): Promise<StatsResult>;
}

export type { MessageEnvelope };
