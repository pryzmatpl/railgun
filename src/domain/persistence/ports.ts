/* RailGun persistence ports. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type {
  AuditEventInput,
  AuditRecord,
  BounceRecord,
  DeliveryAttempt,
  EnvelopeRecipient,
  IdempotencyRecord,
  Message,
  OutboxItem,
  RetentionPolicy,
  Suppression,
} from "./types.js";
import type { AcceptInput } from "./accept.js";

/**
 * Re-export the persisted value contracts so an adapter can import the port
 * and the records it stores from one module.
 */
export type {
  AuditEventInput,
  AuditRecord,
  BounceRecord,
  DeliveryAttempt,
  EnvelopeRecipient,
  EnvelopeStatus,
  IdempotencyRecord,
  Message,
  OutboxItem,
  RetentionPolicy,
  Suppression,
} from "./types.js";

export interface Clock {
  now(): Date;
}

export interface IdGenerator {
  next(): string;
}

export interface MessageQuery {
  readonly tenantId: string;
  readonly status?: Message["status"];
  readonly recipient?: string;
  readonly createdAfter?: string;
  readonly createdBefore?: string;
  readonly limit?: number;
  readonly cursor?: string;
}

export interface MessageStore {
  create(message: Message): Promise<Message>;
  get(tenantId: string, messageId: string): Promise<Message | null>;
  update(message: Message, expectedVersion: number): Promise<Message>;
  list(query: MessageQuery): Promise<readonly Message[]>;
  envelopes(messageId: string): Promise<readonly EnvelopeRecipient[]>;
  updateEnvelope(envelope: EnvelopeRecipient, expectedVersion: number): Promise<EnvelopeRecipient>;
  appendAttempt(attempt: DeliveryAttempt): Promise<DeliveryAttempt>;
  attempts(envelopeId: string): Promise<readonly DeliveryAttempt[]>;
  deleteExpired(tenantId: string, before: string, bodyBefore?: string): Promise<{ messages: number; bodies: number }>;
}

export interface LeaseRequest {
  readonly tenantId: string;
  readonly owner: string;
  readonly now: string;
  readonly leaseUntil: string;
  readonly limit: number;
}

export interface OutboxStore {
  enqueue(items: readonly Omit<OutboxItem, "acceptedSequence">[]): Promise<readonly OutboxItem[]>;
  lease(request: LeaseRequest): Promise<readonly OutboxItem[]>;
  renew(itemId: string, owner: string, leaseUntil: string): Promise<OutboxItem>;
  complete(itemId: string, owner: string, outcome: { status: EnvelopeRecipient["status"]; smtpCode?: number; response?: string; errorCode?: string }): Promise<void>;
  release(itemId: string, owner: string, nextAttemptAt: string, errorCode?: string): Promise<void>;
  stats(tenantId: string, now: string): Promise<{ depth: number; due: number; oldestAgeMs: number | null }>;
  reconcileExpired(now: string): Promise<number>;
}

export interface IdempotencyStore {
  reserve(record: IdempotencyRecord): Promise<"reserved" | "replay" | "conflict">;
  commit(key: string, messageId: string, response: unknown, expiresAt: string): Promise<IdempotencyRecord>;
  release(key: string): Promise<void>;
  get(key: string): Promise<IdempotencyRecord | null>;
  expire(now: string): Promise<number>;
}

export interface SuppressionStore {
  isSuppressed(tenantId: string, recipient: string, now: string): Promise<boolean>;
  create(suppression: Suppression): Promise<Suppression>;
  list(tenantId: string): Promise<readonly Suppression[]>;
  remove(tenantId: string, id: string): Promise<boolean>;
  expire(now: string): Promise<number>;
}

export interface BounceQuery {
  readonly tenantId: string;
  readonly recipient?: string;
  readonly messageId?: string;
  readonly envelopeId?: string;
  readonly bounceClass?: BounceRecord["bounceClass"];
  readonly dsnClass?: BounceRecord["dsnClass"];
  readonly dsnCode?: string;
  readonly after?: string;
  readonly before?: string;
  readonly limit?: number;
  readonly cursor?: string;
}

export interface BounceStore {
  append(bounce: BounceRecord): Promise<BounceRecord>;
  list(query: BounceQuery): Promise<readonly BounceRecord[]>;
  get(tenantId: string, id: string): Promise<BounceRecord | null>;
  counts(tenantId: string): Promise<Record<BounceRecord["bounceClass"], number>>;
}

export interface AuditVerification {
  readonly valid: boolean;
  readonly headSequence: number;
  readonly headDigest: string;
  readonly firstInvalidSequence: number | null;
  readonly reason: string | null;
}

export interface AuditStore {
  append(event: AuditEventInput): Promise<AuditRecord>;
  read(fromSequence?: number): Promise<readonly AuditRecord[]>;
  verify(): Promise<AuditVerification>;
  head(): Promise<{ sequence: number; digest: string }>;
}

export interface RailGunStore {
  readonly messages: MessageStore;
  readonly outbox: OutboxStore;
  readonly idempotency: IdempotencyStore;
  readonly suppressions: SuppressionStore;
  readonly bounces: BounceStore;
  readonly audit: AuditStore;
  accept(input: AcceptInput): Promise<{ message: Message; envelopes: readonly EnvelopeRecipient[]; outbox: readonly OutboxItem[] }>;
  applyRetention(policy: RetentionPolicy, now: string): Promise<Record<string, number>>;
}
