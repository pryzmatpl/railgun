// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * In-memory implementation of the RailGun email application port.
 *
 * This is the reference implementation used by the MCP test-suite and by
 * `railgun serve --stdio` development runs. It enforces the invariants the
 * MCP surface relies on:
 *
 * - tenant-scoped idempotency: the same `(tenant_id, requestId)` replays the
 *   original result; a different payload under the same key is rejected with
 *   `IDEMPOTENCY_KEY_REUSED`;
 * - tenant isolation: a message belonging to another tenant is not found;
 * - deterministic message IDs.
 */

import { createHash } from "node:crypto";

import type {
  BouncePage,
  BounceQuery,
  EmailApplication,
  MessageLookup,
  SendCommand,
  SendOutcome,
} from "./ports.js";
import type {
  BounceRecord,
  StatsQuery,
  StatsResult,
  StoredMessage,
} from "../domain/message.js";
import { normalizeStatus } from "../domain/status.js";
import { RailGunError } from "../mcp/errors.js";
import { sendInputFingerprint } from "../mcp/schemas.js";

interface IdempotencyRecord {
  readonly fingerprint: string;
  readonly outcome: SendOutcome;
}

export interface MemoryEmailApplicationOptions {
  /** Fixed clock for deterministic tests. */
  readonly now?: () => Date;
}

/**
 * Principals configured as tenant-wide readers. The reference implementation
 * treats principals whose id carries the `auditor:` / `operator:` / `admin:`
 * prefix as tenant-wide readers.
 */
const TENANT_READER_PRINCIPALS = new Set<string>();

/** Mark a principal as a tenant-wide reader. */
export function registerTenantReader(principalId: string): void {
  TENANT_READER_PRINCIPALS.add(principalId);
}

/**
 * Tenant-wide readers (`operator`, `auditor`, `admin`) may inspect the whole
 * tenant; a `sender` sees only its own messages.
 */
function isTenantReader(record: { readonly principalId: string }): boolean {
  return TENANT_READER_PRINCIPALS.has(record.principalId);
}

export class MemoryEmailApplication implements EmailApplication {
  private readonly messages = new Map<string, StoredMessage>();
  private readonly byRequestId = new Map<string, string>();
  private readonly idempotency = new Map<string, IdempotencyRecord>();
  private readonly bounceRecords: BounceRecord[] = [];
  private readonly now: () => Date;

  constructor(options: MemoryEmailApplicationOptions = {}) {
    this.now = options.now ?? (() => new Date());
  }

  async send(command: SendCommand): Promise<SendOutcome> {
    const key = `${command.tenantId}:${command.requestId}`;
    const fingerprint = sendInputFingerprint({
      to: command.to,
      cc: command.cc,
      bcc: command.bcc,
      subject: command.subject,
      text: command.text,
      html: command.html,
      from: command.from,
      replyTo: command.replyTo,
      requestId: command.requestId,
    });

    const existing = this.idempotency.get(key);
    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        throw new RailGunError(
          "IDEMPOTENCY_KEY_REUSED",
          "The requestId was already used with a different payload.",
          { field: "requestId", requestId: command.requestId },
        );
      }
      return { ...existing.outcome, replayed: true };
    }

    const createdAt = this.now().toISOString();
    const id = `rg_${deterministicId(command.tenantId, command.requestId)}`;
    const messageId = `<${deterministicId(command.tenantId, command.requestId)}@railgun>`;
    const recipients = [
      ...command.to.map((address) => ({ address, status: "queued" as const })),
      ...command.cc.map((address) => ({ address, status: "queued" as const })),
      ...command.bcc.map((address) => ({ address, status: "queued" as const })),
    ];

    const outcome: SendOutcome = {
      id,
      status: "queued",
      messageId,
      requestId: command.requestId,
      recipients: recipients.map((recipient) => ({
        address: recipient.address,
        status: recipient.status,
      })),
      reason: null,
      warnings: [],
      replayed: false,
    };

    const message: StoredMessage = {
      id,
      tenantId: command.tenantId,
      principalId: command.principalId,
      requestId: command.requestId,
      messageId,
      subject: command.subject,
      body: { text: command.text, html: command.html },
      envelope: {
        sender: command.from ?? null,
        recipients: recipients.map((recipient) => ({
          address: recipient.address,
          status: recipient.status,
          attempts: 0,
        })),
      },
      status: "queued",
      attempts: 0,
      createdAt,
      updatedAt: createdAt,
      nextAttemptAt: null,
      lastSmtpCode: null,
      lastErrorClass: null,
      reason: null,
      attemptHistory: [],
    };

    this.messages.set(id, message);
    this.byRequestId.set(`${command.tenantId}:${command.requestId}`, id);
    this.idempotency.set(key, { fingerprint, outcome });

    return outcome;
  }

  async status(lookup: MessageLookup): Promise<StoredMessage | null> {
    // Tenant isolation (IR §7.4): a message owned by another tenant is not
    // found. The `sender` role additionally sees only its own messages.
    const visible = (message: StoredMessage): boolean => {
      if (message.tenantId !== lookup.tenantId) return false;
      if (message.principalId !== lookup.principalId && !isTenantReader(message)) {
        return false;
      }
      return true;
    };

    if (lookup.id) {
      const message = this.messages.get(lookup.id);
      return message && visible(message) ? message : null;
    }
    if (lookup.requestId) {
      const id = this.byRequestId.get(`${lookup.tenantId}:${lookup.requestId}`);
      if (!id) return null;
      const message = this.messages.get(id);
      return message && visible(message) ? message : null;
    }
    return null;
  }

  async bounces(query: BounceQuery): Promise<BouncePage> {
    const limit = Math.min(query.limit ?? 50, 200);
    const items = this.bounceRecords
      .filter((bounce) => {
        // Tenant-scoped: a tenant never sees another tenant's bounces.
        if (bounce.tenantId !== query.tenantId) return false;
        if (bounce.principalId !== query.principalId && !isTenantReader(bounce)) {
          return false;
        }
        if (query.since && bounce.occurredAt < query.since) return false;
        if (query.until && bounce.occurredAt > query.until) return false;
        if (query.reason && bounce.reason !== query.reason) return false;
        return true;
      })
      .slice(0, limit);
    return { items, nextCursor: null, count: items.length };
  }

  async stats(query: StatsQuery): Promise<StatsResult> {
    const from = query.from ?? new Date(this.now().getTime() - 24 * 3600_000).toISOString();
    const to = query.to ?? this.now().toISOString();
    const totals = {
      received: 0,
      policy_evaluated: 0,
      rejected: 0,
      suppressed: 0,
      queued: 0,
      accepted: 0,
      delivered: 0,
      deferred: 0,
      failed: 0,
      bounced: 0,
    };
    for (const message of this.messages.values()) {
      if (message.tenantId !== query.tenantId) continue;
      if (message.createdAt < from || message.createdAt > to) continue;
      totals[normalizeStatus(message.status)] += 1;
    }
    return { window: { from, to }, totals, series: [], tenantId: query.tenantId };
  }

  /** Test helper: seed a message owned by a tenant. */
  seedMessage(message: StoredMessage): void {
    this.messages.set(message.id, message);
    this.byRequestId.set(`${message.tenantId}:${message.requestId}`, message.id);
  }

  /** Test helper: seed a bounce record. */
  seedBounce(bounce: BounceRecord): void {
    this.bounceRecords.push(bounce);
  }
}

/**
 * Deterministic identifier derived from the tenant and request id.
 *
 * The same logical send always yields the same message id, which keeps
 * idempotent replays and cross-surface correlation stable.
 */
function deterministicId(tenantId: string, requestId: string): string {
  return createHash("sha256")
    .update(`${tenantId}:${requestId}`)
    .digest("hex")
    .slice(0, 26);
}
