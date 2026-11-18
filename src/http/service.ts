// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * The HTTP service container: every port the routes need, plus the shared
 * helpers (JSON writing, pagination, rate limiting).
 */

import type { AuditLog, BounceStore, Clock, HttpConfig, IdempotencyStore, MessageStore, OutboxQueue, PolicyEngine, DomainRegistry, ReadinessProbe, SuppressionStore } from "./types.js";
import type { CredentialStore, JwtVerifier } from "./auth.js";
import type { IdGenerator } from "./types.js";
import { decodeCursor, encodeCursor, recipientHash as hashRecipient } from "./crypto.js";
import { HttpError } from "./errors.js";

export interface HttpServiceDeps {
  config: HttpConfig;
  clock: Clock;
  ids: IdGenerator;
  messages: MessageStore;
  bounces: BounceStore;
  suppressions: SuppressionStore;
  idempotency: IdempotencyStore;
  queue: OutboxQueue;
  audit: AuditLog;
  policy: PolicyEngine;
  domains: DomainRegistry;
  credentials: CredentialStore;
  jwt: JwtVerifier | null;
  readiness: ReadinessProbe[];
  /** Tenant-scoped secret used to pseudonymize recipients. */
  tenantSecret: (tenant_id: string) => string;
  /** Optional metrics sink; the service renders Prometheus text itself. */
  metrics?: MetricsSink;
}

/** Minimal metrics sink owned by the HTTP surface. */
export interface MetricsSink {
  observeRequest(route: string, method: string, status: number, duration_ms: number): void;
  observeSend(status: string): void;
  render(): string;
}

/** Shared state available to every route handler. */
export class HttpService {
  readonly deps: HttpServiceDeps;

  constructor(deps: HttpServiceDeps) {
    this.deps = deps;
  }

  get config(): HttpConfig {
    return this.deps.config;
  }

  now(): Date {
    return this.deps.clock.now();
  }

  nowIso(): string {
    return this.deps.clock.now().toISOString();
  }

  /** Pseudonymize a recipient address with the tenant-scoped secret. */
  recipientHash(tenant_id: string, email: string): string {
    return hashRecipient(this.deps.tenantSecret(tenant_id), email);
  }

  /** Encode a pagination cursor bound to a filter set. */
  encodeCursor(filterKey: string, row: { created_at: string; id: string }): string {
    return encodeCursor(this.config.cursor_secret, {
      ts: row.created_at,
      id: row.id,
      f: filterKey,
    });
  }

  /** Decode a pagination cursor and verify it is bound to `filterKey`. */
  decodeCursor(
    cursor: string,
    filterKey: string,
  ): { created_at: string; id: string } {
    const decoded = decodeCursor(this.config.cursor_secret, cursor);
    if (!decoded || decoded.f !== filterKey) {
      throw new HttpError(400, "INVALID_CURSOR", "The cursor is invalid or does not match the filters.");
    }
    return { created_at: decoded.ts, id: decoded.id };
  }

  /** Append an audit record (§9.3). */
  async audit(record: {
    event: string;
    actor: string;
    resource?: string | null;
    tenant_id?: string | null;
    request_id: string;
    outcome: "ok" | "denied" | "error";
    detail?: Record<string, unknown>;
  }): Promise<void> {
    await this.deps.audit.append({
      ts: this.nowIso(),
      event: record.event,
      actor: record.actor,
      resource: record.resource ?? null,
      tenant_id: record.tenant_id ?? null,
      request_id: record.request_id,
      outcome: record.outcome,
      detail: record.detail ?? {},
    });
  }
}
