// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * `POST /v1/messages/{id}/retry` and `POST /v1/messages/{id}/suppress` —
 * operator actions (§5.4, §5.5).
 */

import { HttpError } from "../errors.js";
import { writeJson } from "../responses.js";
import type { RequestContext } from "../router.js";
import type { HttpService } from "../service.js";
import type { SuppressionRecord } from "../types.js";

/** Statuses a message may be requeued from. */
const RETRYABLE_STATUSES = new Set(["bounced", "deferred", "failed", "suppressed"]);

/** Handle `POST /v1/messages/{id}/retry`. */
export async function handleRetry(ctx: RequestContext, service: HttpService): Promise<void> {
  const principal = ctx.principal;
  if (!principal) {
    throw new HttpError(401, "UNAUTHENTICATED", "Authentication required.");
  }
  const idempotencyKey = ctx.headers["idempotency-key"];
  if (!idempotencyKey) {
    throw new HttpError(400, "INVALID_REQUEST", "An Idempotency-Key header is required.", {
      field: "idempotency-key",
    });
  }
  const id = ctx.params.id ?? "";
  const record = await service.deps.messages.get(principal.tenant_id, id);
  if (!record) {
    throw new HttpError(404, "NOT_FOUND", "Message not found.");
  }
  const force = ctx.query.get("force") === "true";
  if (!force && !RETRYABLE_STATUSES.has(record.status)) {
    throw new HttpError(409, "MESSAGE_NOT_RETRYABLE", "The message is not in a retryable state.");
  }

  const now = service.nowIso();
  const updated = await service.deps.messages.update(principal.tenant_id, id, {
    status: "queued",
    delivery: "queued",
    attempts: 0,
    queued_at: now,
    updated_at: now,
    last_error: null,
  });
  if (!updated) {
    throw new HttpError(404, "NOT_FOUND", "Message not found.");
  }
  for (const recipient of [record.to_addr, ...record.cc_addrs, ...record.bcc_addrs]) {
    if (!recipient) {
      continue;
    }
    await service.deps.queue.enqueue({
      tenant_id: principal.tenant_id,
      message_id: id,
      recipient,
      request_id: `${record.request_id}:retry:${now}`,
      enqueued_at: now,
    });
  }
  await service.audit({
    event: "message.retried",
    actor: principal.id,
    resource: id,
    tenant_id: principal.tenant_id,
    request_id: ctx.request_id,
    outcome: "ok",
    detail: { forced: force },
  });

  writeJson(
    ctx.res,
    202,
    {
      ok: true,
      id,
      status: "queued",
      attempts_reset: true,
      request_id: ctx.request_id,
    },
    { "x-request-id": ctx.request_id },
  );
}

/** Handle `POST /v1/messages/{id}/suppress`. */
export async function handleSuppress(ctx: RequestContext, service: HttpService): Promise<void> {
  const principal = ctx.principal;
  if (!principal) {
    throw new HttpError(401, "UNAUTHENTICATED", "Authentication required.");
  }
  const idempotencyKey = ctx.headers["idempotency-key"];
  if (!idempotencyKey) {
    throw new HttpError(400, "INVALID_REQUEST", "An Idempotency-Key header is required.", {
      field: "idempotency-key",
    });
  }
  const id = ctx.params.id ?? "";
  const record = await service.deps.messages.get(principal.tenant_id, id);
  if (!record) {
    throw new HttpError(404, "NOT_FOUND", "Message not found.");
  }

  const raw = parseOptionalJson(ctx.body);
  const email = typeof raw.email === "string" && raw.email.trim() ? raw.email.trim().toLowerCase() : null;
  const reason = parseReason(raw.reason);
  const scope = raw.scope === "domain" ? "domain" : "global";
  const domain =
    scope === "domain"
      ? typeof raw.domain === "string" && raw.domain.trim()
        ? raw.domain.trim().toLowerCase()
        : null
      : null;
  if (scope === "domain" && !domain) {
    throw new HttpError(400, "INVALID_REQUEST", "domain is required when scope is domain.", {
      field: "domain",
    });
  }
  const expiresAt =
    typeof raw.expires_at === "string" && raw.expires_at.trim() ? raw.expires_at.trim() : null;
  const detail = typeof raw.detail === "string" ? raw.detail : null;

  const targets = email ? [email] : [record.to_addr, ...record.cc_addrs];
  const created: SuppressionRecord[] = [];
  let wasCreated = false;
  for (const target of targets) {
    if (!target) {
      continue;
    }
    const existing = await service.deps.suppressions.get(principal.tenant_id, target, scope, domain);
    if (existing && existing.expires_at === null && expiresAt !== null) {
      if (ctx.query.get("override") !== "true") {
        throw new HttpError(
          409,
          "SUPPRESSION_CONFLICT",
          "The existing permanent suppression cannot be shortened.",
        );
      }
    }
    const outcome = await service.deps.suppressions.upsert({
      id: existing?.id ?? `sup_${service.deps.ids.requestId()}`,
      tenant_id: principal.tenant_id,
      email: target,
      reason,
      scope,
      domain,
      expires_at: expiresAt,
      detail,
      created_at: existing?.created_at ?? service.nowIso(),
    });
    created.push(outcome.record);
    wasCreated = wasCreated || outcome.created;
  }

  await service.deps.messages.update(principal.tenant_id, id, {
    status: "suppressed",
    delivery: "suppressed",
    updated_at: service.nowIso(),
  });
  await service.audit({
    event: "message.suppressed",
    actor: principal.id,
    resource: id,
    tenant_id: principal.tenant_id,
    request_id: ctx.request_id,
    outcome: "ok",
    detail: { count: created.length, scope },
  });

  writeJson(
    ctx.res,
    200,
    {
      ok: true,
      created: wasCreated,
      suppressions: created.map((entry) => ({
        id: entry.id,
        email: entry.email,
        reason: entry.reason,
        scope: entry.scope,
        domain: entry.domain,
        expires_at: entry.expires_at,
        created_at: entry.created_at,
      })),
      request_id: ctx.request_id,
    },
    { "x-request-id": ctx.request_id },
  );
}

/** Parse an optional JSON body. */
function parseOptionalJson(body: Buffer): Record<string, unknown> {
  if (body.length === 0) {
    return {};
  }
  try {
    const parsed = JSON.parse(body.toString("utf8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    return parsed as Record<string, unknown>;
  } catch {
    throw new HttpError(400, "INVALID_REQUEST", "The request body is not valid JSON.", {
      field: "body",
    });
  }
}

/** Validate the suppression reason. */
function parseReason(raw: unknown): SuppressionRecord["reason"] {
  const allowed: SuppressionRecord["reason"][] = [
    "manual",
    "hard_bounce",
    "soft_bounce",
    "complaint",
    "unsubscribe",
  ];
  if (typeof raw === "string" && allowed.includes(raw as SuppressionRecord["reason"])) {
    return raw as SuppressionRecord["reason"];
  }
  return "manual";
}
