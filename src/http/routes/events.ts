// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * `POST /v1/events` — inbound DSN/feedback webhook (§7).
 *
 * Authentication is by shared secret / HMAC (`X-RailGun-Signature` +
 * `X-RailGun-Timestamp`), never by API key alone. Ingestion is idempotent on
 * the DSN's original message id + recipient, so a redelivered DSN neither
 * double-counts nor double-suppresses.
 */

import { verifyWebhookHmac } from "../auth.js";
import { HttpError } from "../errors.js";
import { writeJson } from "../responses.js";
import type { RequestContext } from "../router.js";
import type { HttpService } from "../service.js";
import type { BounceRecord, SuppressionRecord } from "../types.js";

interface DsnEvent {
  message_id: string;
  request_id?: string;
  recipient?: string;
  recipient_hash?: string;
  code: string;
  reason?: string;
  remote_mta?: string;
  occurred_at?: string;
}

/** Handle `POST /v1/events`. */
export async function handleEvents(ctx: RequestContext, service: HttpService): Promise<void> {
  const principal = ctx.principal;
  const secret = service.config.webhook_secret;
  if (secret) {
    verifyWebhookHmac(ctx.headers, ctx.body, secret, service.now());
  } else if (!principal) {
    throw new HttpError(401, "UNAUTHENTICATED", "Authentication required.");
  }
  const tenantId = principal?.tenant_id ?? "default";

  const events = parseEvents(ctx.body);
  const suppressed: string[] = [];
  const deferred: string[] = [];
  const ignored: string[] = [];

  for (const event of events) {
    if (!event.message_id) {
      ignored.push("missing_message_id");
      continue;
    }
    const recipientHash =
      event.recipient_hash ??
      (event.recipient
        ? service.recipientHash(tenantId, event.recipient)
        : `sha256:${event.message_id}`);

    const seen = await service.deps.bounces.hasSeen(tenantId, event.message_id, recipientHash);
    if (seen) {
      ignored.push("duplicate");
      continue;
    }

    const enhanced = event.code;
    const hard = enhanced.startsWith("5.");
    const record: BounceRecord = {
      id: `bnc_${service.deps.ids.requestId()}`,
      tenant_id: tenantId,
      message_id: event.message_id,
      request_id: event.request_id ?? "",
      recipient_hash: recipientHash,
      code: enhanced,
      enhanced_code: enhanced,
      class: hard ? "hard" : "soft",
      reason: event.reason ?? (hard ? "mailbox_does_not_exist" : "temporary_failure"),
      remote_mta: event.remote_mta ?? "",
      action_taken: hard ? "suppressed" : "deferred",
      occurred_at: event.occurred_at ?? service.nowIso(),
    };
    await service.deps.bounces.insert(record);

    if (hard && event.recipient) {
      const existing = await service.deps.suppressions.get(tenantId, event.recipient, "global");
      const suppression: SuppressionRecord = {
        id: existing?.id ?? `sup_${service.deps.ids.requestId()}`,
        tenant_id: tenantId,
        email: event.recipient.toLowerCase(),
        reason: "hard_bounce",
        scope: "global",
        domain: null,
        expires_at: null,
        detail: null,
        created_at: existing?.created_at ?? service.nowIso(),
      };
      await service.deps.suppressions.upsert(suppression);
      suppressed.push(event.recipient);
    } else {
      deferred.push(event.message_id);
    }
  }

  await service.audit({
    event: "feedback.ingested",
    actor: principal?.id ?? "webhook",
    resource: null,
    tenant_id: principal?.tenant_id ?? null,
    request_id: ctx.request_id,
    outcome: "ok",
    detail: { parsed: events.length, suppressed: suppressed.length, deferred: deferred.length },
  });

  writeJson(
    ctx.res,
    202,
    {
      ok: true,
      parsed: events.length,
      suppressed,
      deferred,
      ignored,
      report_id: `rpt_${service.deps.ids.requestId()}`,
    },
    { "x-request-id": ctx.request_id },
  );
}

/** Parse the webhook body — a JSON object, a JSON array, or a raw DSN blob. */
export function parseEvents(body: Buffer): DsnEvent[] {
  const text = body.toString("utf8").trim();
  if (!text) {
    return [];
  }
  if (text.startsWith("[") || text.startsWith("{")) {
    try {
      const parsed = JSON.parse(text) as unknown;
      const entries = Array.isArray(parsed) ? parsed : [parsed];
      const out: DsnEvent[] = [];
      for (const entry of entries) {
        if (!entry || typeof entry !== "object") {
          continue;
        }
        const record = entry as Record<string, unknown>;
        out.push({
          message_id: typeof record.message_id === "string" ? record.message_id : "",
          request_id: typeof record.request_id === "string" ? record.request_id : undefined,
          recipient: typeof record.recipient === "string" ? record.recipient : undefined,
          recipient_hash:
            typeof record.recipient_hash === "string" ? record.recipient_hash : undefined,
          code: typeof record.code === "string" ? record.code : "4.0.0",
          reason: typeof record.reason === "string" ? record.reason : undefined,
          remote_mta: typeof record.remote_mta === "string" ? record.remote_mta : undefined,
          occurred_at: typeof record.occurred_at === "string" ? record.occurred_at : undefined,
        });
      }
      return out;
    } catch {
      throw new HttpError(400, "INVALID_REQUEST", "The event body is not valid JSON.", {
        field: "body",
      });
    }
  }
  // A raw RFC 3464 multipart/report is accepted; only the enhanced status
  // code and the original message id are extracted. The raw body is never
  // echoed back.
  const code = /Status:\s*([245]\.\d+\.\d+)/i.exec(text)?.[1] ?? "4.0.0";
  const originalMessageId = /Original-Message-ID:\s*<?([^>\s]+)>?/i.exec(text)?.[1] ?? "";
  const finalRecipient = /Final-Recipient:\s*[^;]+;\s*([^\s]+)/i.exec(text)?.[1] ?? "";
  return [
    {
      message_id: originalMessageId,
      recipient: finalRecipient || undefined,
      code,
    },
  ];
}
