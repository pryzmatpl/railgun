// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * `POST /v1/email/send` (and its `POST /send` alias) — protocol-compatible
 * email submission (§4).
 *
 * The route answers `202` with `status: "queued"` only after the message is
 * durably admitted to the queue. It never claims delivery: `deliveryConfirmed`
 * is `false` on a queued response.
 */

import { assertNoTenantOverride, assertSenderAllowed, domainOf } from "../authorize.js";
import { canonicalDigest } from "../crypto.js";
import { HttpError } from "../errors.js";
import { writeJson } from "../responses.js";
import type { RequestContext } from "../router.js";
import type { HttpService } from "../service.js";
import { parseSendRequest } from "../schemas/send.js";
import type { MessageRecord, PolicyDecision } from "../types.js";

/** Header carrying the explicit idempotency key (§5.1). */
export const IDEMPOTENCY_HEADER = "idempotency-key";

/** Handle a send request. */
export async function handleSend(ctx: RequestContext, service: HttpService): Promise<void> {
  const principal = ctx.principal;
  if (!principal) {
    throw new HttpError(401, "UNAUTHENTICATED", "Authentication required.");
  }

  const rawBody = parseJsonBody(ctx.body);
  assertNoTenantOverride(principal, rawBody);

  const idempotencyKey = ctx.headers["idempotency-key"];
  const request = parseSendRequest(rawBody, {
    now: service.now(),
    hasIdempotencyHeader: Boolean(idempotencyKey),
    max_body_bytes: service.config.max_body_bytes,
    max_attachment_bytes: service.config.max_attachment_bytes,
    max_recipients_per_message: service.config.max_recipients_per_message,
  });

  // Sender authorization (§3.4) happens before any queue write.
  const from = request.from ?? service.deps.domains.defaultSender(principal.tenant_id);
  if (!from) {
    throw new HttpError(400, "INVALID_REQUEST", "No default sender is configured for this tenant.", {
      field: "from",
    });
  }
  assertSenderAllowed(
    principal,
    from,
    service.deps.domains.verifiedSenderDomains(principal.tenant_id),
  );

  const senderDomain = domainOf(from);
  if (!service.deps.domains.isVerified(principal.tenant_id, senderDomain)) {
    throw new HttpError(409, "DOMAIN_NOT_VERIFIED", "The sending domain is not verified.", {
      domain: senderDomain,
    });
  }

  // Logical-send identity (§5.2): the body `request_id`, the idempotency
  // header, or — for the legacy Jaisiu body that carries neither — a digest
  // of the canonical request, so a repeated identical submission still
  // produces exactly one durable message.
  const logicalRequestId =
    request.request_id ??
    (idempotencyKey
      ? `idem:${idempotencyKey}`
      : `body:${canonicalDigest({ principal: principal.id, request })}`);
  // The header key is a second, independent identity (§5.3): it binds the
  // transport-level replay in the idempotency middleware, while
  // `logicalRequestId` binds the logical send.

  const existing = await service.deps.messages.findByRequestId(principal.tenant_id, logicalRequestId);
  if (existing) {
    writeJson(ctx.res, 202, submissionEnvelope(service, existing, principal.tenant_id), {
      location: `/v1/messages/${existing.id}`,
      "idempotency-replayed": "true",
      "x-request-id": ctx.request_id,
    });
    await service.audit({
      event: "idempotency.replayed",
      actor: principal.id,
      resource: existing.id,
      tenant_id: principal.tenant_id,
      request_id: ctx.request_id,
      outcome: "ok",
      detail: { layer: "request_id" },
    });
    return;
  }

  const decision = await service.deps.policy.evaluate({
    tenant_id: principal.tenant_id,
    principal,
    recipients: [...request.to, ...request.cc, ...request.bcc],
    subject: request.subject,
    text: request.text,
    html: request.html,
    from,
    size_bytes: Buffer.byteLength(request.text ?? "") + Buffer.byteLength(request.html ?? ""),
  });

  if (decision.rejection) {
    throw new HttpError(
      422,
      decision.rejection.code as "SPAM_POLICY_DENIED",
      "The message was rejected by policy.",
      decision.rejection.details,
    );
  }

  const accepted = decision.recipients.filter((entry) => entry.allowed);
  const rejected = decision.recipients.filter((entry) => !entry.allowed);
  if (accepted.length === 0) {
    throw rejectionError(rejected);
  }

  const now = service.nowIso();
  const messageId = service.deps.ids.messageId(principal.tenant_id, logicalRequestId);
  const record: MessageRecord = {
    id: messageId,
    tenant_id: principal.tenant_id,
    request_id: logicalRequestId,
    from_addr: from,
    to_addr: request.to[0] ?? "",
    cc_addrs: request.cc,
    bcc_addrs: request.bcc,
    recipient_hashes: request.to.map((entry) => service.recipientHash(principal.tenant_id, entry)),
    subject: request.subject,
    status: "queued",
    delivery: "queued",
    deliveryConfirmed: false,
    smtp_code: null,
    smtp_response: null,
    dkim_signed: false,
    mode: "direct",
    attempts: 0,
    last_error: null,
    tags: Object.keys(request.metadata),
    created_at: now,
    queued_at: now,
    accepted_at: null,
    delivered_at: null,
    updated_at: now,
    body_text: request.text,
    body_html: request.html,
    retryable: false,
  };

  await service.deps.messages.insert(record);
  for (const recipient of accepted) {
    await service.deps.queue.enqueue({
      tenant_id: principal.tenant_id,
      message_id: messageId,
      recipient: recipient.address,
      request_id: logicalRequestId,
      enqueued_at: now,
    });
  }

  await service.audit({
    event: "message.created",
    actor: principal.id,
    resource: messageId,
    tenant_id: principal.tenant_id,
    request_id: ctx.request_id,
    outcome: "ok",
    detail: { recipients: accepted.length, rejected: rejected.length },
  });
  service.deps.metrics?.observeSend("queued");

  const body = submissionEnvelope(service, record, principal.tenant_id);
  if (rejected.length > 0) {
    body.recipients = [
      ...accepted.map((entry) => ({ address: entry.address, status: "queued" })),
      ...rejected.map((entry) => ({
        address: entry.address,
        status: entry.status,
        reason: entry.reason,
      })),
    ];
  }

  writeJson(ctx.res, 202, body, {
    location: `/v1/messages/${messageId}`,
    "x-request-id": ctx.request_id,
  });
}

/**
 * The canonical `202` submission envelope (§4.3).
 *
 * `deliveryConfirmed` is `false`: acceptance is never delivery.
 */
export function submissionEnvelope(
  service: HttpService,
  record: MessageRecord,
  tenant_id: string,
): Record<string, unknown> {
  return {
    success: true,
    id: record.id,
    messageId: service.deps.ids.messageIdHeader(record.id),
    status: record.status,
    delivery: record.delivery,
    deliveryConfirmed: record.deliveryConfirmed,
    request_id: record.request_id,
    tenant_id: tenant_id,
    created_at: record.created_at,
    queued_at: record.queued_at,
    accepted_at: record.accepted_at,
    relayHost: null,
    mode: record.mode,
  };
}

/** Parse a JSON body, rejecting malformed payloads. */
export function parseJsonBody(body: Buffer): Record<string, unknown> {
  if (body.length === 0) {
    throw new HttpError(400, "INVALID_REQUEST", "A JSON request body is required.", { field: "body" });
  }
  try {
    const parsed = JSON.parse(body.toString("utf8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new HttpError(400, "INVALID_REQUEST", "The request body must be a JSON object.", {
        field: "body",
      });
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof HttpError) {
      throw error;
    }
    throw new HttpError(400, "INVALID_REQUEST", "The request body is not valid JSON.", {
      field: "body",
    });
  }
}

/**
 * Build the error for a fully rejected send (§4.4 "Partial acceptance").
 *
 * The highest-severity rejection wins: the first non-`SUPPRESSED` rejection,
 * else `SUPPRESSED`.
 */
function rejectionError(rejected: Array<PolicyDecision["recipients"][number]>): HttpError {
  const first = rejected[0];
  const code = (first?.error_code ?? "SUPPRESSED") as "SUPPRESSED" | "BLOCKED";
  return new HttpError(422, code, "The message was rejected for every recipient.", {
    ...first?.details,
    ...(first?.reason ? { reason: first.reason } : {}),
  });
}
