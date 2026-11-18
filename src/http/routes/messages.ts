// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * `GET /v1/messages` and `GET /v1/messages/{id}` — tenant-scoped message
 * inspection (§6.1, §6.2).
 */

import { canReadBody } from "../authorize.js";
import { HttpError } from "../errors.js";
import { etagOf, etagMatches, writeJson } from "../responses.js";
import type { RequestContext } from "../router.js";
import { projectMessage } from "../schemas/projection.js";
import type { HttpService } from "../service.js";
import type { MessageFilter, MessageStatus } from "../types.js";

/** Query parameters accepted by `GET /v1/messages`. */
const MESSAGE_QUERY_PARAMS = new Set([
  "status",
  "delivery",
  "recipient_hash",
  "from",
  "to",
  "domain",
  "request_id",
  "tag",
  "limit",
  "cursor",
  "include_body",
]);

/** Default and maximum page size. */
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

/** Handle `GET /v1/messages`. */
export async function handleListMessages(
  ctx: RequestContext,
  service: HttpService,
): Promise<void> {
  const principal = ctx.principal;
  if (!principal) {
    throw new HttpError(401, "UNAUTHENTICATED", "Authentication required.");
  }
  const filter = parseMessageQuery(ctx, service);
  const limit = parseLimit(ctx);
  const filterKey = filterFingerprint(filter);
  const cursor = ctx.query.get("cursor");
  const decoded = cursor ? service.decodeCursor(cursor, filterKey) : null;

  const page = await service.deps.messages.list(
    principal.tenant_id,
    filter,
    limit,
    decoded ? { created_at: decoded.created_at, id: decoded.id } : null,
  );

  const data = page.items.map((record) => projectMessage(record, false));
  const body = {
    data,
    page: {
      next_cursor:
        page.next_cursor ??
        (page.has_more && page.items.length > 0
          ? service.encodeCursor(filterKey, {
              created_at: (page.items[page.items.length - 1] as { created_at: string }).created_at,
              id: (page.items[page.items.length - 1] as { id: string }).id,
            })
          : null),
      has_more: page.has_more,
      limit,
    },
  };
  const etag = etagOf(body);
  if (etagMatches(ctx.req.headers["if-none-match"], etag)) {
    ctx.res.writeHead(304, { etag, "x-request-id": ctx.request_id });
    ctx.res.end();
    return;
  }
  writeJson(ctx.res, 200, body, { etag, "x-request-id": ctx.request_id });
}

/** Handle `GET /v1/messages/{id}`. */
export async function handleGetMessage(
  ctx: RequestContext,
  service: HttpService,
): Promise<void> {
  const principal = ctx.principal;
  if (!principal) {
    throw new HttpError(401, "UNAUTHENTICATED", "Authentication required.");
  }
  const id = ctx.params.id ?? "";
  // Cross-tenant access is indistinguishable from "not found" (§3.2).
  const record = await service.deps.messages.get(principal.tenant_id, id);
  if (!record) {
    throw new HttpError(404, "NOT_FOUND", "Message not found.");
  }
  const includeBody = ctx.query.get("include_body") === "true";
  const body = projectMessage(record, includeBody && canReadBody(principal));
  const etag = etagOf(body);
  if (etagMatches(ctx.req.headers["if-none-match"], etag)) {
    ctx.res.writeHead(304, { etag, "x-request-id": ctx.request_id });
    ctx.res.end();
    return;
  }
  writeJson(ctx.res, 200, body, { etag, "x-request-id": ctx.request_id });
}

/** Parse and validate the message list filters. */
export function parseMessageQuery(ctx: RequestContext, service: HttpService): MessageFilter {
  for (const key of ctx.query.keys()) {
    if (!MESSAGE_QUERY_PARAMS.has(key)) {
      throw new HttpError(400, "UNKNOWN_FILTER", `Unknown query parameter: ${key}.`);
    }
  }
  const filter: MessageFilter = {};
  const status = parseStatusList(ctx.query.getAll("status"));
  if (status) {
    filter.status = status;
  }
  const delivery = parseStatusList(ctx.query.getAll("delivery"));
  if (delivery) {
    filter.delivery = delivery;
  }
  const recipientHash = ctx.query.get("recipient_hash");
  if (recipientHash) {
    filter.recipient_hash = recipientHash;
  }
  const from = parseTimestamp(ctx.query.get("from"), "from");
  if (from) {
    filter.from = from;
  }
  const to = parseTimestamp(ctx.query.get("to"), "to");
  if (to) {
    filter.to = to;
  }
  const domain = ctx.query.get("domain");
  if (domain) {
    filter.domain = domain.toLowerCase();
  }
  const requestId = ctx.query.get("request_id");
  if (requestId) {
    filter.request_id = requestId;
  }
  const tags = ctx.query
    .getAll("tag")
    .flatMap((entry) => entry.split(","))
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (tags.length > 0) {
    filter.tag = tags;
  }
  void service;
  return filter;
}

/** Parse a multi-valued status filter. */
function parseStatusList(values: string[]): MessageStatus[] | undefined {
  const raw = values.flatMap((entry) => entry.split(","));
  const cleaned = raw.map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  if (cleaned.length === 0) {
    return undefined;
  }
  const valid = new Set<MessageStatus>([
    "received",
    "policy_evaluated",
    "queued",
    "accepted",
    "delivered",
    "deferred",
    "bounced",
    "failed",
    "rejected",
    "suppressed",
  ]);
  const out: MessageStatus[] = [];
  for (const entry of cleaned) {
    if (!valid.has(entry as MessageStatus)) {
      throw new HttpError(400, "INVALID_REQUEST", `Unknown status filter: ${entry}.`, {
        field: "status",
      });
    }
    out.push(entry as MessageStatus);
  }
  return out;
}

/** Parse an RFC3339 timestamp filter. */
function parseTimestamp(value: string | null, field: string): string | undefined {
  if (!value) {
    return undefined;
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new HttpError(400, "INVALID_REQUEST", `${field} must be an RFC3339 timestamp.`, {
      field,
    });
  }
  return new Date(parsed).toISOString();
}

/** Parse and validate the page size. */
export function parseLimit(ctx: RequestContext): number {
  const raw = ctx.query.get("limit");
  if (raw === null) {
    return DEFAULT_LIMIT;
  }
  if (!/^\d+$/.test(raw)) {
    throw new HttpError(400, "INVALID_LIMIT", "limit must be a non-negative integer.");
  }
  const limit = Number.parseInt(raw, 10);
  if (limit === 0 || limit > MAX_LIMIT) {
    throw new HttpError(400, "INVALID_LIMIT", `limit must be between 1 and ${MAX_LIMIT}.`);
  }
  return limit;
}

/** Fingerprint of the active filter set — binds a cursor to its filters. */
export function filterFingerprint(filter: MessageFilter): string {
  return JSON.stringify({
    status: filter.status ?? null,
    delivery: filter.delivery ?? null,
    recipient_hash: filter.recipient_hash ?? null,
    from: filter.from ?? null,
    to: filter.to ?? null,
    domain: filter.domain ?? null,
    request_id: filter.request_id ?? null,
    tag: filter.tag ?? null,
  });
}
