// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * `GET /v1/bounces` — tenant-scoped bounce list (§6.3).
 */

import { HttpError } from "../errors.js";
import { writeJson } from "../responses.js";
import type { RequestContext } from "../router.js";
import { projectBounce } from "../schemas/projection.js";
import type { HttpService } from "../service.js";

/** Query parameters accepted by `GET /v1/bounces`. */
const BOUNCE_QUERY_PARAMS = new Set([
  "from",
  "to",
  "domain",
  "code",
  "recipient_hash",
  "limit",
  "cursor",
]);

/** Handle `GET /v1/bounces`. */
export async function handleListBounces(
  ctx: RequestContext,
  service: HttpService,
): Promise<void> {
  const principal = ctx.principal;
  if (!principal) {
    throw new HttpError(401, "UNAUTHENTICATED", "Authentication required.");
  }
  for (const key of ctx.query.keys()) {
    if (!BOUNCE_QUERY_PARAMS.has(key)) {
      throw new HttpError(400, "UNKNOWN_FILTER", `Unknown query parameter: ${key}.`);
    }
  }
  const limit = parseLimit(ctx);
  const filter: {
    from?: string;
    to?: string;
    domain?: string;
    code?: string[];
    recipient_hash?: string;
  } = {};
  const from = ctx.query.get("from");
  if (from) {
    filter.from = parseTimestamp(from, "from");
  }
  const to = ctx.query.get("to");
  if (to) {
    filter.to = parseTimestamp(to, "to");
  }
  const domain = ctx.query.get("domain");
  if (domain) {
    filter.domain = domain.toLowerCase();
  }
  const codes = ctx.query
    .getAll("code")
    .flatMap((entry) => entry.split(","))
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (codes.length > 0) {
    filter.code = codes;
  }
  const recipientHash = ctx.query.get("recipient_hash");
  if (recipientHash) {
    filter.recipient_hash = recipientHash;
  }

  const filterKey = JSON.stringify(filter);
  const cursor = ctx.query.get("cursor");
  const decoded = cursor ? service.decodeCursor(cursor, filterKey) : null;
  const page = await service.deps.bounces.list(
    principal.tenant_id,
    filter,
    limit,
    decoded ? { occurred_at: decoded.created_at, id: decoded.id } : null,
  );
  const data = page.items.map((record) => projectBounce(record));
  writeJson(
    ctx.res,
    200,
    {
      data,
      page: {
        next_cursor:
          page.next_cursor ??
          (page.has_more && page.items.length > 0
            ? service.encodeCursor(filterKey, {
                created_at: (page.items[page.items.length - 1] as { occurred_at: string })
                  .occurred_at,
                id: (page.items[page.items.length - 1] as { id: string }).id,
              })
            : null),
        has_more: page.has_more,
        limit,
      },
    },
    { "x-request-id": ctx.request_id },
  );
}

/** Parse and validate the page size. */
function parseLimit(ctx: RequestContext): number {
  const raw = ctx.query.get("limit");
  if (raw === null) {
    return 50;
  }
  if (!/^\d+$/.test(raw)) {
    throw new HttpError(400, "INVALID_LIMIT", "limit must be a non-negative integer.");
  }
  const limit = Number.parseInt(raw, 10);
  if (limit === 0 || limit > 200) {
    throw new HttpError(400, "INVALID_LIMIT", "limit must be between 1 and 200.");
  }
  return limit;
}

/** Parse an RFC3339 timestamp filter. */
function parseTimestamp(value: string, field: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new HttpError(400, "INVALID_REQUEST", `${field} must be an RFC3339 timestamp.`, {
      field,
    });
  }
  return new Date(parsed).toISOString();
}
