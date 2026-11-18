// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * `GET /v1/stats` — tenant-scoped aggregates (§6.4).
 */

import { HttpError } from "../errors.js";
import { writeJson } from "../responses.js";
import type { RequestContext } from "../router.js";
import type { HttpService } from "../service.js";

/** Query parameters accepted by `GET /v1/stats`. */
const STATS_QUERY_PARAMS = new Set(["from", "to", "domain", "group_by"]);

/** Handle `GET /v1/stats`. */
export async function handleStats(ctx: RequestContext, service: HttpService): Promise<void> {
  const principal = ctx.principal;
  if (!principal) {
    throw new HttpError(401, "UNAUTHENTICATED", "Authentication required.");
  }
  for (const key of ctx.query.keys()) {
    if (!STATS_QUERY_PARAMS.has(key)) {
      throw new HttpError(400, "UNKNOWN_FILTER", `Unknown query parameter: ${key}.`);
    }
  }
  const from = ctx.query.get("from");
  const to = ctx.query.get("to");
  const domain = ctx.query.get("domain");
  const groupByRaw = ctx.query.get("group_by") ?? "day";
  if (!["status", "domain", "day", "tag"].includes(groupByRaw)) {
    throw new HttpError(400, "INVALID_REQUEST", "group_by must be status, domain, day or tag.", {
      field: "group_by",
    });
  }
  const window: { from?: string; to?: string; domain?: string } = {};
  if (from) {
    window.from = parseTimestamp(from, "from");
  }
  if (to) {
    window.to = parseTimestamp(to, "to");
  }
  if (domain) {
    window.domain = domain.toLowerCase();
  }

  const aggregate = await service.deps.messages.aggregate(
    principal.tenant_id,
    window,
    groupByRaw as "status" | "domain" | "day" | "tag",
  );
  writeJson(
    ctx.res,
    200,
    {
      from: window.from ?? null,
      to: window.to ?? null,
      totals: aggregate.totals,
      buckets: aggregate.buckets,
    },
    { "x-request-id": ctx.request_id },
  );
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
