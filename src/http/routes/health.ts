// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * Health, readiness and metrics routes (§6.5, §6.6).
 *
 * `/health` and `/healthz` are exact aliases; `/ready` and `/readyz` are exact
 * aliases. A prefix match is forbidden.
 */

import { HttpError } from "../errors.js";
import { etagOf, etagMatches, writeJson, writeText } from "../responses.js";
import type { RequestContext } from "../router.js";
import type { HttpService } from "../service.js";

const startedAt = Date.now();

/** `GET /health` and `GET /healthz` — public liveness, touches nothing. */
export async function handleHealth(ctx: RequestContext, _service: HttpService): Promise<void> {
  const body = {
    status: "ok",
    ok: true,
    version: "1.0.0",
    uptime_s: Math.max(0, Math.floor((Date.now() - startedAt) / 1000)),
  };
  const etag = etagOf({ status: body.status, ok: body.ok, version: body.version });
  if (etagMatches(ctx.req.headers["if-none-match"], etag)) {
    ctx.res.writeHead(304, { etag, "x-request-id": ctx.request_id });
    ctx.res.end();
    return;
  }
  writeJson(ctx.res, 200, body, { etag, "x-request-id": ctx.request_id });
}

/** `GET /ready` and `GET /readyz` — readiness with per-dependency checks. */
export async function handleReady(ctx: RequestContext, service: HttpService): Promise<void> {
  const checks: Array<{ name: string; status: string; detail: string }> = [];
  for (const probe of service.deps.readiness) {
    try {
      const result = await probe.check();
      checks.push({ name: probe.name, status: result.status, detail: result.detail });
    } catch {
      checks.push({ name: probe.name, status: "error", detail: "unavailable" });
    }
  }
  let queueDepth = 0;
  try {
    queueDepth = await service.deps.queue.depth();
  } catch {
    queueDepth = 0;
  }
  const ok = !checks.some((check) => check.status === "error");
  const body = {
    ok,
    status: ok ? "ok" : "error",
    checks,
    queue_depth: queueDepth,
  };
  if (!ok) {
    const failing = checks.filter((check) => check.status === "error").map((check) => check.name);
    const error = new HttpError(503, "NOT_READY", "Service is not ready.", { checks: failing });
    const envelope = error.toEnvelope(ctx.request_id);
    writeJson(ctx.res, error.status, envelope, { ...error.headers, "x-request-id": ctx.request_id });
    return;
  }
  writeJson(ctx.res, 200, body, { "x-request-id": ctx.request_id });
}

/** `GET /metrics` — Prometheus text exposition. */
export async function handleMetrics(ctx: RequestContext, service: HttpService): Promise<void> {
  const rendered = service.deps.metrics?.render() ?? "";
  writeText(ctx.res, 200, rendered, {
    "content-type": "text/plain; version=0.0.4; charset=utf-8",
    "x-request-id": ctx.request_id,
  });
}
