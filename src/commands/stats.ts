// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * `railgun stats` — the canonical delivery counters.
 *
 * `delivered` is only counted for a confirmed delivery. Queue acceptance,
 * SMTP acceptance and a durable enqueue are never presented as delivery.
 */
import { CliError } from "../cli/errors.js";
import { type CommandContext } from "../cli/context.js";
import { renderFields, renderJson } from "../cli/output.js";
import type { StatsProjection } from "../domain/types.js";
import { requireScope } from "../services/compose.js";

/** Filters accepted by `stats`. */
export interface StatsOptions {
  tenant?: string | undefined;
  since?: string | undefined;
  until?: string | undefined;
}

/** `railgun stats` */
export async function statsCommand(context: CommandContext, options: StatsOptions): Promise<number> {
  const stats = context.isRemote
    ? await context.remote().stats({
        tenant: options.tenant,
        since: options.since,
        until: options.until,
      })
    : statsLocal(context, options);

  context.channel.stdout(context.options.json ? renderJson(stats) : renderStats(stats));
  return 0;
}

function statsLocal(context: CommandContext, options: StatsOptions): StatsProjection {
  const services = context.services();
  requireScope(services.principal, "read");
  return services.store.stats({
    tenant: options.tenant,
    since: options.since,
    until: options.until,
  });
}

/**
 * Render the counters.
 *
 * The delivery line is explicit about what it counts so an operator never
 * reads a queued count as a delivered count.
 */
function renderStats(stats: StatsProjection): string {
  const fields: [string, string][] = [
    ["queued", String(stats.queued)],
    ["accepted", String(stats.accepted)],
    ["delivered", `${stats.delivered} (confirmed delivery only)`],
    ["deferred", String(stats.deferred)],
    ["bounced", String(stats.bounced)],
    ["suppressed", String(stats.suppressed)],
    ["rejected", String(stats.rejected)],
  ];
  if (stats.windowStart || stats.windowEnd) {
    fields.push(["window", `${stats.windowStart ?? "beginning"} .. ${stats.windowEnd ?? "now"}`]);
  }
  if (stats.tenant) {
    fields.push(["tenant", stats.tenant]);
  }
  return renderFields(fields);
}

/** Raise the stable insufficient-scope error. */
export function insufficientScope(scope: string): CliError {
  return new CliError({
    code: "INSUFFICIENT_SCOPE",
    message: `The principal does not hold the '${scope}' scope`,
    exitCode: 5,
    details: { required_scope: scope },
  });
}
