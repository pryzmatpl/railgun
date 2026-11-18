// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * `railgun queue stats` — the durable outbox depth.
 *
 * The command is read-only and reports no message bodies and no
 * per-recipient high-cardinality labels.
 */
import { type CommandContext } from "../cli/context.js";
import { renderFields, renderJson, renderTable } from "../cli/output.js";
import type { QueueStatsProjection } from "../domain/types.js";
import { requireScope } from "../services/compose.js";

/** `railgun queue stats` */
export async function queueStats(context: CommandContext): Promise<number> {
  const stats = context.isRemote
    ? await context.remote().queueStats()
    : queueStatsLocal(context);

  context.channel.stdout(context.options.json ? renderJson(stats) : renderQueueStats(stats));
  return 0;
}

function queueStatsLocal(context: CommandContext): QueueStatsProjection {
  const services = context.services();
  requireScope(services.principal, "read");
  return services.store.queueStats();
}

/** Render the queue depth projection. */
function renderQueueStats(stats: QueueStatsProjection): string {
  let output = renderFields([
    ["depth", String(stats.depth)],
    ["due", String(stats.due)],
    ["leased", String(stats.leased)],
    ["scheduled", String(stats.scheduled)],
    ["oldest-queued-age", `${stats.oldestQueuedAgeSeconds}s`],
  ]);
  if (stats.destinations.length > 0) {
    output += "\ndestinations\n";
    output += renderTable(
      ["DESTINATION", "COUNT"],
      stats.destinations.map((entry) => [entry.destination, String(entry.count)]),
    );
  }
  return output;
}
