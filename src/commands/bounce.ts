// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * `railgun bounce list` — sanitized delivery feedback.
 *
 * The projection excludes message bodies, SMTP AUTH transcripts and secrets.
 * Bounce classification (permanent versus temporary) stays with the bounce
 * store and the delivery engine; the CLI only renders what it reports.
 */
import { type CommandContext } from "../cli/context.js";
import { renderJson, renderTable } from "../cli/output.js";
import type { BounceProjection } from "../domain/types.js";
import { requireScope } from "../services/compose.js";

/** Filters accepted by `bounce list`. */
export interface BounceListOptions {
  class?: "permanent" | "temporary" | undefined;
  since?: string | undefined;
  until?: string | undefined;
  limit: number;
  cursor?: string | undefined;
}

/** `railgun bounce list` */
export async function bounceList(
  context: CommandContext,
  options: BounceListOptions,
): Promise<number> {
  const page = context.isRemote
    ? await context.remote().listBounces({
        class: options.class,
        since: options.since,
        until: options.until,
        limit: String(options.limit),
        cursor: options.cursor,
      })
    : bounceListLocal(context, options);

  context.channel.stdout(
    context.options.json
      ? renderJson({
          items: page.items,
          next_cursor: page.nextCursor,
          total: page.total,
        })
      : renderBounces(page.items),
  );
  return 0;
}

function bounceListLocal(context: CommandContext, options: BounceListOptions) {
  const services = context.services();
  requireScope(services.principal, "read");
  return services.store.listBounces({
    class: options.class,
    since: options.since,
    until: options.until,
    limit: options.limit,
    cursor: options.cursor,
  });
}

/** Render the bounce list as an aligned table. */
function renderBounces(bounces: readonly BounceProjection[]): string {
  if (bounces.length === 0) {
    return "No bounces matched the filter.\n";
  }
  return renderTable(
    ["ID", "MESSAGE", "RECIPIENT", "CLASS", "STATUS", "AT"],
    bounces.map((bounce) => [
      bounce.id,
      bounce.messageId ?? "-",
      bounce.recipient,
      bounce.class,
      bounce.status ?? "-",
      bounce.at,
    ]),
  );
}
