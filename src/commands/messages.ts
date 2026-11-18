// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * `railgun messages` — list, show, retry and suppress.
 *
 * The commands project application state; they never reimplement validation,
 * status derivation or suppression policy.
 */
import { CliError } from "../cli/errors.js";
import { toCliError } from "../cli/service-error.js";
import { type CommandContext } from "../cli/context.js";
import { renderFields, renderJson, renderTable } from "../cli/output.js";
import { type MessageProjection, type RailGunStatus } from "../domain/types.js";
import { RAILGUN_STATUSES } from "../domain/status.js";
import { auditRecord, requireScope } from "../services/compose.js";

/** Filters accepted by `messages list`. */
export interface MessageListOptions {
  status?: string | undefined;
  tenant?: string | undefined;
  recipient?: string | undefined;
  since?: string | undefined;
  until?: string | undefined;
  limit: number;
  cursor?: string | undefined;
}

/**
 * Validate a status filter.
 *
 * An unknown status value is a usage error: the CLI must not silently list
 * everything because the operator mistyped the filter.
 */
export function parseStatusFilter(raw: string | undefined): RailGunStatus | undefined {
  if (raw === undefined) {
    return undefined;
  }
  const normalized = raw.trim().toLowerCase();
  if (!(RAILGUN_STATUSES as readonly string[]).includes(normalized)) {
    throw CliError.usage(
      `Unknown message status '${raw}': expected one of ${RAILGUN_STATUSES.join(", ")}`,
    );
  }
  return normalized as RailGunStatus;
}

/** `railgun messages list` */
export async function messagesList(
  context: CommandContext,
  options: MessageListOptions,
): Promise<number> {
  const status = parseStatusFilter(options.status);

  if (context.isRemote) {
    const page = await context.remote().listMessages({
      status,
      tenant: options.tenant,
      recipient: options.recipient,
      since: options.since,
      until: options.until,
      limit: String(options.limit),
      cursor: options.cursor,
    });
    context.channel.stdout(
      context.options.json
        ? renderJson({
            items: page.items,
            next_cursor: page.nextCursor,
            total: page.total,
          })
        : renderMessagesTable(page.items),
    );
    return 0;
  }

  const services = context.services();
  requireScope(services.principal, "read");
  const page = services.store.listMessages({
    status,
    tenant: options.tenant,
    recipient: options.recipient,
    since: options.since,
    until: options.until,
    limit: options.limit,
    cursor: options.cursor,
  });
  context.channel.stdout(
    context.options.json
      ? renderJson({
          items: page.items,
          next_cursor: page.nextCursor,
          total: page.total,
        })
      : renderMessagesTable(page.items),
  );
  return 0;
}

/** Render the message list as an aligned table. */
function renderMessagesTable(messages: readonly MessageProjection[]): string {
  if (messages.length === 0) {
    return "No messages matched the filter.\n";
  }
  return renderTable(
    ["ID", "STATUS", "DELIVERY", "RECIPIENTS", "ATTEMPTS", "CREATED"],
    messages.map((message) => [
      message.id,
      message.status,
      message.deliveryConfirmed ? "confirmed" : "not-confirmed",
      String(message.recipients.length),
      String(message.attempts),
      message.createdAt,
    ]),
  );
}

/** `railgun messages show <id>` */
export async function messagesShow(context: CommandContext, id: string): Promise<number> {
  if (!id) {
    throw CliError.usage("A message id is required");
  }

  const message = context.isRemote
    ? await context.remote().getMessage(id)
    : await showLocal(context, id);

  context.channel.stdout(
    context.options.json ? renderJson(message) : renderMessageDetail(message),
  );
  return 0;
}

async function showLocal(context: CommandContext, id: string): Promise<MessageProjection> {
  const services = context.services();
  requireScope(services.principal, "read");
  const message = services.store.getMessage(id);
  if (!message) {
    throw CliError.notFound(`Message not found: ${id}`, { message_id: id });
  }
  return message;
}

/**
 * Render a single message.
 *
 * The body is never rendered: the projection excludes it, and the CLI does not
 * add it back.
 */
function renderMessageDetail(message: MessageProjection): string {
  const fields: [string, string][] = [
    ["id", message.id],
    ["status", message.status],
    ["delivery", message.deliveryConfirmed ? "confirmed" : "not-confirmed"],
    ["message-id", message.messageId ?? "-"],
    ["tenant", message.tenant],
    ["subject", message.subject ?? "-"],
    ["from", message.from ?? "-"],
    ["attempts", String(message.attempts)],
    ["created", message.createdAt],
    ["updated", message.updatedAt],
    ["policy-reason", message.policyReason ?? "-"],
    ["last-response", message.lastResponse ?? "-"],
  ];
  let output = renderFields(fields);
  if (message.recipients.length > 0) {
    output += "\nrecipients\n";
    output += renderTable(
      ["ID", "RECIPIENT", "STATUS", "ATTEMPTS", "LAST REASON"],
      message.recipients.map((recipient) => [
        recipient.id,
        recipient.recipient,
        recipient.status,
        String(recipient.attempts),
        recipient.lastReason ?? "-",
      ]),
    );
  }
  return output;
}

/** `railgun messages retry <id>` */
export async function messagesRetry(context: CommandContext, id: string): Promise<number> {
  if (!id) {
    throw CliError.usage("A message id is required");
  }

  if (context.isRemote) {
    const message = await context.remote().retryMessage(id);
    context.channel.stdout(
      context.options.json ? renderJson(message) : renderRetryResult(message),
    );
    return 0;
  }

  const services = context.services();
  requireScope(services.principal, "admin");

  let message: MessageProjection;
  try {
    message = services.store.retryMessage(id);
  } catch (cause) {
    throw toCliError(cause);
  }
  services.store.appendAudit(
    auditRecord(services.principal, "message.retry", message.id, "manual_retry"),
  );
  context.channel.stdout(
    context.options.json ? renderJson(message) : renderRetryResult(message),
  );
  return 0;
}

/**
 * Render a retry result.
 *
 * A requeue is never presented as a delivery.
 */
function renderRetryResult(message: MessageProjection): string {
  return renderFields([
    ["id", message.id],
    ["status", message.status],
    ["delivery", message.deliveryConfirmed ? "confirmed" : "not-confirmed"],
    ["note", "the message was requeued; it is not delivered"],
  ]);
}

/** `railgun messages suppress <id>` */
export async function messagesSuppress(
  context: CommandContext,
  id: string,
  reason: string,
  expiresAt: string | null,
): Promise<number> {
  if (!id) {
    throw CliError.usage("A message id is required");
  }
  if (!reason) {
    throw CliError.usage("A suppression reason is required");
  }

  if (context.isRemote) {
    const message = await context.remote().suppressMessage(id, reason, expiresAt);
    context.channel.stdout(
      context.options.json ? renderJson(message) : renderSuppressResult(message, reason),
    );
    return 0;
  }

  const services = context.services();
  requireScope(services.principal, "admin");

  let message: MessageProjection;
  try {
    message = services.store.suppressMessage(id, reason, expiresAt);
  } catch (cause) {
    throw toCliError(cause);
  }
  services.store.appendAudit(
    auditRecord(services.principal, "message.suppress", message.id, reason),
  );
  context.channel.stdout(
    context.options.json ? renderJson(message) : renderSuppressResult(message, reason),
  );
  return 0;
}

function renderSuppressResult(message: MessageProjection, reason: string): string {
  return renderFields([
    ["id", message.id],
    ["status", message.status],
    ["reason", reason],
    ["delivery", message.deliveryConfirmed ? "confirmed" : "not-confirmed"],
  ]);
}
