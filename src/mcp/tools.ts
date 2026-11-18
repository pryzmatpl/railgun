// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * The four RailGun MCP tools (IR §2): `email_send`, `email_status`,
 * `email_bounces` and `email_stats`.
 *
 * The tool names are frozen and are identical across the stdio and streamable
 * HTTP transports. Handlers are projections of the application use cases: they
 * translate MCP requests into application commands and translate application
 * results into the canonical MCP envelopes.
 *
 * Every handler runs inside an authenticated `McpRequestContext`; the tenant is
 * always taken from that context and never from tool arguments.
 */

import type { McpRequestContext, Principal } from "./auth.js";
import { hashRecipient, requireAllowedSender, requireScope } from "./auth.js";
import type { EmailApplication } from "../application/ports.js";
import type { BounceRecord, StoredMessage } from "../domain/message.js";
import { isDeliveryConfirmed, normalizeStatus } from "../domain/status.js";
import { RailGunError } from "./errors.js";
import {
  DEFAULT_BOUNCE_LIMIT,
  DEFAULT_MAX_BOUNCE_LIMIT,
  emailBouncesInputSchema,
  emailSendInputSchema,
  emailStatsInputSchema,
  emailStatusInputSchema,
  normalizeSendInput,
  type SendToolLimits,
} from "./schemas.js";

export const RAILGUN_MCP_TOOL_NAMES = [
  "email_send",
  "email_status",
  "email_bounces",
  "email_stats",
] as const;

export type RailGunMcpToolName = (typeof RAILGUN_MCP_TOOL_NAMES)[number];

export interface McpToolOptions {
  readonly application: EmailApplication;
  /** Per-deployment salt used for tenant-scoped recipient hashing. */
  readonly recipientSalt: string;
  readonly limits?: SendToolLimits;
  /** Default stats window in hours when the caller supplies none. */
  readonly defaultStatsWindowHours?: number;
}

export interface ToolEnvelope {
  readonly content: readonly { readonly type: "text"; readonly text: string }[];
  readonly structuredContent: Readonly<Record<string, unknown>>;
  readonly isError?: boolean;
}

/** Result envelope for `email_send` (IR §3.2). */
export interface EmailSendEnvelope {
  readonly id: string;
  readonly status: string;
  readonly messageId: string;
  readonly delivery_confirmed: boolean;
  /** Legacy camelCase alias kept for Jaisiu-compatible clients. */
  readonly deliveryConfirmed: boolean;
  readonly requestId: string;
  readonly recipients: readonly { readonly address_hash: string; readonly status: string }[];
  readonly reason: string | null;
  readonly warnings: readonly string[];
}

/**
 * Reconstruct the principal view used for scope and sender checks from the
 * request context. The context carries the effective scopes and roles; the
 * capability flags are derived here so the checks stay transport-agnostic.
 */
function principalFromContext(context: McpRequestContext): Principal {
  return {
    principalId: context.principalId,
    tenantId: context.tenantId,
    roles: context.roles,
    scopes: context.scopes,
    // `sender_override` is an admin-only capability (IR §7.5).
    senderOverride: context.roles.includes("admin") && context.scopes.includes("admin"),
    // Body reads are default deny in v1 (IR §13.2).
    bodyRead: false,
    allowedSenders: context.allowedSenders ?? [],
  };
}

/** A tool handler bound to one request context. */
export type RailGunToolHandler = (
  args: unknown,
  context: McpRequestContext,
) => Promise<ToolEnvelope>;

export interface ToolRegistration {
  readonly name: string;
  readonly config: Record<string, unknown>;
  readonly handler: RailGunToolHandler;
}

function jsonEnvelope(value: unknown): ToolEnvelope {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    structuredContent: value as Record<string, unknown>,
  };
}

interface SchemaLike<T> {
  safeParse(input: unknown): {
    success: boolean;
    data?: T;
    error?: { issues?: readonly { path?: readonly unknown[]; message?: string }[] };
  };
}

function parseWith<T>(schema: SchemaLike<T>, input: unknown, field: string): T {
  const result = schema.safeParse(input);
  if (!result.success || result.data === undefined) {
    const issue = result.error?.issues?.[0];
    const path = issue?.path?.length ? String(issue.path[0]) : field;
    throw new RailGunError(
      "VALIDATION_FAILED",
      issue?.message ?? `Invalid ${field} arguments.`,
      { field: path },
    );
  }
  return result.data;
}

/** Build the `email_send` result envelope from an application outcome. */
export function buildSendEnvelope(
  outcome: {
    readonly id: string;
    readonly status: string;
    readonly messageId: string;
    readonly requestId: string;
    readonly recipients: readonly { readonly address: string; readonly status: string }[];
    readonly reason: string | null;
    readonly warnings: readonly string[];
  },
  tenantId: string,
  recipientSalt: string,
): EmailSendEnvelope {
  const status = normalizeStatus(outcome.status);
  const confirmed = isDeliveryConfirmed(status);
  return {
    id: outcome.id,
    status,
    messageId: outcome.messageId,
    delivery_confirmed: confirmed,
    deliveryConfirmed: confirmed,
    requestId: outcome.requestId,
    recipients: outcome.recipients.map((recipient) => ({
      address_hash: hashRecipient(recipient.address, tenantId, recipientSalt),
      status: normalizeStatus(recipient.status),
    })),
    reason: outcome.reason,
    warnings: outcome.warnings,
  };
}

/** Build the `email_status` result envelope from a stored message. */
export function buildStatusEnvelope(
  message: StoredMessage,
  tenantId: string,
  recipientSalt: string,
): Record<string, unknown> {
  const status = normalizeStatus(message.status);
  const confirmed = isDeliveryConfirmed(status);
  return {
    id: message.id,
    status,
    delivery_confirmed: confirmed,
    deliveryConfirmed: confirmed,
    requestId: message.requestId,
    messageId: message.messageId,
    created_at: message.createdAt,
    updated_at: message.updatedAt,
    attempts: message.attempts,
    next_attempt_at: message.nextAttemptAt,
    recipients: message.envelope.recipients.map((recipient) => ({
      address_hash: hashRecipient(recipient.address, tenantId, recipientSalt),
      status: normalizeStatus(recipient.status),
      attempts: recipient.attempts,
    })),
    attempt_history: message.attemptHistory.map((attempt) => ({
      attempted_at: attempt.attemptedAt,
      attempt: attempt.attempt,
      outcome: normalizeStatus(attempt.outcome),
      smtp_code: attempt.smtpCode,
      reason: attempt.reason,
    })),
    last_smtp_code: message.lastSmtpCode,
    last_error_class: message.lastErrorClass,
    reason: message.reason,
    warnings: [],
  };
}

/** Build the `email_bounces` result envelope from a bounce page. */
export function buildBouncesEnvelope(
  page: {
    readonly items: readonly BounceRecord[];
    readonly nextCursor: string | null;
    readonly count: number;
  },
  tenantId: string,
  recipientSalt: string,
): Record<string, unknown> {
  return {
    items: page.items.map((bounce) => ({
      message_id: bounce.messageId,
      recipient_hash: hashRecipient(bounce.recipient, tenantId, recipientSalt),
      occurred_at: bounce.occurredAt,
      code: bounce.code,
      reason: bounce.reason,
      permanent: bounce.permanent,
      diagnostic: bounce.diagnostic,
    })),
    next_cursor: page.nextCursor,
    count: page.count,
  };
}

/**
 * Build the four tool registrations.
 *
 * `email_send` requires the `send` scope; the three read tools require `read`.
 * A principal without the scope receives `FORBIDDEN` naming the missing scope.
 */
export function buildToolRegistrations(options: McpToolOptions): ToolRegistration[] {
  const { application } = options;
  const limits = options.limits;
  const recipientSalt = options.recipientSalt;
  const defaultStatsWindowHours = options.defaultStatsWindowHours ?? 24;

  const emailSend: ToolRegistration = {
    name: "email_send",
    config: {
      title: "Send email",
      description:
        "Submit an email for durable queueing through RailGun. Returns queued acceptance, not a guarantee of delivery.",
      inputSchema: emailSendInputSchema,
    },
    handler: async (args, context) => {
      requireScope(principalFromContext(context), "send");
      const input = normalizeSendInput(args, limits);
      requireAllowedSender(principalFromContext(context), input.from);

      const outcome = await application.send({
        tenantId: context.tenantId,
        principalId: context.principalId,
        to: input.to,
        cc: input.cc,
        bcc: input.bcc,
        subject: input.subject,
        text: input.text,
        html: input.html,
        from: input.from,
        replyTo: input.replyTo,
        requestId: input.requestId,
        metadata: input.metadata,
      });

      return jsonEnvelope(
        buildSendEnvelope(outcome, context.tenantId, recipientSalt),
      );
    },
  };

  const emailStatus: ToolRegistration = {
    name: "email_status",
    config: {
      title: "Email status",
      description:
        "Retrieve the delivery status of a RailGun message owned by the caller's tenant.",
      inputSchema: emailStatusInputSchema,
    },
    handler: async (args, context) => {
      requireScope(principalFromContext(context), "read");
      const parsed = parseWith(emailStatusInputSchema, args, "arguments");
      const message = await application.status({
        tenantId: context.tenantId,
        principalId: context.principalId,
        id: parsed.id,
        requestId: parsed.requestId,
      });
      if (!message) {
        // Cross-tenant identifiers behave as non-existent (IR §7.4).
        throw new RailGunError("NOT_FOUND", "No such message.");
      }
      return jsonEnvelope(
        buildStatusEnvelope(message, context.tenantId, recipientSalt),
      );
    },
  };

  const emailBounces: ToolRegistration = {
    name: "email_bounces",
    config: {
      title: "Email bounces",
      description:
        "List bounce records for the caller's tenant with sanitized DSN codes.",
      inputSchema: emailBouncesInputSchema,
    },
    handler: async (args, context) => {
      requireScope(principalFromContext(context), "read");
      const parsed = parseWith(emailBouncesInputSchema, args, "arguments");
      const limit = Math.min(parsed.limit ?? DEFAULT_BOUNCE_LIMIT, DEFAULT_MAX_BOUNCE_LIMIT);
      const page = await application.bounces({
        tenantId: context.tenantId,
        principalId: context.principalId,
        limit,
        cursor: parsed.cursor,
        since: parsed.since,
        until: parsed.until,
        recipientHash: parsed.recipientHash,
        reason: parsed.reason,
      });
      return jsonEnvelope(
        buildBouncesEnvelope(page, context.tenantId, recipientSalt),
      );
    },
  };

  const emailStats: ToolRegistration = {
    name: "email_stats",
    config: {
      title: "Email statistics",
      description:
        "Aggregate sending statistics for the caller's tenant over a time window.",
      inputSchema: emailStatsInputSchema,
    },
    handler: async (args, context) => {
      requireScope(principalFromContext(context), "read");
      const parsed = parseWith(emailStatsInputSchema, args, "arguments");
      const now = Date.now();
      const to = parsed.to ?? new Date(now).toISOString();
      const from =
        parsed.from ??
        new Date(now - defaultStatsWindowHours * 60 * 60 * 1000).toISOString();
      const stats = await application.stats({
        tenantId: context.tenantId,
        principalId: context.principalId,
        from,
        to,
        groupBy: parsed.groupBy ?? "none",
      });
      return jsonEnvelope({
        window: { from: stats.window.from, to: stats.window.to },
        totals: stats.totals,
        series: stats.series,
        tenant_id: stats.tenantId,
      });
    },
  };

  return [emailSend, emailStatus, emailBounces, emailStats];
}

export { requireAllowedSender, requireScope };
