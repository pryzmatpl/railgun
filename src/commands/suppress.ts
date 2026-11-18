// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * `railgun suppress add` — add a suppression entry.
 *
 * The CLI validates the address syntax and the reason token, then delegates to
 * the suppression store, which owns normalization, expiry rules and conflict
 * handling. The CLI never reimplements bounce-triggered suppression.
 */
import { CliError } from "../cli/errors.js";
import { toCliError } from "../cli/service-error.js";
import { type CommandContext } from "../cli/context.js";
import { renderFields, renderJson } from "../cli/output.js";
import type { SuppressionProjection } from "../domain/types.js";
import { auditRecord, requireScope } from "../services/compose.js";

/**
 * The stable suppression reason tokens.
 *
 * A free-form reason would make the suppression list unauditable, so the
 * vocabulary is closed.
 */
export const SUPPRESSION_REASONS: readonly string[] = [
  "hard_bounce",
  "complaint",
  "unsubscribe",
  "manual",
  "blocklist",
  "policy",
];

/** Validate the reason token. */
export function validateReason(raw: string | undefined): string {
  if (!raw) {
    throw CliError.usage(
      `A suppression reason is required; expected one of ${SUPPRESSION_REASONS.join(", ")}`,
    );
  }
  const normalized = raw.trim().toLowerCase();
  if (!SUPPRESSION_REASONS.includes(normalized)) {
    throw CliError.usage(
      `Unknown suppression reason '${raw}': expected one of ${SUPPRESSION_REASONS.join(", ")}`,
    );
  }
  return normalized;
}

/**
 * Validate the suppression scope.
 *
 * An address must contain a local part and a dotted domain; an approved
 * wildcard domain is `*.example.com`.
 */
export function validateScope(raw: string | undefined): string {
  if (!raw || raw.trim().length === 0) {
    throw CliError.usage("A suppression address or wildcard domain is required");
  }
  const scope = raw.trim().toLowerCase();
  if (scope.startsWith("*.")) {
    if (!isDottedDomain(scope.slice(2))) {
      throw CliError.usage(`Invalid wildcard domain '${raw}'`);
    }
    return scope;
  }
  const at = scope.lastIndexOf("@");
  if (at <= 0 || at === scope.length - 1) {
    throw CliError.usage(`Invalid suppression address '${raw}'`);
  }
  const local = scope.slice(0, at);
  const domain = scope.slice(at + 1);
  if (!/^[^\s@]+$/.test(local) || !isDottedDomain(domain)) {
    throw CliError.usage(`Invalid suppression address '${raw}'`);
  }
  return scope;
}

function isDottedDomain(domain: string): boolean {
  return (
    domain.length > 0 &&
    domain.length <= 253 &&
    domain.includes(".") &&
    /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)
  );
}

/** Options accepted by `suppress add`. */
export interface SuppressAddOptions {
  address: string | undefined;
  reason: string | undefined;
  expiresAt: string | undefined;
}

/** `railgun suppress add <address> --reason <code>` */
export async function suppressAdd(
  context: CommandContext,
  options: SuppressAddOptions,
): Promise<number> {
  const scope = validateScope(options.address);
  const reason = validateReason(options.reason);
  const expiresAt = parseExpiry(options.expiresAt);

  if (context.isRemote) {
    const result = await context.remote().addSuppression({ scope, reason, expiresAt });
    context.channel.stdout(
      context.options.json
        ? renderJson(result)
        : renderSuppression(result.suppression, result.created),
    );
    return 0;
  }

  const services = context.services();
  requireScope(services.principal, "admin");

  let result: { projection: SuppressionProjection; created: boolean };
  try {
    result = services.store.addSuppression({ scope, reason, expiresAt });
  } catch (cause) {
    throw toCliError(cause);
  }
  services.store.appendAudit(
    auditRecord(services.principal, "suppression.add", result.projection.id, reason),
  );
  context.channel.stdout(
    context.options.json
      ? renderJson(result)
      : renderSuppression(result.projection, result.created),
  );
  return 0;
}

/**
 * Parse the optional expiry.
 *
 * An explicit expiry is required to be a valid timestamp; an absent expiry
 * means a permanent suppression, which is never silently extended.
 */
function parseExpiry(raw: string | undefined): string | null {
  if (raw === undefined) {
    return null;
  }
  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed)) {
    throw CliError.usage(`Invalid expiry '${raw}': expected an ISO 8601 timestamp`);
  }
  return new Date(parsed).toISOString();
}

function renderSuppression(suppression: SuppressionProjection, created: boolean): string {
  return renderFields([
    ["id", suppression.id],
    ["scope", suppression.scope],
    ["reason", suppression.reason],
    ["created", created ? "yes" : "already-present"],
    ["expires", suppression.expiresAt ?? "never"],
    ["permanent", suppression.permanent ? "yes" : "no"],
  ]);
}
