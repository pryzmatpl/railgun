// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * Canonical RailGun status vocabulary.
 *
 * MCP tools MUST NOT invent statuses outside this list (IR §1.3). Legacy or
 * unknown status names encountered in durable state are mapped into this
 * vocabulary rather than surfaced verbatim.
 */
export const RAILGUN_STATUSES = [
  "received",
  "policy_evaluated",
  "rejected",
  "suppressed",
  "queued",
  "accepted",
  "delivered",
  "deferred",
  "failed",
  "bounced",
] as const;

export type RailGunStatus = (typeof RAILGUN_STATUSES)[number];

/**
 * Map an arbitrary status string onto the canonical vocabulary.
 *
 * Unknown values collapse to `failed` rather than leaking a legacy token to
 * clients; this keeps the MCP contract stable while still representing a
 * non-success outcome.
 */
export function normalizeStatus(value: string | null | undefined): RailGunStatus {
  if (!value) return "failed";
  const candidate = value.trim().toLowerCase();
  const aliases: Record<string, RailGunStatus> = {
    pending: "queued",
    new: "received",
    sent: "accepted",
    delivered: "delivered",
    failure: "failed",
    softbounce: "deferred",
    soft_bounce: "deferred",
    hardbounce: "bounced",
    hard_bounce: "bounced",
  };
  if (aliases[candidate]) return aliases[candidate];
  if ((RAILGUN_STATUSES as readonly string[]).includes(candidate)) {
    return candidate as RailGunStatus;
  }
  return "failed";
}

/**
 * `delivery_confirmed` is true only when the message has reached `delivered`.
 * Queue acceptance never implies delivery (IR §1.3, MCP-AC8).
 */
export function isDeliveryConfirmed(status: RailGunStatus): boolean {
  return status === "delivered";
}
