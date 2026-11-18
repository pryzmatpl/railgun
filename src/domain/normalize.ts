/* RailGun normalization helpers. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

export function normalizeEmailAddress(value: string): string {
  const trimmed = value.trim();
  const at = trimmed.lastIndexOf("@");
  if (at <= 0 || at === trimmed.length - 1) {
    throw new Error(`Invalid email address: ${value}`);
  }
  return `${trimmed.slice(0, at).toLowerCase()}@${trimmed.slice(at + 1).toLowerCase()}`;
}

export function canonicalIdempotencyKey(tenantId: string, action: string, requestId: string): string {
  if (!tenantId || !action || !requestId.trim()) {
    throw new Error("tenantId, action and requestId are required");
  }
  return `email:idempotency:${tenantId}:${action}:${requestId.trim()}`;
}
