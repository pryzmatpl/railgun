/* RailGun shared persistence contracts. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { Message, OutboxItem } from "./ports.js";

export interface AcceptInput {
  readonly message: Message;
  readonly envelopes: readonly import("./types.js").EnvelopeRecipient[];
  readonly outbox: readonly Omit<OutboxItem, "acceptedSequence">[];
  readonly idempotency: import("./types.js").IdempotencyRecord;
  readonly response: unknown;
  readonly idempotencyExpiresAt: string;
}
