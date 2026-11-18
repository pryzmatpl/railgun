/* RailGun retention helpers. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { RailGunStore } from "./ports.js";
import type { RetentionPolicy } from "./types.js";

export async function applyRetention(store: RailGunStore, policy: RetentionPolicy, now: string): Promise<Record<string, number>> {
  return store.applyRetention(policy, now);
}
