/* RailGun anti-spam / compliance test configuration.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scoped to the policy engine's own suite so it can run independently of the
 * sibling surface suites (SMTP, HTTP, MCP) that live in the same package.
 */

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/policy/**/*.test.ts", "test/dkim.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    testTimeout: 30_000,
  },
});
