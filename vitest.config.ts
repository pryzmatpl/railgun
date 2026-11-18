// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "railgun",
    testTimeout: 30_000,
    include: ["test/**/*.test.ts"],
    environment: "node",
  },
});
