#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The `railgun` executable entry point.
 *
 * The process exit code is the stable CLI exit-code contract, so an
 * automation can branch on the failure class without parsing output.
 */
import { run } from "./cli.js";

const exitCode = await run(process.argv.slice(2));
process.exitCode = exitCode;
