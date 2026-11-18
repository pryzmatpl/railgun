// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * RailGun MCP stdio server entry point.
 *
 * Started by an MCP host as a child process:
 *
 * ```
 * railgun-mcp --stdio
 * ```
 *
 * The credential is read from the environment (`RAILGUN_MCP_API_KEY`,
 * `RAILGUN_MCP_JWT` or `RAILGUN_MCP_LOCAL_PRINCIPAL`); stdout carries MCP
 * protocol traffic only and every diagnostic goes to stderr.
 */

import { parseMcpArgs, startMcpServer } from "../server-main.js";

async function main(): Promise<void> {
  const options = parseMcpArgs(process.argv.slice(2));
  await startMcpServer(options);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "unknown error";
  process.stderr.write(
    `${JSON.stringify({ level: "error", event: "mcp_stdio_failed", message })}\n`,
  );
  process.exitCode = 1;
});
