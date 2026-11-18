// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * RailGun MCP stdio transport (IR §9.1).
 *
 * Framing: newline-delimited JSON-RPC 2.0 on stdin/stdout, UTF-8, one
 * message per line. **stdout carries protocol traffic only**; every log and
 * diagnostic goes to stderr, because stdout is the MCP framing channel and a
 * credential must never be echoed there.
 *
 * The credential is resolved once at startup from the environment or the
 * configured `SecretProvider`. There is no anonymous principal for tool
 * invocation.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import {
  authenticateHeader,
  buildRequestContext,
  type McpRequestContext,
  type Principal,
  type PrincipalResolver,
} from "../auth.js";
import { RailGunError } from "../errors.js";
import type { ContextResolver, RailGunMcpServer } from "../server.js";

export interface StdioTransportOptions {
  readonly server: RailGunMcpServer;
  readonly principalResolver: PrincipalResolver;
  /**
   * Credential presented by the local operator. Defaults to the
   * `RAILGUN_MCP_API_KEY` / `RAILGUN_MCP_JWT` environment variables.
   */
  readonly credential?: string;
  /** Logger for diagnostics; always writes to stderr. */
  readonly log?: (line: string) => void;
}

function defaultLogger(line: string): void {
  process.stderr.write(`${line}\n`);
}

/**
 * Resolve the startup principal for the stdio transport.
 *
 * Credentials come from the process environment / `SecretProvider` resolved at
 * startup; the value is never written to stdout.
 */
export async function resolveStdioPrincipal(
  options: StdioTransportOptions,
): Promise<Principal> {
  const explicit = options.credential;
  const envJwt = process.env.RAILGUN_MCP_JWT;
  const envKey = process.env.RAILGUN_MCP_API_KEY;
  const envLocal = process.env.RAILGUN_MCP_LOCAL_PRINCIPAL;

  const credential = explicit
    ? ({ kind: "apiKey" as const, value: explicit })
    : envJwt
      ? ({ kind: "jwt" as const, value: envJwt })
      : envKey
        ? ({ kind: "apiKey" as const, value: envKey })
        : envLocal
          ? ({ kind: "local" as const, value: envLocal })
          : null;

  if (!credential) {
    throw new RailGunError(
      "UNAUTHENTICATED",
      "No credential configured for the RailGun MCP stdio transport.",
    );
  }

  return authenticateHeader(credential, options.principalResolver);
}

/**
 * Build the context resolver used by the stdio transport.
 *
 * The principal is resolved once at startup; every subsequent tool call runs
 * under that principal's scopes and tenant.
 */
export function createStdioContextResolver(
  principal: Principal,
): ContextResolver {
  return () => buildRequestContext(principal, "stdio", null);
}

/**
 * Start the RailGun MCP server on stdio.
 *
 * The server reads requests until EOF, then closes cleanly.
 */
export async function startStdioTransport(
  options: StdioTransportOptions,
): Promise<{ close: () => Promise<void> }> {
  const log = options.log ?? defaultLogger;
  const principal = await resolveStdioPrincipal(options);

  const transport = new StdioServerTransport();
  await options.server.server.connect(transport);

  log(
    JSON.stringify({
      level: "info",
      event: "mcp_stdio_started",
      principal_id: principal.principalId,
      tenant_id: principal.tenantId,
    }),
  );

  return {
    close: async () => {
      await options.server.server.close();
    },
  };
}
