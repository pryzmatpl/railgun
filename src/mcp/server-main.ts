// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * RailGun MCP server entry point.
 *
 * Runs the RailGun MCP server over the stdio or the streamable HTTP
 * transport:
 *
 * ```
 * railgun-mcp --stdio
 * railgun-mcp --http --host 127.0.0.1 --port 3333
 * ```
 *
 * The credential is read from the environment (`RAILGUN_MCP_API_KEY`,
 * `RAILGUN_MCP_JWT` or `RAILGUN_MCP_LOCAL_PRINCIPAL`). stdout carries MCP
 * protocol traffic only; every diagnostic goes to stderr.
 */

import { MemoryEmailApplication } from "../application/memory-email-application.js";
import type { Principal, PrincipalResolver } from "../mcp/auth.js";
import { createRailGunMcpServer } from "../mcp/server.js";
import {
  createHttpContextResolver,
  startHttpTransport,
} from "../mcp/transports/http.js";
import {
  createStdioContextResolver,
  resolveStdioPrincipal,
  startStdioTransport,
} from "../mcp/transports/stdio.js";

interface PrincipalDescriptor {
  readonly principalId: string;
  readonly tenantId: string;
  readonly roles?: readonly ("admin" | "operator" | "sender" | "auditor")[];
  readonly scopes?: readonly ("send" | "read" | "admin" | "feedback")[];
  readonly allowedSenders?: readonly string[];
  readonly bodyRead?: boolean;
  readonly senderOverride?: boolean;
}

/**
 * Resolve principals from the environment.
 *
 * `RAILGUN_MCP_PRINCIPALS` carries a JSON map from credential to principal
 * descriptor. It exists so a deployment can supply principals without a
 * database; the secret itself still has to be presented by the client.
 */
export function environmentResolver(): PrincipalResolver {
  const raw = process.env.RAILGUN_MCP_PRINCIPALS;
  let table: Record<string, PrincipalDescriptor> = {};
  if (raw) {
    try {
      table = JSON.parse(raw) as Record<string, PrincipalDescriptor>;
    } catch {
      throw new Error("RAILGUN_MCP_PRINCIPALS is not valid JSON.");
    }
  }

  const toPrincipal = (descriptor: PrincipalDescriptor): Principal => ({
    principalId: descriptor.principalId,
    tenantId: descriptor.tenantId,
    roles: descriptor.roles ?? ["sender"],
    scopes: descriptor.scopes ?? ["send", "read"],
    senderOverride: descriptor.senderOverride ?? false,
    bodyRead: descriptor.bodyRead ?? false,
    allowedSenders: descriptor.allowedSenders ?? [],
  });

  return {
    async resolveApiKey(apiKey: string): Promise<Principal | null> {
      const descriptor = table[apiKey];
      return descriptor ? toPrincipal(descriptor) : null;
    },
    async resolveJwt(token: string): Promise<Principal | null> {
      const descriptor = table[token];
      return descriptor ? toPrincipal(descriptor) : null;
    },
    async resolveLocal(label: string): Promise<Principal | null> {
      const descriptor = table[label];
      return descriptor ? toPrincipal(descriptor) : null;
    },
  };
}

export interface McpServerOptions {
  readonly mode: "stdio" | "http";
  readonly host?: string;
  readonly port?: number;
  readonly path?: string;
  readonly recipientSalt?: string;
  readonly log?: (line: string) => void;
}

/**
 * Start the RailGun MCP server.
 *
 * In stdio mode the principal is resolved once at startup; in HTTP mode the
 * credential is resolved per request so a session never widens a
 * principal's scopes.
 */
export async function startMcpServer(options: McpServerOptions): Promise<{
  close: () => Promise<void>;
}> {
  const principalResolver = environmentResolver();
  const application = new MemoryEmailApplication();
  const recipientSalt = options.recipientSalt ?? process.env.RAILGUN_MCP_RECIPIENT_SALT ?? "railgun";
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));

  if (options.mode === "stdio") {
    const principal = await resolveStdioPrincipal({
      server: createRailGunMcpServer({
        application,
        principalResolver,
        recipientSalt,
        resolveContext: () => {
          throw new Error("unreachable");
        },
      }),
      principalResolver,
    });

    const server = createRailGunMcpServer({
      application,
      principalResolver,
      recipientSalt,
      resolveContext: createStdioContextResolver(principal),
    });

    return startStdioTransport({ server, principalResolver, log });
  }

  const handle = await startHttpTransport({
    createServer: () =>
      createRailGunMcpServer({
        application,
        principalResolver,
        recipientSalt,
        resolveContext: createHttpContextResolver(principalResolver),
      }),
    principalResolver,
    host: options.host,
    port: options.port,
    path: options.path,
    log,
  });

  return { close: handle.close };
}

/** Parse the command-line arguments of the MCP server entry point. */
export function parseMcpArgs(argv: readonly string[]): McpServerOptions {
  let mode: "stdio" | "http" | undefined;
  let host: string | undefined;
  let port: number | undefined;
  let path: string | undefined;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--stdio") mode = "stdio";
    else if (arg === "--http") mode = "http";
    else if (arg === "--host") host = argv[++index];
    else if (arg === "--port") port = Number.parseInt(argv[++index] ?? "", 10);
    else if (arg === "--path") path = argv[++index];
  }

  if (!mode) {
    throw new Error("Exactly one of --stdio or --http is required.");
  }

  return {
    mode,
    host,
    port: Number.isFinite(port) ? port : undefined,
    path,
  };
}

/**
 * Run the MCP server when this module is the process entry point.
 *
 * `railgun-mcp --stdio` and `railgun-mcp --http` both land here.
 */
async function main(): Promise<void> {
  const options = parseMcpArgs(process.argv.slice(2));
  await startMcpServer(options);
}

// Only run when invoked directly, so the module stays importable.
const invokedDirectly =
  process.argv[1] !== undefined &&
  (process.argv[1].endsWith("server-main.js") || process.argv[1].endsWith("server-main.ts"));

if (invokedDirectly) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "unknown error";
    process.stderr.write(
      `${JSON.stringify({ level: "error", event: "mcp_server_failed", message })}\n`,
    );
    process.exitCode = 1;
  });
}
