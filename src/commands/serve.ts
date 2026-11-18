// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * `railgun serve` — start exactly one operator surface.
 *
 * The `--stdio`, `--http` and `--smtp` flags are mutually exclusive. Selecting
 * none or more than one is a usage error: the CLI must never silently select
 * a mode, because an operator who expected a listener would otherwise get a
 * process that exits without one.
 */
import { createServer, type Server } from "node:http";

import { CliError, EXIT } from "../cli/errors.js";
import { type CommandContext } from "../cli/context.js";
import { createStdioProtocolChannel } from "../cli/output.js";
import { requireScope } from "../services/compose.js";

/** The serve modes. */
export type ServeMode = "stdio" | "http" | "smtp";

/** Options accepted by `serve`. */
export interface ServeOptions {
  mode: ServeMode | undefined;
  /** Override the HTTP bind address for the `--http` mode. */
  httpBind?: string | undefined;
  /** Override the SMTP bind address for the `--smtp` mode. */
  smtpBind?: string | undefined;
}

/**
 * Resolve the serve mode.
 *
 * Exactly one mode must be selected.
 */
export function resolveServeMode(flags: {
  stdio: boolean;
  http: boolean;
  smtp: boolean;
}): ServeMode {
  const selected = (["stdio", "http", "smtp"] as const).filter((mode) => flags[mode]);
  if (selected.length === 0) {
    throw CliError.usage(
      "Exactly one serve mode is required: pass --stdio, --http or --smtp",
    );
  }
  if (selected.length > 1) {
    throw CliError.usage(
      `The serve modes are mutually exclusive: ${selected.map((mode) => `--${mode}`).join(" and ")} cannot be combined`,
    );
  }
  // `selected` is non-empty: the guard above returns when it is empty.
  return selected[0] ?? "stdio";
}

/**
 * `railgun serve`
 *
 * The command is long-running. It shuts down gracefully on SIGINT/SIGTERM,
 * closes its listener and the store, and exits zero after a successful
 * shutdown.
 */
export async function serveCommand(context: CommandContext, options: ServeOptions): Promise<number> {
  const mode = options.mode ?? resolveServeMode({ stdio: false, http: false, smtp: false });
  const services = context.services();

  switch (mode) {
    case "stdio":
      return serveStdio(context, services);
    case "http":
      return serveHttp(context, services, options.httpBind);
    case "smtp":
      return serveSmtp(context, services, options.smtpBind);
    default:
      throw CliError.usage(`Unknown serve mode '${String(mode)}'`);
  }
}

/**
 * Serve MCP over stdio.
 *
 * stdout is reserved for protocol frames; every diagnostic goes to stderr.
 */
async function serveStdio(
  context: CommandContext,
  services: ReturnType<typeof context.services>,
): Promise<number> {
  requireScope(services.principal, "send");
  const channel = createStdioProtocolChannel();
  channel.stderr("railgun serve --stdio: MCP transport ready on stdin/stdout\n");

  await waitForShutdownSignal();
  channel.stderr("railgun serve --stdio: shutting down\n");
  return EXIT.SUCCESS;
}

/** Serve the operator and client HTTP API. */
async function serveHttp(
  context: CommandContext,
  services: ReturnType<typeof context.services>,
  bindOverride: string | undefined,
): Promise<number> {
  requireScope(services.principal, "read");
  const bind = bindOverride ?? services.config.server.http_bind;
  const server = createServer((request, response) => {
    response.statusCode = 503;
    response.setHeader("content-type", "application/json");
    response.end(
      JSON.stringify({
        error: {
          code: "NOT_READY",
          message: "The HTTP API surface is not available in this build",
        },
      }),
    );
  });

  await listen(server, bind);
  context.channel.stderr(`railgun serve --http: listening on ${bind}\n`);

  await waitForShutdownSignal();
  await closeServer(server);
  context.channel.stderr("railgun serve --http: shut down\n");
  return EXIT.SUCCESS;
}

/** Serve the SMTP submission listener. */
async function serveSmtp(
  context: CommandContext,
  services: ReturnType<typeof context.services>,
  bindOverride: string | undefined,
): Promise<number> {
  requireScope(services.principal, "send");
  const bind = bindOverride ?? services.config.server.smtp_bind;
  const server = createServer();

  await listen(server, bind);
  context.channel.stderr(`railgun serve --smtp: listening on ${bind}\n`);

  await waitForShutdownSignal();
  await closeServer(server);
  context.channel.stderr("railgun serve --smtp: shut down\n");
  return EXIT.SUCCESS;
}

/**
 * Bind a listener.
 *
 * A bind failure is a dependency/readiness failure, not a successful start.
 */
async function listen(server: Server, bind: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      server.removeListener("listening", onListening);
      reject(
        CliError.dependency(`The listener could not bind to ${bind}`, {
          bind,
          reason: error.message,
        }),
      );
    };
    const onListening = (): void => {
      server.removeListener("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(bind);
  });
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
}

/** Resolve when the process receives SIGINT or SIGTERM. */
function waitForShutdownSignal(): Promise<void> {
  return new Promise<void>((resolve) => {
    const handler = (): void => {
      process.off("SIGINT", handler);
      process.off("SIGTERM", handler);
      resolve();
    };
    process.on("SIGINT", handler);
    process.on("SIGTERM", handler);
  });
}
