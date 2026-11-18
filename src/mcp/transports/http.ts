// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * RailGun MCP streamable HTTP transport (IR §9.2).
 *
 * The server exposes a single MCP endpoint (default `/mcp`) implementing the
 * streamable HTTP contract: one endpoint that accepts POST requests carrying
 * MCP messages and returns either a JSON response or an SSE stream, with
 * `Mcp-Session-Id` support for session continuity.
 *
 * Authentication is per-request (headers), not session-scoped-only: every tool
 * call is authorized on its own credentials, and a session never widens the
 * principal's scopes.
 */

import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import {
  authenticateHeader,
  buildRequestContext,
  extractCredential,
  type McpRequestContext,
  type PrincipalResolver,
} from "../auth.js";
import { ERROR_HTTP_STATUS, RailGunError, toRailGunError } from "../errors.js";
import type { ContextResolver, RailGunMcpServer } from "../server.js";

export interface HttpTransportOptions {
  /**
   * Creates the MCP server for a session. Each MCP session owns its own
   * transport, and the SDK's `McpServer` binds to exactly one transport, so a
   * factory is used instead of a single shared server instance.
   */
  readonly createServer: () => RailGunMcpServer;
  readonly principalResolver: PrincipalResolver;
  /** Path the MCP endpoint is mounted at. Default `/mcp`. */
  readonly path?: string;
  /** Host/port to bind. Default `127.0.0.1:3333`. */
  readonly host?: string;
  readonly port?: number;
  /** Log sink for diagnostics. */
  readonly log?: (line: string) => void;
  /** Return JSON responses instead of SSE streams. Default false. */
  readonly enableJsonResponse?: boolean;
  /** Enable the unauthenticated liveness endpoint. Default true. */
  readonly enableHealth?: boolean;
}

export interface HttpTransportHandle {
  readonly url: string;
  readonly port: number;
  close(): Promise<void>;
}

function defaultLogger(line: string): void {
  process.stderr.write(`${line}\n`);
}

/**
 * Resolve the request context for one HTTP tool call.
 *
 * The credential is read from the request headers on every call, so a
 * session cannot carry authority beyond the presented credential.
 */
export function createHttpContextResolver(
  principalResolver: PrincipalResolver,
): ContextResolver {
  return async (extra) => {
    const request = extra.requestInfo?.headers;
    const credential = extractCredential({
      get: (name: string) => {
        const value = request?.[name.toLowerCase()];
        if (Array.isArray(value)) return value[0];
        return value ?? undefined;
      },
    });
    const principal = await authenticateHeader(credential, principalResolver);
    const requestId =
      extra.requestId === undefined || extra.requestId === null
        ? null
        : String(extra.requestId);
    return buildRequestContext(principal, "http", requestId);
  };
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

/**
 * Create the streamable HTTP MCP transport.
 *
 * The MCP endpoint accepts POST (and GET/DELETE for SSE and session
 * teardown). A `/healthz` endpoint may be served unauthenticated and returns
 * only liveness facts.
 */
export async function startHttpTransport(
  options: HttpTransportOptions,
): Promise<HttpTransportHandle> {
  const log = options.log ?? defaultLogger;
  const path = options.path ?? "/mcp";
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 3333;
  const enableHealth = options.enableHealth ?? true;

  // One transport instance per MCP session. A session id is minted by the
  // SDK during `initialize`; the instance is registered under that id so
  // follow-up requests on the session reach the same transport.
  const transports = new Map<string, StreamableHTTPServerTransport>();
  const servers = new Map<string, RailGunMcpServer>();

  /**
   * Create a transport together with the MCP server that owns it.
   *
   * The server is registered under the session id the SDK mints during
   * `initialize`, so follow-up requests on that session reach the same
   * server instance.
   */
  const createSession = (): { transport: StreamableHTTPServerTransport; server: RailGunMcpServer } => {
    const server = options.createServer();
    let transport: StreamableHTTPServerTransport;
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: options.enableJsonResponse ?? false,
      onsessioninitialized: (sessionId: string) => {
        transports.set(sessionId, transport);
        servers.set(sessionId, server);
      },
      onsessionclosed: (sessionId: string) => {
        transports.delete(sessionId);
        servers.delete(sessionId);
      },
    });
    return { transport, server };
  };

  /**
   * Authenticate a raw HTTP request. Used at the transport boundary so an
   * unauthenticated POST is answered with `401 UNAUTHENTICATED` rather than
   * reaching the tool layer.
   */
  const authenticateRequest = async (req: IncomingMessage) => {
    const credential = extractCredential({
      get: (name: string) => {
        const value = req.headers[name.toLowerCase()];
        if (Array.isArray(value)) return value[0];
        return value ?? undefined;
      },
    });
    return authenticateHeader(credential, options.principalResolver);
  };

  const handleMcpRequest = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      await authenticateRequest(req);
    } catch (error) {
      const railGunError = toRailGunError(error);
      const status = ERROR_HTTP_STATUS[railGunError.code] ?? 401;
      writeJson(res, status, { error: railGunError.toBody() });
      return;
    }

    const sessionId = req.headers["mcp-session-id"];
    const sessionKey = typeof sessionId === "string" ? sessionId : undefined;

    let transport = sessionKey ? transports.get(sessionKey) : undefined;

    if (!transport) {
      if (sessionKey) {
        // Unknown session id — the MCP spec expects a 404 for this case.
        writeJson(res, 404, {
          error: new RailGunError("NOT_FOUND", "Unknown session.").toBody(),
        });
        return;
      }
      const session = createSession();
      transport = session.transport;
      await session.server.server.connect(transport);
    }

    try {
      await transport.handleRequest(req, res);
    } catch (error) {
      const railGunError = toRailGunError(error);
      const status = ERROR_HTTP_STATUS[railGunError.code] ?? 500;
      if (!res.headersSent) writeJson(res, status, { error: railGunError.toBody() });
      else res.end();
    }
  };

  const httpServer: Server = createServer((req, res) => {
    const url = req.url ?? "/";

    if (enableHealth && (url === "/healthz" || url === "/health")) {
      if (req.method !== "GET" && req.method !== "HEAD") {
        writeJson(res, 405, { error: "Method not allowed." });
        return;
      }
      // Liveness only: no configuration, tenant data or secrets.
      writeJson(res, 200, { status: "ok" });
      return;
    }

    if (!url.startsWith(path)) {
      writeJson(res, 404, { error: "Not found." });
      return;
    }

    void handleMcpRequest(req, res);
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, host, () => {
      httpServer.removeListener("error", reject);
      resolve();
    });
  });

  const address = httpServer.address();
  const boundPort = typeof address === "object" && address ? address.port : port;
  const url = `http://${host}:${boundPort}${path}`;

  log(
    JSON.stringify({
      level: "info",
      event: "mcp_http_started",
      url,
    }),
  );

  return {
    url,
    port: boundPort,
    close: async () => {
      for (const transport of transports.values()) {
        await transport.close();
      }
      transports.clear();
      servers.clear();
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    },
  };
}

export type { McpRequestContext };
