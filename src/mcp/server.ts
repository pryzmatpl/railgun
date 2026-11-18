// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * Transport-agnostic RailGun MCP server core (IR §1).
 *
 * The core owns tool registration, authorization, validation and envelope
 * shaping. Transports (stdio, streamable HTTP) are responsible only for
 * framing and for resolving the authenticated principal per request.
 *
 * One semantic model, two projections: the same handlers back both
 * transports, so a send over MCP and the same logical send over HTTP resolve
 * to the same stored message.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { ServerRequest, ServerNotification } from "@modelcontextprotocol/sdk/types.js";

import type { EmailApplication } from "../application/ports.js";
import {
  buildRequestContext,
  type McpRequestContext,
  type Principal,
  type PrincipalResolver,
} from "./auth.js";
import { RailGunError, toRailGunError } from "./errors.js";
import {
  buildToolRegistrations,
  type McpToolOptions,
  type ToolEnvelope,
} from "./tools.js";

/**
 * Build the sanitized MCP tool-error envelope (IR §8).
 *
 * The payload carries the stable machine code, one human-safe sentence and
 * optional safe fields only — never a stack trace, file path, raw SMTP text
 * or credential.
 */
function errorEnvelope(error: RailGunError): ToolEnvelope {
  const body = error.toBody();
  return {
    content: [{ type: "text", text: JSON.stringify({ error: body }) }],
    structuredContent: { error: body } as Record<string, unknown>,
    isError: true,
  };
}

/**
 * The `extra` object the MCP SDK hands to tool callbacks. It carries the
 * original HTTP request (for streamable HTTP) and the session id.
 */
export type ToolCallExtra = RequestHandlerExtra<ServerRequest, ServerNotification>;

/**
 * Resolves the authenticated request context for one tool call.
 *
 * The stdio transport resolves a startup principal; the streamable HTTP
 * transport resolves the credential from the request headers on every call,
 * so a session never widens a principal's scopes.
 */
export type ContextResolver = (
  extra: ToolCallExtra,
) => Promise<McpRequestContext> | McpRequestContext;

export interface RailGunMcpServerOptions extends McpToolOptions {
  readonly application: EmailApplication;
  /**
   * Resolves a presented credential to a principal. Transports use it to
   * authenticate; the core itself never reads credentials.
   */
  readonly principalResolver: PrincipalResolver;
  /** Resolves the request context for each tool call. */
  readonly resolveContext: ContextResolver;
  readonly serverName?: string;
  readonly serverVersion?: string;
}

/**
 * A registered RailGun MCP server plus helpers used by the transports.
 */
export interface RailGunMcpServer {
  readonly server: McpServer;
  /** Build the request context for an authenticated principal. */
  contextFor(
    principal: Principal,
    transport: "stdio" | "http",
    requestId?: string | null,
  ): McpRequestContext;
  /** Execute a tool directly with an authenticated context. */
  callTool(
    name: string,
    args: unknown,
    context: McpRequestContext,
  ): Promise<ToolEnvelope>;
  /** Names of the exposed tools. */
  readonly toolNames: readonly string[];
}

/**
 * Create the RailGun MCP server.
 *
 * Tool handlers are invoked through the SDK's `tools/call` dispatch; the
 * request context is resolved per call, so authorization is never cached on
 * the server instance.
 */
export function createRailGunMcpServer(
  options: RailGunMcpServerOptions,
): RailGunMcpServer {
  const server = new McpServer(
    {
      name: options.serverName ?? "railgun",
      version: options.serverVersion ?? "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  const registrations = buildToolRegistrations(options);
  const byName = new Map(registrations.map((registration) => [registration.name, registration]));

  for (const registration of registrations) {
    server.registerTool(
      registration.name,
      registration.config as never,
      (async (args: unknown, extra: ToolCallExtra) => {
        let context: McpRequestContext;
        try {
          context = await options.resolveContext(extra);
        } catch (error) {
          // Authentication and authorization failures are reported through the
          // sanitized MCP error envelope (IR §8), never as a raw exception.
          return errorEnvelope(toRailGunError(error));
        }
        try {
          return await callTool(registration.name, args, context);
        } catch (error) {
          return errorEnvelope(toRailGunError(error, context.requestId));
        }
      }) as never,
    );
  }

  const contextFor = (
    principal: Principal,
    transport: "stdio" | "http",
    requestId: string | null = null,
  ): McpRequestContext => buildRequestContext(principal, transport, requestId);

  const callTool = async (
    name: string,
    args: unknown,
    context: McpRequestContext,
  ): Promise<ToolEnvelope> => {
    const registration = byName.get(name);
    if (!registration) {
      throw new RailGunError("ACTION_NOT_PERMITTED", "Unknown tool.");
    }
    try {
      return await registration.handler(args, context);
    } catch (error) {
      throw toRailGunError(error, context.requestId);
    }
  };

  return {
    server,
    contextFor,
    callTool,
    toolNames: registrations.map((registration) => registration.name),
  };
}
