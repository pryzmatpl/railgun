// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * RailGun MCP server surface.
 *
 * RailGun ships its own MCP protocol server and tool schemas; it does not
 * depend on the Jaisiu in-process MCP subsystem. The four tools
 * (`email_send`, `email_status`, `email_bounces`, `email_stats`) are exposed
 * over the stdio and streamable HTTP transports with identical names and
 * semantics.
 */

export {
  createRailGunMcpServer,
  type ContextResolver,
  type RailGunMcpServer,
  type RailGunMcpServerOptions,
  type ToolCallExtra,
} from "./server.js";

export {
  buildToolRegistrations,
  buildBouncesEnvelope,
  buildSendEnvelope,
  buildStatusEnvelope,
  RAILGUN_MCP_TOOL_NAMES,
  type EmailSendEnvelope,
  type McpToolOptions,
  type RailGunMcpToolName,
  type ToolEnvelope,
  type ToolRegistration,
} from "./tools.js";

export {
  authenticate,
  authenticateHeader,
  buildRequestContext,
  constantTimeEquals,
  extractCredential,
  hashIdempotencyKey,
  hashRecipient,
  hasScope,
  parseBearer,
  requireAllowedSender,
  requireScope,
  RAILGUN_ROLES,
  RAILGUN_SCOPES,
  type Credential,
  type McpRequestContext,
  type Principal,
  type PrincipalResolver,
  type RailGunRole,
  type RailGunScope,
} from "./auth.js";

export {
  ERROR_HTTP_STATUS,
  RailGunError,
  RAILGUN_ERROR_CODES,
  toRailGunError,
  type McpToolError,
  type RailGunErrorBody,
  type RailGunErrorCode,
} from "./errors.js";

export {
  DEFAULT_SEND_LIMITS,
  emailBouncesInputSchema,
  emailSendInputSchema,
  emailStatsInputSchema,
  emailStatusInputSchema,
  normalizeSendInput,
  sendInputFingerprint,
  type NormalizedSendInput,
  type SendToolLimits,
} from "./schemas.js";

export {
  createHttpContextResolver,
  startHttpTransport,
  type HttpTransportHandle,
  type HttpTransportOptions,
} from "./transports/http.js";

export {
  createStdioContextResolver,
  resolveStdioPrincipal,
  startStdioTransport,
  type StdioTransportOptions,
} from "./transports/stdio.js";
