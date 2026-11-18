/* RailGun SMTP submission server — public surface.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Package-local SMTP submission server (RFC 5321 subset).
 *
 * The server accepts inbound submissions from agents and mail clients,
 * evaluates per-recipient policy hooks, and hands accepted messages to the
 * durable queue port. It never performs outbound delivery itself.
 *
 * Contract: `docs/design/84df18ec-8e87-47cb-9d64-b804c4205cb3-railgun-smtp-submission-server-ir.md`
 */

export {
  DataAccumulator,
  SmtpParseError,
  isNonAsciiAddress,
  parseCommand,
  parseHeaders,
  parseParams,
  parsePath,
  splitCommand,
  type DataChunkResult,
  type ParsedCommand,
  type ParsedPath,
  type SmtpHeaderParseResult,
} from "./parser.js";

export {
  AUTH_LOGIN_PASSWORD_CHALLENGE,
  AUTH_LOGIN_USERNAME_CHALLENGE,
  SmtpSession,
  type SmtpSessionInit,
  type SmtpSessionTransport,
} from "./session.js";

export { createSmtpServer, startSmtpServer, type SmtpServerHandle } from "./server.js";

export {
  SMTP_REASON_CODES,
  type PolicyDecisionContext,
  type PolicyHookOutcome,
  type PolicyHookResult,
  type RecipientOutcome,
  type SmtpAuthenticator,
  type SmtpHeader,
  type SmtpPolicyHooks,
  type SmtpPrincipal,
  type SmtpQueuePort,
  type SmtpReasonCode,
  type SmtpServerEvent,
  type SmtpServerOptions,
  type SmtpSessionState,
  type SmtpSubmission,
  type SmtpTlsOptions,
} from "./types.js";
