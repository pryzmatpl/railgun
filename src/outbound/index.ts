// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The outbound delivery engine — the package's **primary** outbound path.
 *
 * Contract: `docs/design/railgun-direct-mx-delivery-engine-ir.md`.
 *
 * Direct-to-MX is the default and the only mode required for normal
 * operation; an operator relay is an optional fallback. The engine is
 * provider-independent: it uses Node built-ins only, so a standalone install
 * keeps working and no SMTP client library is needed.
 */

/* -------------------------------------------------------------------------- */
/* The engine                                                                  */
/* -------------------------------------------------------------------------- */

export {
  DEFAULT_LOOP_LIMIT,
  DeliveryEngine,
  LOOP_HEADER,
  inspectLoopMarker,
  redactRecipient,
  routingDomainOf,
} from "./engine.js";
export type { DeliveryEngineOptions, DeliveryRunResult } from "./engine.js";

/* -------------------------------------------------------------------------- */
/* DNS                                                                         */
/* -------------------------------------------------------------------------- */

export {
  DEFAULT_MAX_DNS_TTL_SECONDS,
  NodeDnsResolver,
  TtlDnsCache,
  checkAddressPolicy,
  isNullMx,
  isTemporaryDnsError,
  orderAddresses,
  orderMxRecords,
  reverseDnsMatches,
} from "./dns.js";
export type { AddressCandidate, AddressPolicyVerdict } from "./dns.js";

/* -------------------------------------------------------------------------- */
/* The SMTP client                                                             */
/* -------------------------------------------------------------------------- */

export {
  MAX_COMMAND_LINE_BYTES,
  MAX_REPLY_BYTES,
  MIN_TLS_VERSION,
  SmtpClient,
  SmtpProtocolError,
  SmtpTimeoutError,
  SmtpTlsError,
  certificateFingerprint,
  dotStuff,
  isCertificateError,
  parseCapabilities,
  sanitizeResponse,
  takeReply,
} from "./smtp-client.js";
export type { SmtpClientOptions } from "./smtp-client.js";

/* -------------------------------------------------------------------------- */
/* Classification, backoff, message ids and DSNs                               */
/* -------------------------------------------------------------------------- */

export {
  classifyFinalResponse,
  classifySmtpResponse,
  extractEnhancedCode,
  permanentCodeFor,
} from "./classify.js";
export type { SmtpClassification } from "./classify.js";

export {
  BASE_BACKOFF_MS,
  DEFAULT_MAX_ATTEMPTS,
  MAX_BACKOFF_MS,
  backoffCeiling,
  backoffDelay,
  deterministicJitter,
  effectiveMaxAttempts,
  nextAttemptAt,
} from "./backoff.js";
export type { BackoffOptions } from "./backoff.js";

export {
  MESSAGE_ID_ACTION,
  buildMessageId,
  messageIdHeader,
  messageIdLocalPart,
  normalizeDomain,
} from "./message-id.js";

export {
  classifyDsnResult,
  extractDeliveryStatusPart,
  isDsnDeliveryConfirmed,
  parseDeliveryStatus,
} from "./dsn.js";
export type {
  DsnAction,
  DsnOutcome,
  DsnRecipientResult,
  DsnReport,
  DsnStatusClass,
} from "./dsn.js";

/* -------------------------------------------------------------------------- */
/* The seams and the value contracts                                           */
/* -------------------------------------------------------------------------- */

export { DELIVERY_ERROR_CODES, DELIVERY_EVENT_NAMES } from "./types.js";
export type {
  AuditSink,
  BounceSink,
  DeliveryAttemptStore,
  DeliveryErrorCode,
  DeliveryEvent,
  DeliveryEventName,
  DeliveryOutcome,
  DeliveryRequest,
  DeliveryResult,
  DeliveryRuntime,
  DnsCache,
  DnsResolver,
  EventSink,
  MxRecord,
  OutboxLease,
  SmtpCapabilities,
  SmtpResponse,
  SmtpTransport,
  TlsFacts,
  TlsMode,
} from "./types.js";
