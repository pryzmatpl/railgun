// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The public module surface of the RailGun package.
 *
 * The package exposes three coherent surfaces: the operator CLI, the domain
 * and persistence contracts, and the operator application services. An
 * embedder may use any one of them without pulling in the others.
 */

/* -------------------------------------------------------------------------- */
/* Operator CLI                                                                */
/* -------------------------------------------------------------------------- */

export { run, packageVersion, HELP_TEXT } from "./cli.js";
export { CliError, EXIT, exitCodeFor, toErrorEnvelope } from "./cli/errors.js";
export type { ErrorCode, ErrorEnvelope, ExitCode } from "./cli/errors.js";
export type { OutputChannel } from "./cli/output.js";

/* -------------------------------------------------------------------------- */
/* Operator projections                                                       */
/* -------------------------------------------------------------------------- */

export type {
  AdminProjection,
  BounceProjection,
  EnvelopeRecipientProjection,
  MessageProjection,
  Page,
  Principal,
  QueueStatsProjection,
  RailGunStatus,
  StatsProjection,
  SuppressionProjection,
} from "./domain/types.js";

/* -------------------------------------------------------------------------- */
/* Application services                                                       */
/* -------------------------------------------------------------------------- */

export { composeServices, requireScope } from "./services/compose.js";
export type { OperatorServices } from "./services/compose.js";
export {
  FileOperatorStore,
  MemoryOperatorStore,
  ServiceError,
} from "./services/operator.js";
export type { OperatorStore } from "./services/operator.js";

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

export {
  applyEnvOverlay,
  defaultConfig,
  mergeYaml,
  resolveSecret,
  validateConfig,
} from "./config/config.js";
export type { RailgunConfig } from "./config/config.js";
export { loadConfig } from "./config/load.js";

/* -------------------------------------------------------------------------- */
/* Outbound delivery engine                                                    */
/* -------------------------------------------------------------------------- */

export {
  DeliveryEngine,
  NodeDnsResolver,
  TtlDnsCache,
  SmtpClient,
  buildMessageId,
  classifyDsnResult,
  classifySmtpResponse,
  parseDeliveryStatus,
} from "./outbound/index.js";
export type {
  DeliveryEngineOptions,
  DeliveryEvent,
  DeliveryOutcome,
  DeliveryRequest,
  DeliveryResult,
  DnsResolver,
  MxRecord,
  SmtpResponse,
} from "./outbound/index.js";

/* -------------------------------------------------------------------------- */
/* Domain contracts                                                           */
/* -------------------------------------------------------------------------- */

export {
  RAILGUN_STATUSES,
  isDeliveryConfirmed,
  normalizeStatus,
} from "./domain/status.js";
export type { RailGunStatus as CanonicalStatus } from "./domain/status.js";
export {
  canonicalIdempotencyKey,
  normalizeEmailAddress,
} from "./domain/normalize.js";
export { MemoryStore } from "./domain/persistence/memory-store.js";
export { FileAuditStore } from "./domain/persistence/file-audit-store.js";
export { IdempotencyConflictError, PersistenceError } from "./domain/persistence/errors.js";
export type {
  AuditEventInput,
  AuditRecord,
  BounceRecord,
  DeliveryAttempt,
  EnvelopeRecipient,
  EnvelopeStatus,
  IdempotencyRecord,
  Message,
  OutboxItem,
  RetentionPolicy,
  Suppression,
} from "./domain/persistence/types.js";
export type {
  AuditStore,
  BounceStore,
  Clock,
  IdempotencyStore,
  IdGenerator,
  MessageStore,
  OutboxStore,
  RailGunStore,
  SuppressionStore,
} from "./domain/persistence/ports.js";
