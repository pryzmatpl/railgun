// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * The public surface of the RailGun HTTP API.
 *
 * The service is standalone: it depends only on the ports declared in
 * `types.ts`, never on the Jaisiu monorepo.
 */

export { RailGunHttpServer, buildRouter, definedHeaders, normalizeHeaders } from "./server.js";
export { HttpService } from "./service.js";
export type { HttpServiceDeps, MetricsSink } from "./service.js";
export { Router, matchSegments, splitPath } from "./router.js";
export type { RequestContext, RouteDefinition, RouteHandler } from "./router.js";
export {
  ERROR_CODES,
  ERROR_CODE_ALIASES,
  HttpError,
  actionNotPermitted,
  ambiguousField,
  insufficientScope,
  internalError,
  invalidRequest,
  notFound,
  notReady,
  rateLimited,
  sanitizePayload,
  unauthenticated,
} from "./errors.js";
export type { ErrorCode, ErrorEnvelope } from "./errors.js";
export {
  authenticate,
  classifyBearer,
  extractBearer,
  hashApiKey,
  keyPrefix,
  resolveApiKey,
  safeEqualHex,
  verifyJwt,
  verifyWebhookHmac,
} from "./auth.js";
export type { ApiKeyRecord, AuthResult, CredentialStore, JwtVerifier } from "./auth.js";
export {
  assertNoTenantOverride,
  assertSenderAllowed,
  canReadBody,
  domainOf,
  requireScope,
} from "./authorize.js";
export {
  base64UrlDecode,
  base64UrlEncode,
  canonicalDigest,
  canonicalJson,
  decodeCursor,
  encodeCursor,
  hmacHex,
  recipientHash,
  safeEqual,
  sha256Hex,
} from "./crypto.js";
export { etagMatches, etagOf, writeError, writeJson, writeText } from "./responses.js";
export { buildOpenApiDocument } from "./openapi.js";
export { parseSendRequest, normalizeAddress, splitAddressList, isValidAddress } from "./schemas/send.js";
export type { SendRequest } from "./schemas/send.js";
export { deliveryRate, projectBounce, projectMessage } from "./schemas/projection.js";
export type { BounceProjection, MessageProjection, StatsProjection } from "./schemas/projection.js";
export {
  FixedClock,
  MemoryAuditLog,
  MemoryBounceStore,
  MemoryIdempotencyStore,
  MemoryMessageStore,
  MemoryOutboxQueue,
  MemorySuppressionStore,
  SequentialIds,
} from "./memory.js";
export { hasScope, normalizeScope, normalizeScopes, systemClock } from "./types.js";
export type {
  AuditLog,
  BounceRecord,
  BounceStore,
  Clock,
  DomainRegistry,
  HttpConfig,
  IdempotencyStore,
  IdGenerator,
  MessageFilter,
  MessageRecord,
  MessageStatus,
  MessageStore,
  OutboxQueue,
  Page,
  PolicyDecision,
  PolicyEngine,
  Principal,
  ReadinessProbe,
  Scope,
  StatsBucket,
  SuppressionRecord,
  SuppressionStore,
} from "./types.js";
