// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * The RailGun HTTP server: lifecycle, request pipeline and the route table.
 *
 * The pipeline order is normative:
 *
 * 1. exact-path route resolution (`404`/`405`)
 * 2. request id assignment
 * 3. rate limit (before expensive body parsing)
 * 4. body buffering with a hard size cap
 * 5. authentication (unauthenticated requests never consume an idempotency key)
 * 6. scope authorization
 * 7. idempotency lookup / reservation
 * 8. route handler
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { authenticate, verifyWebhookHmac } from "./auth.js";
import { canonicalDigest } from "./crypto.js";
import { HttpError, internalError, notFound, rateLimited } from "./errors.js";
import { writeError, writeJson } from "./responses.js";
import { Router, type RequestContext } from "./router.js";
import { HttpService } from "./service.js";
import { handleEvents } from "./routes/events.js";
import { buildOpenApiDocument } from "./openapi.js";
import { handleHealth, handleMetrics, handleReady } from "./routes/health.js";
import { handleListBounces } from "./routes/bounces.js";
import { handleGetMessage, handleListMessages } from "./routes/messages.js";
import { handleRetry, handleSuppress } from "./routes/actions.js";
import { handleSend } from "./routes/email.js";
import { handleStats } from "./routes/stats.js";
import type { Principal, Scope } from "./types.js";

/** A token bucket for the per-API-key minute budget (§8.4). */
class TokenBucket {
  private tokens: number;
  private updatedAt: number;

  constructor(
    private readonly capacity: number,
    now: number,
  ) {
    this.tokens = capacity;
    this.updatedAt = now;
  }

  /** Try to consume one token. Returns the remaining budget and reset delay. */
  consume(now: number): { allowed: boolean; remaining: number; resetAfterSeconds: number } {
    const elapsedSeconds = (now - this.updatedAt) / 1000;
    if (elapsedSeconds > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + elapsedSeconds);
      this.updatedAt = now;
    }
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return {
        allowed: true,
        remaining: Math.floor(this.tokens),
        resetAfterSeconds: Math.ceil((1 - this.tokens) / 1),
      };
    }
    return { allowed: false, remaining: 0, resetAfterSeconds: 60 };
  }
}

export interface HttpServerOptions {
  service: HttpService;
  /** Injectable clock for the rate limiter (milliseconds). */
  now?: () => number;
}

/** The RailGun HTTP server. */
export class RailGunHttpServer {
  readonly service: HttpService;
  readonly router: Router;
  private server: Server | null = null;
  private readonly buckets = new Map<string, TokenBucket>();
  private readonly now: () => number;

  constructor(options: HttpServerOptions) {
    this.service = options.service;
    this.now = options.now ?? (() => Date.now());
    this.router = buildRouter(this.service);
  }

  /** Start listening. Resolves with the bound address. */
  async listen(port = this.service.config.port, host = this.service.config.host): Promise<AddressInfo> {
    const server = createServer((req, res) => {
      void this.handle(req, res);
    });
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
    const address = server.address() as AddressInfo;
    return address;
  }

  /** Stop the server and close idle connections. */
  async close(): Promise<void> {
    const server = this.server;
    this.server = null;
    if (!server) {
      return;
    }
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections?.();
    });
  }

  /** The full request pipeline. */
  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const started = this.now();
    const requestId = this.service.deps.ids.requestId();
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      const path = url.pathname;
      const method = (req.method ?? "GET").toUpperCase();

      const matched = this.router.match(method, path);
      if (!matched) {
        throw notFound("Route not found.");
      }
      if ("methodMismatch" in matched) {
        throw new HttpError(405, "METHOD_NOT_ALLOWED", "Method not allowed for this route.");
      }

      const route = matched.route;
      const headers = normalizeHeaders(req);

      // Rate limit before parsing an expensive body (§8.4).
      const principalHint = this.principalHint(headers);
      const limitHeaders = this.checkRateLimit(principalHint);
      for (const [key, value] of Object.entries(limitHeaders)) {
        res.setHeader(key, value);
      }

      const body = await this.readBody(req);

      const ctx: RequestContext = {
        req,
        res,
        path,
        method,
        url,
        query: url.searchParams,
        params: matched.params,
        request_id: requestId,
        body,
        headers,
      };

      if (!route.public && !(route.publicWhen?.(this.service.config) ?? false)) {
        ctx.principal = await this.resolvePrincipal(ctx, route);
      }

      await this.withIdempotency(ctx, route, async () => {
        await route.handler(ctx);
      });
      this.service.deps.metrics?.observeRequest(route.name, method, res.statusCode, this.now() - started);
    } catch (error) {
      const httpError =
        error instanceof HttpError ? error : internalError();
      if (!(error instanceof HttpError)) {
        // Never leak the raw exception to the wire; log it server-side only.
        console.error("[railgun] unhandled request error", {
          request_id: requestId,
          error: error instanceof Error ? error.message : "unknown",
        });
      }
      writeError(res, httpError, requestId);
      this.service.deps.metrics?.observeRequest("unknown", "UNKNOWN", httpError.status, this.now() - started);
    }
  }

  /** Resolve the principal for a protected route. */
  private async resolvePrincipal(
    ctx: RequestContext,
    route: { name: string; scope?: string },
  ): Promise<Principal> {
    if (route.name === "events") {
      // The webhook path may authenticate by HMAC instead of a credential.
      if (this.service.config.webhook_secret) {
        verifyWebhookHmac(ctx.headers, ctx.body, this.service.config.webhook_secret, this.service.now());
        return {
          id: "webhook",
          tenant_id: "default",
          kind: "local_operator",
          scopes: ["feedback"],
          roles: [],
          allowed_senders: [],
          allowed_domains: [],
          active: true,
        };
      }
    }
    const result = await authenticate(
      {
        headers: ctx.headers,
        body: ctx.body,
        method: ctx.method,
        path: ctx.path,
      },
      this.service.deps.credentials,
      this.service.deps.jwt,
      this.service.now(),
    );
    if (route.scope) {
      const required = route.scope as Scope;
      if (!result.principal.scopes.includes(required)) {
        throw new HttpError(403, "INSUFFICIENT_SCOPE", "Insufficient scope for this action.", {
          required_scope: required,
        });
      }
    }
    return result.principal;
  }

  /**
   * Apply the explicit `Idempotency-Key` replay guard (§5.1).
   *
   * Authentication and authorization run before this point, so an
   * unauthenticated request never consumes or creates an idempotency record.
   */
  private async withIdempotency(
    ctx: RequestContext,
    route: { method: string; template: string; idempotency?: "header" | "natural" },
    run: () => Promise<void>,
  ): Promise<void> {
    if (route.method === "GET") {
      await run();
      return;
    }
    if (route.idempotency === "natural") {
      // The route owns its own natural-key idempotency (§5.5).
      await run();
      return;
    }
    const key = ctx.headers["idempotency-key"];
    if (typeof key !== "string" || key.trim().length === 0) {
      await run();
      return;
    }
    const principalId = ctx.principal?.id ?? "anonymous";
    const scopeKey = `${principalId}|${route.method}|${route.template}|${key}`;
    const digest = canonicalDigest(normalizeBodyForDigest(ctx.body));

    const existing = await this.service.deps.idempotency.get(scopeKey);
    if (existing) {
      if (existing.body_digest !== digest) {
        throw new HttpError(
          409,
          "IDEMPOTENCY_KEY_REUSED",
          "Idempotency key was already used with a different request body.",
        );
      }
      writeJson(ctx.res, existing.status, existing.body, {
        ...definedHeaders(existing.headers),
        "idempotency-replayed": "true",
        "x-request-id": ctx.request_id,
      });
      await this.service.audit({
        event: "idempotency.replayed",
        actor: ctx.principal?.id ?? "anonymous",
        tenant_id: ctx.principal?.tenant_id ?? null,
        request_id: ctx.request_id,
        outcome: "ok",
        detail: { route: route.template },
      });
      return;
    }

    const now = this.service.now();
    const ttlMs = this.service.config.idempotency_ttl_hours * 60 * 60 * 1000;
    const reserved = await this.service.deps.idempotency.reserve({
      scope_key: scopeKey,
      body_digest: digest,
      status: 0,
      headers: {},
      body: null,
      created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + ttlMs).toISOString(),
    });
    if (!reserved) {
      // Another request reserved the key concurrently — replay its result.
      const concurrent = await this.service.deps.idempotency.get(scopeKey);
      if (concurrent) {
        writeJson(ctx.res, concurrent.status, concurrent.body, {
          ...definedHeaders(concurrent.headers),
          "idempotency-replayed": "true",
          "x-request-id": ctx.request_id,
        });
        return;
      }
      throw new HttpError(409, "IDEMPOTENCY_KEY_REUSED", "The idempotency key is already in use.");
    }

    const chunks: Buffer[] = [];
    const originalWrite = ctx.res.write.bind(ctx.res);
    const originalEnd = ctx.res.end.bind(ctx.res);
    let capturedStatus = 0;
    ctx.res.write = ((chunk: unknown, ...rest: unknown[]) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      return (originalWrite as (...args: unknown[]) => boolean)(chunk, ...rest);
    }) as typeof ctx.res.write;
    ctx.res.end = ((chunk?: unknown, ...rest: unknown[]) => {
      if (chunk !== undefined && chunk !== null) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
        capturedStatus = ctx.res.statusCode;
        return (originalEnd as (...args: unknown[]) => unknown)(chunk, ...rest);
      }
      capturedStatus = ctx.res.statusCode;
      return (originalEnd as (...args: unknown[]) => unknown)(...rest);
    }) as typeof ctx.res.end;

    await run();

    const captured = Buffer.concat(chunks).toString("utf8");
    let parsed: unknown = null;
    try {
      parsed = captured.length > 0 ? JSON.parse(captured) : null;
    } catch {
      parsed = null;
    }
    await this.service.deps.idempotency.complete(scopeKey, {
      status: capturedStatus || ctx.res.statusCode,
      headers: this.captureHeaders(ctx.res),
      body: parsed,
    });
  }

  /** Capture the response headers worth replaying (defined values only). */
  private captureHeaders(res: ServerResponse): Record<string, string> {
    const out: Record<string, string> = {};
    const location = res.getHeader("location");
    if (typeof location === "string") {
      out.location = location;
    }
    return out;
  }

  /** Per-principal token bucket. */
  private checkRateLimit(principalId: string): Record<string, string> {
    const capacity = this.service.config.rate_limit_per_minute;
    if (capacity <= 0) {
      return {};
    }
    const now = this.now();
    let bucket = this.buckets.get(principalId);
    if (!bucket) {
      bucket = new TokenBucket(capacity, now);
      this.buckets.set(principalId, bucket);
    }
    const result = bucket.consume(now);
    if (!result.allowed) {
      throw rateLimited("api_key_minute", result.resetAfterSeconds);
    }
    return {
      "x-ratelimit-limit": String(capacity),
      "x-ratelimit-remaining": String(Math.max(0, result.remaining)),
      "x-ratelimit-reset": String(Math.ceil((now + result.resetAfterSeconds * 1000) / 1000)),
    };
  }

  /** A stable, non-secret bucket key for the rate limiter. */
  private principalHint(headers: Record<string, string | string[] | undefined>): string {
    const apiKey = headers["x-api-key"];
    const authorization = headers.authorization;
    const raw =
      typeof apiKey === "string" && apiKey
        ? apiKey
        : typeof authorization === "string"
          ? authorization
          : "anonymous";
    // Hash the credential so the bucket key never contains key material.
    return canonicalDigest(raw).slice(0, 16);
  }

  /** Buffer the request body with a hard size cap. */
  private readBody(req: IncomingMessage): Promise<Buffer> {
    const limit = this.service.config.body_limit_bytes;
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let settled = false;
      req.on("data", (chunk: Buffer) => {
        if (settled) {
          return;
        }
        size += chunk.length;
        if (size > limit) {
          settled = true;
          // Stop consuming, but keep the socket alive long enough to write the
          // 413 response — destroying the request would kill the connection
          // before the client can read the error.
          req.pause();
          reject(
            new HttpError(413, "PAYLOAD_TOO_LARGE", "The request body exceeds the configured limit."),
          );
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => {
        if (!settled) {
          settled = true;
          resolve(Buffer.concat(chunks));
        }
      });
      req.on("error", (error) => {
        if (!settled) {
          settled = true;
          reject(error);
        }
      });
    });
  }
}

/**
 * Drop headers whose value is `undefined` — Node rejects them and they carry
 * no information anyway.
 */
export function definedHeaders(
  headers: Record<string, string | undefined> | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (typeof value === "string") {
      out[key] = value;
    }
  }
  return out;
}

/** Normalize node headers into a plain record. */export function normalizeHeaders(req: IncomingMessage): Record<string, string | string[] | undefined> {
  const out: Record<string, string | string[] | undefined> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    out[key.toLowerCase()] = value;
  }
  return out;
}

/**
 * Canonicalize a body for the idempotency digest.
 *
 * The body is parsed as JSON when possible so that field ordering does not
 * matter (§5.1 "Comparison"); otherwise the raw bytes are hashed.
 */
export function normalizeBodyForDigest(body: Buffer): unknown {
  if (body.length === 0) {
    return null;
  }
  try {
    return JSON.parse(body.toString("utf8"));
  } catch {
    return body.toString("base64");
  }
}

/** The canonical RailGun route table (§2.1). */
export function buildRouter(service: HttpService): Router {
  const router = new Router();
  const openApi = () => buildOpenApiDocument(router.list());
  router.add({
    method: "GET",
    template: "/health",
    name: "health",
    public: true,
    handler: (ctx) => handleHealth(ctx, service),
  });
  router.add({
    method: "GET",
    template: "/healthz",
    name: "health",
    public: true,
    handler: (ctx) => handleHealth(ctx, service),
  });
  router.add({
    method: "GET",
    template: "/ready",
    name: "ready",
    publicWhen: (config) => config.readiness_public,
    handler: (ctx) => handleReady(ctx, service),
  });
  router.add({
    method: "GET",
    template: "/readyz",
    name: "ready",
    publicWhen: (config) => config.readiness_public,
    handler: (ctx) => handleReady(ctx, service),
  });
  router.add({
    method: "GET",
    template: "/metrics",
    name: "metrics",
    publicWhen: (config) => config.metrics_public,
    handler: (ctx) => handleMetrics(ctx, service),
  });
  router.add({
    method: "POST",
    template: "/v1/email/send",
    name: "email.send",
    scope: "send",
    handler: (ctx) => handleSend(ctx, service),
  });
  router.add({
    method: "POST",
    template: "/send",
    name: "email.send",
    scope: "send",
    handler: (ctx) => handleSend(ctx, service),
  });
  router.add({
    method: "GET",
    template: "/v1/openapi.json",
    name: "openapi",
    scope: "read",
    handler: async (ctx) => {
      writeJson(ctx.res, 200, openApi(), {
        "x-request-id": ctx.request_id,
      });
    },
  });
  router.add({
    method: "GET",
    template: "/v1/messages",
    name: "messages.list",
    scope: "read",
    handler: (ctx) => handleListMessages(ctx, service),
  });
  router.add({
    method: "GET",
    template: "/v1/messages/{id}",
    name: "messages.get",
    scope: "read",
    handler: (ctx) => handleGetMessage(ctx, service),
  });
  router.add({
    method: "POST",
    template: "/v1/messages/{id}/retry",
    name: "messages.retry",
    scope: "admin",
    handler: (ctx) => handleRetry(ctx, service),
  });
  router.add({
    method: "POST",
    template: "/v1/messages/{id}/suppress",
    name: "messages.suppress",
    scope: "admin",
    idempotency: "natural",
    handler: (ctx) => handleSuppress(ctx, service),
  });
  router.add({
    method: "GET",
    template: "/v1/bounces",
    name: "bounces.list",
    scope: "read",
    handler: (ctx) => handleListBounces(ctx, service),
  });
  router.add({
    method: "GET",
    template: "/v1/stats",
    name: "stats.get",
    scope: "read",
    handler: (ctx) => handleStats(ctx, service),
  });
  router.add({
    method: "POST",
    template: "/v1/events",
    name: "events",
    scope: "feedback",
    handler: (ctx) => handleEvents(ctx, service),
  });
  return router;
}
