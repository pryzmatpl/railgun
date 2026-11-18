// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * Exact-path route table.
 *
 * Matching is **exact** (or an exact template match with `{param}` segments).
 * A prefix match is forbidden: the `/health` prefix-shadowing hazard recorded
 * in `src/gateway/prism-http.ts:23` broke the Docker healthcheck while
 * everything else was healthy (IR §6.5, operator IR §6.8).
 */

import type { IncomingMessage, ServerResponse } from "node:http";

export interface RequestContext {
  req: IncomingMessage;
  res: ServerResponse;
  /** Exact request path, without the query string. */
  path: string;
  method: string;
  url: URL;
  /** Parsed query parameters (repeated keys preserved). */
  query: URLSearchParams;
  /** Path parameters captured from `{…}` templates. */
  params: Record<string, string>;
  request_id: string;
  /** Raw request body, buffered by the server. */
  body: Buffer;
  /** Lower-cased request headers. */
  headers: Record<string, string | string[] | undefined>;
  /** The authenticated principal; absent on public routes. */
  principal?: import("./types.js").Principal;
}

export type RouteHandler = (ctx: RequestContext) => Promise<void>;

export interface RouteDefinition {
  method: string;
  /** Path template, e.g. `/v1/messages/{id}`. */
  template: string;
  /** Stable route name used for logs, metrics and audit records. */
  name: string;
  /** Public routes skip authentication entirely (§2.2). */
  public?: boolean;
  /**
   * Optional predicate that makes an otherwise protected route public, e.g.
   * `/metrics` when `http.metrics_public` is enabled (§2.2).
   */
  publicWhen?: (config: { metrics_public: boolean; readiness_public: boolean }) => boolean;
  /** Scope required to call the route (checked after authentication). */
  scope?: string;
  /**
   * How the route is protected against duplicate writes.
   *
   * - `header` (default): the explicit `Idempotency-Key` replay guard (§5.1).
   * - `natural`: the route owns its own idempotency (e.g. the suppression
   *   route, whose §5.5 contract returns the existing record with
   *   `created:false` instead of replaying the original response).
   */
  idempotency?: "header" | "natural";
  handler: RouteHandler;
}

interface CompiledRoute extends RouteDefinition {
  segments: string[];
}

export class Router {
  private readonly routes: CompiledRoute[] = [];

  constructor(routes: RouteDefinition[] = []) {
    for (const route of routes) {
      this.add(route);
    }
  }

  add(route: RouteDefinition): this {
    this.routes.push({ ...route, segments: splitPath(route.template) });
    return this;
  }

  /** All registered routes — used by the OpenAPI generator and `doctor`. */
  list(): readonly RouteDefinition[] {
    return this.routes.map(({ segments: _segments, ...route }) => route);
  }

  /**
   * Resolve a request.
   *
   * Returns the matching route plus its path parameters, `null` when no path
   * matches at all, and a `methodMismatch` flag when the path exists but the
   * method does not (→ `405`).
   */
  match(
    method: string,
    path: string,
  ): { route: CompiledRoute; params: Record<string, string> } | { methodMismatch: true; allowed: string[] } | null {
    const segments = splitPath(path);
    const pathMatches: CompiledRoute[] = [];
    for (const route of this.routes) {
      const params = matchSegments(route.segments, segments);
      if (params) {
        pathMatches.push(route);
      }
    }
    if (pathMatches.length === 0) {
      return null;
    }
    const upper = method.toUpperCase();
    const exact = pathMatches.find((route) => route.method.toUpperCase() === upper);
    if (exact) {
      return { route: exact, params: matchSegments(exact.segments, segments) ?? {} };
    }
    return {
      methodMismatch: true,
      allowed: [...new Set(pathMatches.map((route) => route.method.toUpperCase()))],
    };
  }
}

/** Split a path into non-empty segments. */
export function splitPath(path: string): string[] {
  return path.split("/").filter((segment) => segment.length > 0);
}

/**
 * Match route segments against request segments.
 *
 * `{name}` captures one segment. Exact (non-template) segments must match
 * literally.
 */
export function matchSegments(
  routeSegments: readonly string[],
  requestSegments: readonly string[],
): Record<string, string> | null {
  if (routeSegments.length !== requestSegments.length) {
    return null;
  }
  const params: Record<string, string> = {};
  for (let index = 0; index < routeSegments.length; index += 1) {
    const routeSegment = routeSegments[index] as string;
    const requestSegment = requestSegments[index] as string;
    if (routeSegment.startsWith("{") && routeSegment.endsWith("}")) {
      const name = routeSegment.slice(1, -1);
      if (requestSegment.length === 0) {
        return null;
      }
      params[name] = decodeURIComponent(requestSegment);
      continue;
    }
    if (routeSegment !== requestSegment) {
      return null;
    }
  }
  return params;
}
