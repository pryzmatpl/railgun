// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Remote operator transport.
 *
 * With `--url`, every operator command becomes a call to the versioned HTTP
 * API. The CLI maps the API's stable error envelope back onto the CLI error
 * envelope, so remote and local mode produce equivalent observable results.
 */
import { EXIT, type ExitCode, CliError, type ErrorCode } from "../cli/errors.js";
import type {
  BounceProjection,
  MessageProjection,
  Page,
  QueueStatsProjection,
  StatsProjection,
  SuppressionProjection,
} from "../domain/types.js";

/** The HTTP client the remote transport uses. */
export interface HttpClient {
  request(input: {
    method: string;
    path: string;
    query?: Record<string, string | undefined>;
    body?: unknown;
    headers?: Record<string, string>;
  }): Promise<{ status: number; json: unknown }>;
}

/**
 * Map an HTTP status onto the stable CLI exit-code contract.
 *
 * The mapping follows the operator CLI IR §3.4: configuration and dependency
 * problems are distinguished from permanent operation failures.
 */
export function exitCodeForHttpStatus(status: number): ExitCode {
  if (status === 401 || status === 403) {
    return EXIT.AUTH;
  }
  if (status === 429) {
    return EXIT.OPERATION_FAILED;
  }
  if (status === 502 || status === 503 || status === 504) {
    return EXIT.DEPENDENCY;
  }
  return EXIT.OPERATION_FAILED;
}

/** Map an API error code onto the closest CLI error code. */
function cliCodeForApiCode(apiCode: string): ErrorCode {
  switch (apiCode) {
    case "UNAUTHENTICATED":
    case "UNAUTHORIZED":
      return "AUTH_INVALID";
    case "INSUFFICIENT_SCOPE":
    case "FORBIDDEN":
    case "ACTION_NOT_PERMITTED":
      return "INSUFFICIENT_SCOPE";
    case "NOT_FOUND":
    case "IDENTITY_NOT_FOUND":
      return "NOT_FOUND";
    case "SUPPRESSION_CONFLICT":
    case "IDEMPOTENCY_KEY_REUSED":
    case "MESSAGE_NOT_RETRYABLE":
      return "CONFLICT";
    case "INVALID_REQUEST":
    case "AMBIGUOUS_FIELD":
    case "AMBIGUOUS_AUTH":
    case "UNKNOWN_FILTER":
    case "INVALID_CURSOR":
    case "INVALID_LIMIT":
      return "INVALID_REQUEST";
    case "RATE_LIMITED":
    case "QUOTA_EXCEEDED":
    case "RATE_LIMITED_BY_POLICY":
      return "RATE_LIMITED";
    case "UPSTREAM_UNAVAILABLE":
      return "UPSTREAM_UNAVAILABLE";
    case "UPSTREAM_TIMEOUT":
      return "UPSTREAM_TIMEOUT";
    case "NOT_READY":
      return "NOT_READY";
    case "INTERNAL_ERROR":
    case "UNKNOWN":
      return "INTERNAL_ERROR";
    default:
      return "INTERNAL_ERROR";
  }
}

/** Convert an API error response into a CLI error. */
export function errorFromHttpResponse(status: number, body: unknown): CliError {
  const envelope = body as
    | { error?: { code?: string; message?: string; details?: Record<string, unknown>; request_id?: string } }
    | undefined;
  const apiCode = envelope?.error?.code ?? "UNKNOWN";
  const message = envelope?.error?.message ?? `The remote API returned HTTP ${status}`;
  return new CliError({
    code: cliCodeForApiCode(apiCode),
    message,
    exitCode: exitCodeForHttpStatus(status),
    details: envelope?.error?.details,
    requestId: envelope?.error?.request_id,
  });
}

/** A `fetch`-based HTTP client with a bounded timeout. */
export class FetchHttpClient implements HttpClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly timeoutMs: number;

  constructor(options: { baseUrl: string; apiKey?: string | undefined; timeoutMs?: number }) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  async request(input: {
    method: string;
    path: string;
    query?: Record<string, string | undefined>;
    body?: unknown;
    headers?: Record<string, string>;
  }): Promise<{ status: number; json: unknown }> {
    const url = new URL(`${this.baseUrl}${input.path}`);
    for (const [key, value] of Object.entries(input.query ?? {})) {
      if (value !== undefined) {
        url.searchParams.set(key, value);
      }
    }

    const headers: Record<string, string> = {
      accept: "application/json",
      ...input.headers,
    };
    if (input.body !== undefined) {
      headers["content-type"] = "application/json";
    }
    if (this.apiKey) {
      headers["authorization"] = `Bearer ${this.apiKey}`;
      headers["x-api-key"] = this.apiKey;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const init: RequestInit = {
        method: input.method,
        headers,
        signal: controller.signal,
      };
      if (input.body !== undefined) {
        init.body = JSON.stringify(input.body);
      }
      const response = await fetch(url, init);
      const text = await response.text();
      let json: unknown = null;
      if (text.length > 0) {
        try {
          json = JSON.parse(text);
        } catch {
          json = null;
        }
      }
      return { status: response.status, json };
    } catch (cause) {
      if (cause instanceof Error && cause.name === "AbortError") {
        throw CliError.dependency(`The remote API did not respond within ${this.timeoutMs}ms`, {
          url: url.origin,
        });
      }
      throw CliError.dependency(`The remote API could not be reached: ${url.origin}`, {
        url: url.origin,
      });
    } finally {
      clearTimeout(timer);
    }
  }
}

/** The remote operator client. */
export class RemoteOperatorClient {
  private readonly http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  private async call(input: {
    method: string;
    path: string;
    query?: Record<string, string | undefined>;
    body?: unknown;
  }): Promise<unknown> {
    const response = await this.http.request(input);
    if (response.status >= 400) {
      throw errorFromHttpResponse(response.status, response.json);
    }
    return response.json;
  }

  async listMessages(query: Record<string, string | undefined>): Promise<Page<MessageProjection>> {
    const body = (await this.call({ method: "GET", path: "/v1/messages", query })) as {
      items?: MessageProjection[];
      next_cursor?: string | null;
      total?: number | null;
    };
    return {
      items: body?.items ?? [],
      nextCursor: body?.next_cursor ?? null,
      total: body?.total ?? null,
    };
  }

  async getMessage(id: string): Promise<MessageProjection> {
    const body = (await this.call({ method: "GET", path: `/v1/messages/${encodeURIComponent(id)}` })) as {
      message?: MessageProjection;
    };
    if (!body?.message) {
      throw CliError.notFound(`Message not found: ${id}`, { message_id: id });
    }
    return body.message;
  }

  async retryMessage(id: string): Promise<MessageProjection> {
    const body = (await this.call({
      method: "POST",
      path: `/v1/messages/${encodeURIComponent(id)}/retry`,
    })) as { message?: MessageProjection };
    if (!body?.message) {
      throw CliError.notFound(`Message not found: ${id}`, { message_id: id });
    }
    return body.message;
  }

  async suppressMessage(id: string, reason: string, expiresAt: string | null): Promise<MessageProjection> {
    const body = (await this.call({
      method: "POST",
      path: `/v1/messages/${encodeURIComponent(id)}/suppress`,
      body: { reason, expires_at: expiresAt },
    })) as { message?: MessageProjection };
    if (!body?.message) {
      throw CliError.notFound(`Message not found: ${id}`, { message_id: id });
    }
    return body.message;
  }

  async listBounces(query: Record<string, string | undefined>): Promise<Page<BounceProjection>> {
    const body = (await this.call({ method: "GET", path: "/v1/bounces", query })) as {
      items?: BounceProjection[];
      next_cursor?: string | null;
      total?: number | null;
    };
    return {
      items: body?.items ?? [],
      nextCursor: body?.next_cursor ?? null,
      total: body?.total ?? null,
    };
  }

  async stats(query: Record<string, string | undefined>): Promise<StatsProjection> {
    const body = (await this.call({ method: "GET", path: "/v1/stats", query })) as StatsProjection;
    return body;
  }

  async queueStats(): Promise<QueueStatsProjection> {
    const body = (await this.call({ method: "GET", path: "/v1/queue/stats" })) as QueueStatsProjection;
    return body;
  }

  async listSuppressions(): Promise<SuppressionProjection[]> {
    const body = (await this.call({ method: "GET", path: "/v1/suppressions" })) as {
      items?: SuppressionProjection[];
    };
    return body?.items ?? [];
  }

  async addSuppression(input: {
    scope: string;
    reason: string;
    expiresAt: string | null;
  }): Promise<{ suppression: SuppressionProjection; created: boolean }> {
    const body = (await this.call({
      method: "POST",
      path: "/v1/suppressions",
      body: { scope: input.scope, reason: input.reason, expires_at: input.expiresAt },
    })) as { suppression?: SuppressionProjection; created?: boolean };
    if (!body?.suppression) {
      throw CliError.dependency("The remote API did not return a suppression projection");
    }
    return { suppression: body.suppression, created: body.created ?? true };
  }
}
