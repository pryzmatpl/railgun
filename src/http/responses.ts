// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * Response helpers: JSON writing, ETags and the sanitized error renderer.
 */

import { createHash } from "node:crypto";
import type { ServerResponse } from "node:http";
import { HttpError, sanitizePayload } from "./errors.js";

/** Write a JSON response with the canonical content type. */
export function writeJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  const payload = Buffer.from(JSON.stringify(body ?? null), "utf8");
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(payload.byteLength),
    ...headers,
  });
  res.end(payload);
}

/** Write a plain-text response (used by `/metrics`). */
export function writeText(
  res: ServerResponse,
  status: number,
  body: string,
  headers: Record<string, string> = {},
): void {
  const payload = Buffer.from(body, "utf8");
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "content-length": String(payload.byteLength),
    ...headers,
  });
  res.end(payload);
}

/** Strong ETag over the serialized resource (§9.5). */
export function etagOf(body: unknown): string {
  const json = JSON.stringify(body ?? null);
  return `"${createHash("sha256").update(json).digest("hex").slice(0, 32)}"`;
}

/** True when the client's `If-None-Match` matches the computed ETag. */
export function etagMatches(ifNoneMatch: string | undefined, etag: string): boolean {
  if (!ifNoneMatch) {
    return false;
  }
  return ifNoneMatch
    .split(",")
    .map((entry) => entry.trim())
    .some((entry) => entry === etag || entry === "*" || entry === `W/${etag}`);
}

/**
 * Render an error as the canonical sanitized envelope (§8.1).
 *
 * Unknown exceptions collapse into `500 INTERNAL_ERROR` with no details, so
 * a stack trace can never reach the wire.
 */
export function writeError(
  res: ServerResponse,
  error: unknown,
  request_id: string,
): void {
  if (error instanceof HttpError) {
    const envelope = error.toEnvelope(request_id);
    writeJson(res, error.status, sanitizePayload(envelope), {
      ...error.headers,
      "x-request-id": request_id,
    });
    return;
  }
  writeJson(
    res,
    500,
    sanitizePayload({
      error: { code: "INTERNAL_ERROR", message: "Internal error." },
      request_id,
    }),
    { "x-request-id": request_id },
  );
}
