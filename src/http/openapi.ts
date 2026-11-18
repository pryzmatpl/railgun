// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * OpenAPI 3.1 document generated from the **same route table** that serves
 * traffic (§9.5). The document is never hand-maintained, so it cannot drift
 * from the implementation.
 */

import type { RouteDefinition } from "./router.js";

/** The JSON-schema fragment for a route's request body. */
function requestBodySchema(route: RouteDefinition): Record<string, unknown> | undefined {
  if (route.method === "GET") {
    return undefined;
  }
  if (route.name === "email.send") {
    return {
      required: true,
      content: {
        "application/json": {
          schema: {
            type: "object",
            properties: {
              to: { oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }] },
              cc: { oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }] },
              bcc: { oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }] },
              subject: { type: "string" },
              text: { type: "string" },
              html: { type: "string" },
              from: { type: "string" },
              reply_to: { type: "string" },
              replyTo: { type: "string" },
              request_id: { type: "string" },
              requestId: { type: "string" },
              idempotency_key: { type: "string" },
              schedule_at: { type: "string", format: "date-time" },
              metadata: { type: "object", additionalProperties: { type: "string" } },
              content_base64: { type: "string" },
              content_type: { type: "string" },
            },
            additionalProperties: true,
          },
        },
      },
    };
  }
  return {
    required: false,
    content: { "application/json": { schema: { type: "object" } } },
  };
}

/** Build the OpenAPI document for a route table. */
export function buildOpenApiDocument(routes: readonly RouteDefinition[]): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const route of routes) {
    const path = route.template.replaceAll(/\{(\w+)\}/g, "{$1}");
    const operation: Record<string, unknown> = {
      operationId: `${route.method.toLowerCase()}${route.template.replaceAll(/[^A-Za-z0-9]+/g, "_")}`,
      summary: route.name,
      tags: [route.template.split("/")[1] || "railgun"],
      security: route.public ? [] : [{ apiKey: [] }, { bearerAuth: [] }],
      responses: {
        "200": { description: "OK" },
        "202": { description: "Accepted" },
        "400": { description: "Invalid request" },
        "401": { description: "Unauthenticated" },
        "403": { description: "Insufficient scope" },
        "404": { description: "Not found" },
        "409": { description: "State conflict" },
        "422": { description: "Rejected" },
        "429": { description: "Rate limited" },
        "500": { description: "Internal error" },
        "503": { description: "Not ready" },
      },
    };
    if (route.scope) {
      operation.parameters = [
        {
          name: "Idempotency-Key",
          in: "header",
          required: false,
          schema: { type: "string" },
          description: "Replay identity for mutating routes.",
        },
      ];
    }
    const body = requestBodySchema(route);
    if (body) {
      operation.requestBody = body;
    }
    paths[path] = { ...paths[path], [route.method.toLowerCase()]: operation };
  }

  return {
    openapi: "3.1.0",
    info: {
      title: "RailGun HTTP API",
      version: "1.0.0",
      description:
        "The versioned RailGun operator API. Acceptance is never delivery: `deliveryConfirmed` is true only after a final upstream 250.",
    },
    servers: [{ url: "/" }],
    components: {
      securitySchemes: {
        apiKey: { type: "apiKey", in: "header", name: "x-api-key" },
        bearerAuth: { type: "http", scheme: "bearer" },
      },
      schemas: {
        Error: {
          type: "object",
          required: ["error", "request_id"],
          properties: {
            error: {
              type: "object",
              required: ["code", "message"],
              properties: {
                code: { type: "string" },
                message: { type: "string" },
                details: { type: "object", additionalProperties: true },
              },
            },
            request_id: { type: "string" },
          },
        },
      },
    },
    paths,
  };
}
