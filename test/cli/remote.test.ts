// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * CLI integration tests for the remote transport.
 *
 * With `--url` every operator command becomes a call to the versioned HTTP
 * API. These tests run a stub API and assert that the CLI produces the same
 * observable shape and the same error classification as it does locally.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import { runCli, withTempDir, writeConfig } from "./helpers.js";

let server: Server | undefined;

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  }
});

/**
 * Start a stub API.
 *
 * `routes` maps `METHOD /path` to a handler returning the JSON body.
 */
async function startStubApi(
  routes: Record<string, (url: URL) => { status: number; body: unknown }>,
): Promise<string> {
  server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");
    const key = `${request.method ?? "GET"} ${url.pathname}`;
    const route = routes[key];
    if (!route) {
      response.statusCode = 404;
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          error: { code: "NOT_FOUND", message: `No route for ${key}` },
        }),
      );
      return;
    }
    const { status, body } = route(url);
    response.statusCode = status;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify(body));
  });

  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  const address = server?.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

describe("railgun CLI — remote transport", () => {
  it("reads messages through the versioned HTTP API", async () => {
    const baseUrl = await startStubApi({
      "GET /v1/messages": () => ({
        status: 200,
        body: {
          items: [
            {
              id: "rg_remote",
              tenant: "default",
              status: "queued",
              deliveryConfirmed: false,
              messageId: "<rg_remote@railgun>",
              subject: "Hello",
              from: null,
              recipients: [],
              attempts: 0,
              createdAt: "2026-01-01T00:00:00.000Z",
              updatedAt: "2026-01-01T00:00:00.000Z",
              policyReason: null,
              lastResponse: null,
            },
          ],
          next_cursor: null,
          total: 1,
        },
      }),
    });

    const result = await runCli(["messages", "list", "--url", baseUrl, "--json"]);
    expect(result.code).toBe(0);
    const parsed = JSON.parse(result.stdout) as { items: { id: string }[] };
    expect(parsed.items).toHaveLength(1);
    expect(parsed.items[0]?.id).toBe("rg_remote");
  });

  it("maps a remote 404 onto the stable not-found error", async () => {
    const baseUrl = await startStubApi({
      "GET /v1/messages/rg_missing": () => ({
        status: 404,
        body: { error: { code: "NOT_FOUND", message: "Message not found" } },
      }),
    });

    const result = await runCli([
      "messages",
      "show",
      "rg_missing",
      "--url",
      baseUrl,
      "--json",
    ]);
    expect(result.code).toBe(1);
    const parsed = JSON.parse(result.stdout) as { error: { code: string } };
    expect(parsed.error.code).toBe("NOT_FOUND");
  });

  it("maps a remote 401 onto the authentication exit code", async () => {
    const baseUrl = await startStubApi({
      "GET /v1/messages": () => ({
        status: 401,
        body: { error: { code: "UNAUTHENTICATED", message: "Missing credential" } },
      }),
    });

    const result = await runCli(["messages", "list", "--url", baseUrl, "--json"]);
    expect(result.code).toBe(5);
    const parsed = JSON.parse(result.stdout) as { error: { code: string } };
    expect(parsed.error.code).toBe("AUTH_INVALID");
  });

  it("maps a remote 503 onto the dependency exit code", async () => {
    const baseUrl = await startStubApi({
      "GET /v1/messages": () => ({
        status: 503,
        body: { error: { code: "NOT_READY", message: "The store is not ready" } },
      }),
    });

    const result = await runCli(["messages", "list", "--url", baseUrl, "--json"]);
    expect(result.code).toBe(4);
    const parsed = JSON.parse(result.stdout) as { error: { code: string } };
    expect(parsed.error.code).toBe("NOT_READY");
  });

  it("maps an unreachable API onto the dependency exit code", async () => {
    // Port 1 is reserved and refuses connections.
    const result = await runCli([
      "messages",
      "list",
      "--url",
      "http://127.0.0.1:1",
      "--json",
    ]);
    expect(result.code).toBe(4);
    const parsed = JSON.parse(result.stdout) as { error: { code: string } };
    expect(parsed.error.code).toBe("DEPENDENCY_UNAVAILABLE");
  });

  it("produces the same JSON shape locally and remotely", async () => {
    const baseUrl = await startStubApi({
      "GET /v1/stats": () => ({
        status: 200,
        body: {
          queued: 0,
          accepted: 0,
          delivered: 0,
          deferred: 0,
          bounced: 0,
          suppressed: 0,
          rejected: 0,
          windowStart: null,
          windowEnd: null,
          tenant: null,
        },
      }),
    });

    await withTempDir(async (dir) => {
      const configPath = writeConfig(dir);
      const local = await runCli(["stats", "--config", configPath, "--json"]);
      const remote = await runCli(["stats", "--url", baseUrl, "--json"]);
      expect(local.code).toBe(0);
      expect(remote.code).toBe(0);
      expect(Object.keys(JSON.parse(local.stdout) as object).toSorted()).toEqual(
        Object.keys(JSON.parse(remote.stdout) as object).toSorted(),
      );
    });
  });
});
