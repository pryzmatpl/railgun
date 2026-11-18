// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * Streamable HTTP transport contract (MCP-AC5, MCP-AC6) and principal/tenant
 * authorization (MCP-AC4).
 */

import { afterEach, describe, expect, it } from "vitest";

import { MemoryEmailApplication } from "../../src/application/memory-email-application.js";
import { createRailGunMcpServer } from "../../src/mcp/server.js";
import {
  createHttpContextResolver,
  startHttpTransport,
  type HttpTransportHandle,
} from "../../src/mcp/transports/http.js";
import { makePrincipal, TestPrincipalResolver, TEST_SALT } from "./fixtures.js";

const handles: HttpTransportHandle[] = [];

afterEach(async () => {
  while (handles.length > 0) {
    const handle = handles.pop();
    await handle?.close();
  }
});

async function startServer(
  application: MemoryEmailApplication,
  resolver: TestPrincipalResolver,
): Promise<{ handle: HttpTransportHandle; url: string }> {
  const handle = await startHttpTransport({
    createServer: () =>
      createRailGunMcpServer({
        application,
        principalResolver: resolver,
        recipientSalt: TEST_SALT,
        resolveContext: createHttpContextResolver(resolver),
      }),
    principalResolver: resolver,
    host: "127.0.0.1",
    port: 0,
    enableJsonResponse: true,
    log: () => {},
  });
  handles.push(handle);
  return { handle, url: handle.url };
}

const INITIALIZE_BODY = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "railgun-test-client", version: "1.0.0" },
  },
};

describe("RailGun MCP streamable HTTP transport", () => {
  it("completes initialize and returns a session id", async () => {
    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    resolver.apiKeys.set("test-key", makePrincipal());
    const { url } = await startServer(application, resolver);

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: "Bearer test-key",
      },
      body: JSON.stringify(INITIALIZE_BODY),
    });

    expect(response.status).toBe(200);
    const sessionId = response.headers.get("mcp-session-id");
    expect(sessionId).toBeTruthy();

    const text = await response.text();
    expect(text).toContain("railgun");
  });

  it("lists the four tools over HTTP", async () => {
    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    resolver.apiKeys.set("test-key", makePrincipal());
    const { url } = await startServer(application, resolver);

    const initResponse = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: "Bearer test-key",
      },
      body: JSON.stringify(INITIALIZE_BODY),
    });
    const sessionId = initResponse.headers.get("mcp-session-id") ?? "";

    const listResponse = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: "Bearer test-key",
        "mcp-session-id": sessionId,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    });

    expect(listResponse.status).toBe(200);
    const body = await listResponse.text();
    for (const name of ["email_send", "email_status", "email_bounces", "email_stats"]) {
      expect(body).toContain(name);
    }
  });

  it("calls a tool over HTTP", async () => {
    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    resolver.apiKeys.set("test-key", makePrincipal());
    const { url } = await startServer(application, resolver);

    const initResponse = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: "Bearer test-key",
      },
      body: JSON.stringify(INITIALIZE_BODY),
    });
    const sessionId = initResponse.headers.get("mcp-session-id") ?? "";

    const callResponse = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: "Bearer test-key",
        "mcp-session-id": sessionId,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "email_send",
          arguments: {
            to: "alice@example.com",
            subject: "Hello",
            text: "Hi there",
            requestId: "req-http-1",
          },
        },
      }),
    });

    expect(callResponse.status).toBe(200);
    const body = await callResponse.text();
    expect(body).toContain("req-http-1");
    expect(body).toContain("queued");
  });

  it("rejects an unauthenticated tool call with 401", async () => {
    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    const { url } = await startServer(application, resolver);

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "email_send",
          arguments: {
            to: "alice@example.com",
            subject: "Hello",
            text: "Hi",
            requestId: "req-unauth",
          },
        },
      }),
    });

    expect(response.status).toBe(401);
    const body = await response.text();
    expect(body).toContain("UNAUTHENTICATED");
  });

  it("rejects an ambiguous credential with 401", async () => {
    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    resolver.apiKeys.set("test-key", makePrincipal());
    const { url } = await startServer(application, resolver);

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: "Bearer test-key",
        "x-api-key": "test-key",
      },
      body: JSON.stringify(INITIALIZE_BODY),
    });

    expect(response.status).toBe(401);
    expect(await response.text()).toContain("AMBIGUOUS_AUTH");
  });

  it("rejects a tool call whose principal lacks the scope with 403", async () => {
    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    resolver.apiKeys.set(
      "read-only",
      makePrincipal({ scopes: ["read"], roles: ["auditor"] }),
    );
    const { url } = await startServer(application, resolver);

    const initResponse = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: "Bearer read-only",
      },
      body: JSON.stringify(INITIALIZE_BODY),
    });
    const sessionId = initResponse.headers.get("mcp-session-id") ?? "";

    const callResponse = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: "Bearer read-only",
        "mcp-session-id": sessionId,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "email_send",
          arguments: {
            to: "alice@example.com",
            subject: "Hello",
            text: "Hi",
            requestId: "req-forbidden",
          },
        },
      }),
    });

    // The MCP transport answers the JSON-RPC call; the forbidden reason code
    // is carried in the tool error payload.
    expect(callResponse.status).toBe(200);
    const body = await callResponse.text();
    expect(body).toContain("FORBIDDEN");
    expect(body).toContain("send");
  });

  it("serves an unauthenticated liveness endpoint", async () => {
    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    const { handle } = await startServer(application, resolver);

    const response = await fetch(`http://127.0.0.1:${handle.port}/healthz`);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({ status: "ok" });
  });
});
