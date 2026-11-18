// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * Stdio transport round trip (MCP-AC1, MCP-AC7, MCP-AC8).
 *
 * A real MCP client connects over the newline-delimited JSON-RPC stdio
 * transport, lists the tools and calls each of the four RailGun tools.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterEach, describe, expect, it } from "vitest";

import { MemoryEmailApplication } from "../../src/application/memory-email-application.js";
import { createRailGunMcpServer } from "../../src/mcp/server.js";
import { createStdioContextResolver, resolveStdioPrincipal } from "../../src/mcp/transports/stdio.js";
import { makePrincipal, TestPrincipalResolver, TEST_SALT } from "./fixtures.js";

const children: { close: () => Promise<void> }[] = [];

afterEach(async () => {
  while (children.length > 0) {
    const child = children.pop();
    await child?.close();
  }
});

/**
 * Start a stdio MCP server in a child process and connect a client to it.
 *
 * The child runs the *compiled* server (`dist/mcp/transports/stdio-main.js`)
 * so that the suite needs nothing beyond this package's own dependencies —
 * no `tsx`, no monorepo toolchain. `npm test` therefore works in a
 * standalone checkout after `npm run build`.
 */
async function connectClient(
  application: MemoryEmailApplication,
  principalResolver: TestPrincipalResolver,
  apiKey: string,
): Promise<Client> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      new URL("../../dist/mcp/transports/stdio-main.js", import.meta.url).pathname,
      "--stdio",
    ],
    env: {
      ...(process.env as Record<string, string>),
      RAILGUN_MCP_API_KEY: apiKey,
      RAILGUN_MCP_PRINCIPALS: JSON.stringify(
        Object.fromEntries(
          [...principalResolver.apiKeys.entries()].map(([key, value]) => [
            key,
            {
              principalId: value.principalId,
              tenantId: value.tenantId,
              roles: value.roles,
              scopes: value.scopes,
              allowedSenders: value.allowedSenders,
              bodyRead: value.bodyRead,
              senderOverride: value.senderOverride,
            },
          ]),
        ),
      ),
    },
    stderr: "inherit",
  });

  const client = new Client(
    { name: "railgun-test-client", version: "1.0.0" },
    { capabilities: {} },
  );
  await client.connect(transport);
  return client;
}

describe("RailGun MCP stdio transport", () => {
  it("serves the four tools over a stdio round trip", async () => {
    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    resolver.apiKeys.set("test-key", makePrincipal());

    const client = await connectClient(application, resolver, "test-key");

    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name).sort()).toEqual([
      "email_bounces",
      "email_send",
      "email_stats",
      "email_status",
    ]);

    const sent = await client.callTool({
      name: "email_send",
      arguments: {
        to: "alice@example.com",
        subject: "Hello",
        text: "Hi there",
        requestId: "req-stdio-1",
      },
    });
    expect(sent.isError).toBeFalsy();
    const sentPayload = JSON.parse(
      (sent.content as { type: string; text: string }[])[0]?.text ?? "{}",
    );
    expect(sentPayload.status).toBe("queued");
    expect(sentPayload.delivery_confirmed).toBe(false);
    expect(sentPayload.requestId).toBe("req-stdio-1");
    expect(sentPayload.recipients[0].address_hash).toMatch(/^h_[0-9a-f]{32}$/);

    const status = await client.callTool({
      name: "email_status",
      arguments: { id: sentPayload.id },
    });
    const statusPayload = JSON.parse(
      (status.content as { type: string; text: string }[])[0]?.text ?? "{}",
    );
    expect(statusPayload.id).toBe(sentPayload.id);
    expect(statusPayload.status).toBe("queued");

    const bounces = await client.callTool({
      name: "email_bounces",
      arguments: {},
    });
    const bouncePayload = JSON.parse(
      (bounces.content as { type: string; text: string }[])[0]?.text ?? "{}",
    );
    expect(bouncePayload.items).toEqual([]);
    expect(bouncePayload.count).toBe(0);

    const stats = await client.callTool({
      name: "email_stats",
      arguments: {},
    });
    const statsPayload = JSON.parse(
      (stats.content as { type: string; text: string }[])[0]?.text ?? "{}",
    );
    expect(statsPayload.tenant_id).toBe("tnt_a");
    expect(statsPayload.totals.queued).toBe(1);

    await client.close();
  });

  it("honours idempotency across two stdio calls", async () => {
    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    resolver.apiKeys.set("test-key", makePrincipal());

    const client = await connectClient(application, resolver, "test-key");

    const args = {
      to: "alice@example.com",
      subject: "Hello",
      text: "Hi there",
      requestId: "req-stdio-idem",
    };
    const first = await client.callTool({ name: "email_send", arguments: args });
    const second = await client.callTool({ name: "email_send", arguments: args });

    const firstPayload = JSON.parse(
      (first.content as { type: string; text: string }[])[0]?.text ?? "{}",
    );
    const secondPayload = JSON.parse(
      (second.content as { type: string; text: string }[])[0]?.text ?? "{}",
    );
    expect(secondPayload.id).toBe(firstPayload.id);

    await client.close();
  });
});

describe("stdio credential resolution", () => {
  it("resolves the startup principal from the environment", async () => {
    const resolver = new TestPrincipalResolver();
    resolver.apiKeys.set("env-key", makePrincipal());
    const previous = process.env.RAILGUN_MCP_API_KEY;
    process.env.RAILGUN_MCP_API_KEY = "env-key";
    try {
      const principal = await resolveStdioPrincipal({
        server: createRailGunMcpServer({
          application: new MemoryEmailApplication(),
          principalResolver: resolver,
          recipientSalt: TEST_SALT,
          resolveContext: () => {
            throw new Error("unused");
          },
        }),
        principalResolver: resolver,
      });
      expect(principal.tenantId).toBe("tnt_a");
    } finally {
      if (previous === undefined) delete process.env.RAILGUN_MCP_API_KEY;
      else process.env.RAILGUN_MCP_API_KEY = previous;
    }
  });

  it("builds a context resolver bound to the startup principal", async () => {
    const principal = makePrincipal();
    const resolver = createStdioContextResolver(principal);
    const context = await resolver({} as never);
    expect(context.tenantId).toBe("tnt_a");
    expect(context.transport).toBe("stdio");
  });
});
