// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * Principal and tenant authorization (MCP-AC4).
 *
 * A principal must never observe another tenant's message, bounce or stats.
 * Cross-tenant identifiers behave as non-existent (`NOT_FOUND`), never as
 * `FORBIDDEN`, so the MCP surface does not disclose their existence.
 */

import { describe, expect, it } from "vitest";

import { MemoryEmailApplication } from "../../src/application/memory-email-application.js";
import type { BounceRecord, StoredMessage } from "../../src/domain/message.js";
import { buildRequestContext } from "../../src/mcp/auth.js";
import { RailGunError } from "../../src/mcp/errors.js";
import { createRailGunMcpServer } from "../../src/mcp/server.js";
import { makePrincipal, TestPrincipalResolver, TEST_SALT } from "./fixtures.js";

function seedMessage(overrides: Partial<StoredMessage> = {}): StoredMessage {
  return {
    id: "rg_message_b",
    tenantId: "tnt_b",
    principalId: "prp_sender_b",
    requestId: "req-b-1",
    messageId: "<b@railgun>",
    subject: "Secret",
    body: { text: "secret body" },
    envelope: {
      sender: "b@example.com",
      recipients: [{ address: "target@example.com", status: "bounced", attempts: 2 }],
    },
    status: "bounced",
    attempts: 2,
    createdAt: "2026-11-18T10:00:00.000Z",
    updatedAt: "2026-11-18T10:00:05.000Z",
    nextAttemptAt: null,
    lastSmtpCode: "550",
    lastErrorClass: "permanent_failure",
    reason: "mailbox_unavailable",
    attemptHistory: [
      {
        attemptedAt: "2026-11-18T10:00:05.000Z",
        attempt: 2,
        outcome: "bounced",
        smtpCode: "550",
        reason: "mailbox_unavailable",
      },
    ],
    ...overrides,
  };
}

function seedBounce(overrides: Partial<BounceRecord> = {}): BounceRecord {
  return {
    messageId: "rg_message_b",
    tenantId: "tnt_b",
    principalId: "prp_sender_b",
    recipient: "target@example.com",
    occurredAt: "2026-11-18T10:00:05.000Z",
    code: "5.1.1",
    reason: "mailbox_unavailable",
    permanent: true,
    diagnostic: "recipient mailbox unavailable",
    ...overrides,
  };
}

describe("tenant isolation", () => {
  it("returns NOT_FOUND for another tenant's message", async () => {
    const application = new MemoryEmailApplication();
    application.seedMessage(seedMessage());
    const resolver = new TestPrincipalResolver();

    const principal = makePrincipal();
    const server = createRailGunMcpServer({
      application,
      principalResolver: resolver,
      recipientSalt: TEST_SALT,
      resolveContext: () => {
        throw new Error("unused");
      },
    });

    const context = buildRequestContext(principal, "stdio", null);
    await expect(
      server.callTool("email_status", { id: "rg_message_b" }, context),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("never exposes another tenant's bounces", async () => {
    const application = new MemoryEmailApplication();
    application.seedBounce(seedBounce());
    const resolver = new TestPrincipalResolver();

    const principal = makePrincipal();
    const server = createRailGunMcpServer({
      application,
      principalResolver: resolver,
      recipientSalt: TEST_SALT,
      resolveContext: () => {
        throw new Error("unused");
      },
    });

    const context = buildRequestContext(principal, "stdio", null);
    const result = await server.callTool("email_bounces", {}, context);
    const payload = result.structuredContent as { items: unknown[]; count: number };
    expect(payload.items).toEqual([]);
    expect(payload.count).toBe(0);
  });

  it("never exposes another tenant's stats", async () => {
    const application = new MemoryEmailApplication();
    application.seedMessage(seedMessage());
    const resolver = new TestPrincipalResolver();

    const principal = makePrincipal();
    const server = createRailGunMcpServer({
      application,
      principalResolver: resolver,
      recipientSalt: TEST_SALT,
      resolveContext: () => {
        throw new Error("unused");
      },
    });

    const context = buildRequestContext(principal, "stdio", null);
    const result = await server.callTool("email_stats", {}, context);
    const payload = result.structuredContent as {
      tenant_id: string;
      totals: Record<string, number>;
    };
    expect(payload.tenant_id).toBe("tnt_a");
    expect(payload.totals.bounced).toBe(0);
    expect(payload.totals.queued).toBe(0);
  });

  it("lets the owning tenant read its own message", async () => {
    const application = new MemoryEmailApplication();
    application.seedMessage(seedMessage());
    const resolver = new TestPrincipalResolver();

    const principal = makePrincipal({ tenantId: "tnt_b", principalId: "prp_sender_b" });
    const server = createRailGunMcpServer({
      application,
      principalResolver: resolver,
      recipientSalt: TEST_SALT,
      resolveContext: () => {
        throw new Error("unused");
      },
    });

    const context = buildRequestContext(principal, "stdio", null);
    const result = await server.callTool("email_status", { id: "rg_message_b" }, context);
    const payload = result.structuredContent as { id: string; status: string };
    expect(payload.id).toBe("rg_message_b");
    expect(payload.status).toBe("bounced");
  });
});

describe("scope enforcement", () => {
  it("denies email_send to a read-only principal with FORBIDDEN", async () => {
    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    const server = createRailGunMcpServer({
      application,
      principalResolver: resolver,
      recipientSalt: TEST_SALT,
      resolveContext: () => {
        throw new Error("unused");
      },
    });

    const principal = makePrincipal({ scopes: ["read"], roles: ["auditor"] });
    const context = buildRequestContext(principal, "stdio", null);

    const error = await server
      .callTool(
        "email_send",
        {
          to: "alice@example.com",
          subject: "Hello",
          text: "Hi",
          requestId: "req-forbidden",
        },
        context,
      )
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(RailGunError);
    expect((error as RailGunError).code).toBe("FORBIDDEN");
    expect((error as RailGunError).requiredScope).toBe("send");
  });

  it("does not let the admin scope imply the send scope", async () => {
    const application = new MemoryEmailApplication();
    const resolver = new TestPrincipalResolver();
    const server = createRailGunMcpServer({
      application,
      principalResolver: resolver,
      recipientSalt: TEST_SALT,
      resolveContext: () => {
        throw new Error("unused");
      },
    });

    const principal = makePrincipal({ scopes: ["admin"], roles: ["admin"] });
    const context = buildRequestContext(principal, "stdio", null);

    await expect(
      server.callTool(
        "email_send",
        {
          to: "alice@example.com",
          subject: "Hello",
          text: "Hi",
          requestId: "req-admin",
        },
        context,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});
