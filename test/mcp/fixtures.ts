// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * Shared test fixtures for the RailGun MCP test-suite.
 */

import type { Principal, PrincipalResolver } from "../../src/mcp/auth.js";

export const TEST_SALT = "railgun-test-salt";

export function makePrincipal(overrides: Partial<Principal> = {}): Principal {
  return {
    principalId: "prp_sender_a",
    tenantId: "tnt_a",
    roles: ["sender"],
    scopes: ["send", "read"],
    senderOverride: false,
    bodyRead: false,
    allowedSenders: [],
    ...overrides,
  };
}

/**
 * An in-memory principal resolver keyed by API key and JWT.
 *
 * The keys are plain test fixtures; no real credential ever appears here.
 */
export class TestPrincipalResolver implements PrincipalResolver {
  readonly apiKeys = new Map<string, Principal>();
  readonly jwts = new Map<string, Principal>();
  readonly locals = new Map<string, Principal>();

  async resolveApiKey(apiKey: string): Promise<Principal | null> {
    return this.apiKeys.get(apiKey) ?? null;
  }

  async resolveJwt(token: string): Promise<Principal | null> {
    return this.jwts.get(token) ?? null;
  }

  async resolveLocal(label: string): Promise<Principal | null> {
    return this.locals.get(label) ?? null;
  }
}

/** A syntactically valid three-segment token used to exercise the JWT path. */
export const TEST_JWT = "header.payload.signature";
