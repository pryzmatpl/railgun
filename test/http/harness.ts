// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * Test harness for the RailGun HTTP surface.
 *
 * Boots the real service over a real socket with a real HTTP client, the
 * in-memory stores, a deterministic clock and a fake MX sink that records
 * outbound transactions (IR §10.1).
 */

import { createHmac } from "node:crypto";
import type { AddressInfo } from "node:net";
import { hashApiKey } from "../../src/http/auth.js";
import type { ApiKeyRecord, CredentialStore } from "../../src/http/auth.js";
import {
  FixedClock,
  MemoryAuditLog,
  MemoryBounceStore,
  MemoryIdempotencyStore,
  MemoryMessageStore,
  MemoryOutboxQueue,
  MemorySuppressionStore,
  SequentialIds,
} from "../../src/http/memory.js";
import { RailGunHttpServer } from "../../src/http/server.js";
import { HttpService } from "../../src/http/service.js";
import type {
  DomainRegistry,
  HttpConfig,
  PolicyDecision,
  PolicyEngine,
  Principal,
} from "../../src/http/types.js";

/** The plaintext fixture secrets — the leak sweep scans for each of them. */
export const FIXTURE_SECRETS = {
  apiKeyTenantA: "rgk_tenantA_aaaaaaaaaaaaaaaaaaaaaaaa",
  apiKeyTenantB: "rgk_tenantB_bbbbbbbbbbbbbbbbbbbbbbbb",
  apiKeyReadOnly: "rgk_readonly_cccccccccccccccccccccccccc",
  apiKeyAdminOnly: "rgk_adminonly_dddddddddddddddddddddddddd",
  jwtSecret: "fixture-jwt-signing-secret-do-not-leak",
  webhookSecret: "fixture-webhook-secret-do-not-leak",
  smtpPassword: "fixture-smtp-password-do-not-leak",
  dkimPrivateKey: "fixture-dkim-private-key-do-not-leak",
} as const;

/** In-memory credential store for the fixture principals. */
export class MemoryCredentialStore implements CredentialStore {
  readonly records: ApiKeyRecord[] = [];

  add(record: ApiKeyRecord): void {
    this.records.push(record);
  }

  async findByPrefix(prefix: string): Promise<ApiKeyRecord | null> {
    return this.records.find((record) => record.key_prefix === prefix) ?? null;
  }
}

/** Build an API-key record from a plaintext fixture key. */
export function apiKeyRecord(
  id: string,
  tenant_id: string,
  plaintext: string,
  scopes: string[],
  options: Partial<ApiKeyRecord> = {},
): ApiKeyRecord {
  return {
    id,
    tenant_id,
    key_prefix: plaintext.slice(4).split("_")[0] ?? "",
    key_hash: hashApiKey(plaintext),
    scopes,
    roles: [],
    allowed_senders: [`${tenant_id}.example.com`],
    allowed_domains: [`${tenant_id}.example.com`],
    active: true,
    expires_at: null,
    ...options,
  };
}

/** A fake MX sink that counts outbound transactions. */
export class FakeMxSink {
  transactions = 0;
  connections = 0;

  /** Record one outbound SMTP transaction. */
  transaction(): void {
    this.transactions += 1;
  }

  /** Record one outbound connection. */
  connection(): void {
    this.connections += 1;
  }

  reset(): void {
    this.transactions = 0;
    this.connections = 0;
  }
}

/** A domain registry with a configurable verified-domain set. */
export class TestDomainRegistry implements DomainRegistry {
  readonly verified = new Set<string>();
  defaults = new Map<string, string>();

  isVerified(tenant_id: string, domain: string): boolean {
    return this.verified.has(`${tenant_id}:${domain}`) || this.verified.has(domain);
  }

  verifiedSenderDomains(tenant_id: string): string[] {
    const out = new Set<string>();
    for (const key of this.verified) {
      const [tenant, domain] = key.split(":");
      if (tenant === tenant_id && domain) {
        out.add(domain);
      }
    }
    for (const domain of this.verified) {
      if (!domain.includes(":")) {
        out.add(domain);
      }
    }
    return [...out];
  }

  defaultSender(tenant_id: string): string | null {
    return this.defaults.get(tenant_id) ?? null;
  }
}

/** A policy engine with scripted per-recipient outcomes. */
export class TestPolicyEngine implements PolicyEngine {
  /** Addresses that are suppressed for every tenant. */
  readonly suppressed = new Set<string>();
  /** Addresses that are blocked. */
  readonly blocked = new Set<string>();
  /** Message-level rejection code, when set. */
  messageRejection: { code: string; details?: Record<string, unknown> } | null = null;
  /** Tenant-scoped rate-limit rejection. */
  tenantRejection: { code: string; details?: Record<string, unknown> } | null = null;

  async evaluate(input: {
    tenant_id: string;
    recipients: string[];
  }): Promise<PolicyDecision> {
    if (this.messageRejection) {
      return { allowed: false, recipients: [], rejection: this.messageRejection };
    }
    if (this.tenantRejection) {
      return { allowed: false, recipients: [], rejection: this.tenantRejection };
    }
    const recipients = input.recipients.map((address) => {
      if (this.suppressed.has(address)) {
        return {
          address,
          allowed: false,
          status: "suppressed" as const,
          reason: "hard_bounce",
          error_code: "SUPPRESSED",
        };
      }
      if (this.blocked.has(address)) {
        return {
          address,
          allowed: false,
          status: "rejected" as const,
          reason: "BLOCKED",
          error_code: "BLOCKED",
        };
      }
      return { address, allowed: true, status: "queued" as const };
    });
    return { allowed: recipients.some((entry) => entry.allowed), recipients };
  }
}

/** The default HTTP configuration used by the tests. */
export function testConfig(overrides: Partial<HttpConfig> = {}): HttpConfig {
  return {
    host: "127.0.0.1",
    port: 0,
    body_limit_bytes: 1_048_576,
    request_timeout_ms: 30_000,
    idempotency_ttl_hours: 24,
    metrics_public: true,
    readiness_public: true,
    trust_proxy: false,
    cors_allow_origins: [],
    rate_limit_per_minute: 1000,
    max_body_bytes: 1_048_576,
    max_attachment_bytes: 10_485_760,
    max_recipients_per_message: 50,
    cursor_secret: "fixture-cursor-secret",
    webhook_secret: FIXTURE_SECRETS.webhookSecret,
    ...overrides,
  };
}

export interface Harness {
  server: RailGunHttpServer;
  service: HttpService;
  baseUrl: string;
  clock: FixedClock;
  ids: SequentialIds;
  messages: MemoryMessageStore;
  bounces: MemoryBounceStore;
  suppressions: MemorySuppressionStore;
  idempotency: MemoryIdempotencyStore;
  queue: MemoryOutboxQueue;
  audit: MemoryAuditLog;
  credentials: MemoryCredentialStore;
  policy: TestPolicyEngine;
  domains: TestDomainRegistry;
  mx: FakeMxSink;
  close(): Promise<void>;
}

/** Boot the HTTP service on a random free port. */
export async function startHarness(
  configOverrides: Partial<HttpConfig> = {},
): Promise<Harness> {
  const clock = new FixedClock();
  const ids = new SequentialIds();
  const messages = new MemoryMessageStore();
  const bounces = new MemoryBounceStore();
  const suppressions = new MemorySuppressionStore();
  const idempotency = new MemoryIdempotencyStore();
  const queue = new MemoryOutboxQueue();
  const audit = new MemoryAuditLog();
  const credentials = new MemoryCredentialStore();
  const policy = new TestPolicyEngine();
  const domains = new TestDomainRegistry();
  const mx = new FakeMxSink();

  credentials.add(
    apiKeyRecord("key_tenant_a", "tenant_a", FIXTURE_SECRETS.apiKeyTenantA, ["send", "read"]),
  );
  credentials.add(
    apiKeyRecord("key_tenant_b", "tenant_b", FIXTURE_SECRETS.apiKeyTenantB, ["send", "read"]),
  );
  credentials.add(
    apiKeyRecord("key_read_only", "tenant_a", FIXTURE_SECRETS.apiKeyReadOnly, ["read"]),
  );
  credentials.add(
    apiKeyRecord("key_admin_only", "tenant_a", FIXTURE_SECRETS.apiKeyAdminOnly, ["admin"]),
  );
  credentials.add(
    apiKeyRecord("key_body_reader", "tenant_a", "rgk_bodyreader_eeeeeeeeeeeeeeeeeeeeeee", [
      "read",
      "body:read",
    ]),
  );
  credentials.add(
    apiKeyRecord(
      "key_revoked",
      "tenant_a",
      "rgk_revoked_fffffffffffffffffffffffffff",
      ["send", "read"],
      { active: false },
    ),
  );

  for (const tenant of ["tenant_a", "tenant_b"]) {
    domains.defaults.set(tenant, `sender@${tenant}.example.com`);
    domains.verified.add(`${tenant}:${tenant}.example.com`);
  }

  const config = testConfig(configOverrides);
  const service = new HttpService({
    config,
    clock,
    ids,
    messages,
    bounces,
    suppressions,
    idempotency,
    queue,
    audit,
    policy,
    domains,
    credentials,
    jwt: { secret: FIXTURE_SECRETS.jwtSecret, audience: "/railgun" },
    readiness: [
      {
        name: "database",
        check: async () => ({ status: "ok", detail: "ready" }),
      },
      {
        name: "queue",
        check: async () => ({ status: "ok", detail: `depth ${await queue.depth()}` }),
      },
    ],
    tenantSecret: (tenant_id) => `tenant-secret-${tenant_id}`,
  });

  const server = new RailGunHttpServer({ service });
  const address = (await server.listen(0, "127.0.0.1")) as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;

  return {
    server,
    service,
    baseUrl,
    clock,
    ids,
    messages,
    bounces,
    suppressions,
    idempotency,
    queue,
    audit,
    credentials,
    policy,
    domains,
    mx,
    close: () => server.close(),
  };
}

/** Result of a test HTTP call. */
export interface HttpResult {
  status: number;
  headers: Headers;
  body: unknown;
  raw: string;
}

/** Perform a JSON request against the harness. */
export async function request(
  harness: Harness,
  method: string,
  path: string,
  options: {
    body?: unknown;
    headers?: Record<string, string>;
    rawBody?: string;
  } = {},
): Promise<HttpResult> {
  const headers: Record<string, string> = { ...options.headers };
  let body: string | undefined;
  if (options.rawBody !== undefined) {
    body = options.rawBody;
    headers["content-type"] = headers["content-type"] ?? "application/json";
  } else if (options.body !== undefined) {
    body = JSON.stringify(options.body);
    headers["content-type"] = "application/json";
  }
  const response = await fetch(`${harness.baseUrl}${path}`, {
    method,
    headers,
    body,
  });
  const raw = await response.text();
  let parsed: unknown = null;
  if (raw.length > 0) {
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = raw;
    }
  }
  return { status: response.status, headers: response.headers, body: parsed, raw };
}

/** Build an HS256 JWT for the fixture secret. */
export function makeJwt(
  claims: Record<string, unknown>,
  secret = FIXTURE_SECRETS.jwtSecret,
): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  const header = encode({ alg: "HS256", typ: "JWT" });
  const payload = encode(claims);
  const signature = createHmac("sha256", secret)
    .update(`${header}.${payload}`)
    .digest("base64url");
  return `${header}.${payload}.${signature}`;
}

/** A valid tenant-A JWT. */
export function tenantAJwt(overrides: Record<string, unknown> = {}): string {
  return makeJwt({
    sub: "operator-1",
    tenant_id: "tenant_a",
    aud: "/railgun",
    scopes: ["send", "read"],
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...overrides,
  });
}

/** A principal snapshot for assertions. */
export function principalOf(tenant_id: string, scopes: string[]): Principal {
  return {
    id: `key_${tenant_id}`,
    tenant_id,
    kind: "api_key",
    scopes: scopes as Principal["scopes"],
    roles: [],
    allowed_senders: [`${tenant_id}.example.com`],
    allowed_domains: [`${tenant_id}.example.com`],
    active: true,
  };
}
