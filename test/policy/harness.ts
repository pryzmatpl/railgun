// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The shared harness for the policy engine tests.
//
// The policy suites are split across several files for readability; this
// module holds the fixtures they share.

import { generateKeyPairSync } from "node:crypto";

import type { Principal } from "../../src/domain/policy.js";
import { DEFAULT_POLICY_CONFIG, type PolicyConfig } from "../../src/spam/config.js";
import { PolicyEngine, toRecipient } from "../../src/spam/engine.js";
import {
  MemoryBlocklistStore,
  MemoryDuplicateContentStore,
  MemoryDkimKeyStore,
  MemoryRateLimitStore,
  MemoryReputationStore,
  MemorySendingDomainStore,
  MemorySuppressionStore,
  MemoryVerifiedRecipientStore,
  MemoryWarmupStore,
  RecordingAuditSink,
  StaticDkimKeyLoader,
  StaticDnsResolver,
  TestClock,
  sendingDomainRecord,
} from "./fakes.js";

export const RSA = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

/** A principal with the default allowlist scope. */
export function principal(overrides: Partial<Principal> = {}): Principal {
  return {
    principal_id: "key-1",
    tenant_id: "tenant-1",
    auth_method: "api_key",
    roles: ["sender"],
    sending_domains: ["example.com"],
    recipient_scope: "allowlist",
    recipient_allowlist: ["example.org"],
    allowlist_includes_subdomains: false,
    ...overrides,
  };
}

/** The assembled harness. */
export interface Harness {
  engine: PolicyEngine;
  clock: TestClock;
  audit: RecordingAuditSink;
  suppression: MemorySuppressionStore;
  blocklist: MemoryBlocklistStore;
  rateLimits: MemoryRateLimitStore;
  verified: MemoryVerifiedRecipientStore;
  warmup: MemoryWarmupStore;
  dkimKeys: MemoryDkimKeyStore;
  domains: MemorySendingDomainStore;
}

/** Builds a policy engine with in-memory stores. */
export function harness(
  overrides: {
    config?: Partial<PolicyConfig>;
    dns?: StaticDnsResolver;
    principal?: Principal;
    warmupPolicy?: Partial<PolicyConfig["warmup"]>;
  } = {},
): Harness {
  const clock = new TestClock();
  const audit = new RecordingAuditSink();
  const suppression = new MemorySuppressionStore();
  const blocklist = new MemoryBlocklistStore();
  const rateLimits = new MemoryRateLimitStore();
  const verified = new MemoryVerifiedRecipientStore();
  const warmup = new MemoryWarmupStore();
  const reputation = new MemoryReputationStore();
  const duplicates = new MemoryDuplicateContentStore();
  const dkimKeys = new MemoryDkimKeyStore();
  const domains = new MemorySendingDomainStore();
  const dns = overrides.dns ?? new StaticDnsResolver();

  dkimKeys.keys.push({
    domain: "example.com",
    selector: "railgun1",
    algorithm: "rsa-sha256",
    public_key_pem: RSA.publicKey,
    secret_ref: "file:///keys/railgun1.pem",
    status: "active",
    created_at: "2020-01-01T00:00:00.000Z",
    not_after: null,
  });
  void domains.save(sendingDomainRecord({ domain: "example.com" }));

  const config: PolicyConfig = {
    ...DEFAULT_POLICY_CONFIG,
    ...overrides.config,
    warmup: { ...DEFAULT_POLICY_CONFIG.warmup, ...overrides.warmupPolicy },
  };

  const engine = new PolicyEngine({
    clock,
    config,
    suppression,
    blocklist,
    rateLimits,
    verifiedRecipients: verified,
    warmup,
    reputation,
    duplicates,
    dkimKeys,
    dkimKeyLoader: new StaticDkimKeyLoader(RSA.privateKey),
    sendingDomains: domains,
    dns,
    audit,
    tenant_secret: "tenant-secret",
  });

  return {
    engine,
    clock,
    audit,
    suppression,
    blocklist,
    rateLimits,
    verified,
    warmup,
    dkimKeys,
    domains,
  };
}

/** Builds a submission request for the engine. */
export function request(
  p: Principal,
  recipients: string[],
  overrides: {
    sender?: string;
    subject?: string;
    text?: string;
    html?: string;
    request_id?: string;
    correlation_id?: string;
    attachments?: string[];
  } = {},
): Parameters<PolicyEngine["authorizeSubmission"]>[0] {
  return {
    principal: p,
    envelope: {
      sender: overrides.sender ?? "alice@example.com",
      recipients: recipients
        .map((r) => toRecipient(r))
        .filter((r): r is NonNullable<typeof r> => r !== null),
    },
    message: {
      headers: {
        from: "Alice <alice@example.com>",
        to: recipients.join(", "),
        subject: overrides.subject ?? "Hello",
        date: "Tue, 18 Nov 2026 11:00:00 +0000",
        "message-id": "<abc@example.com>",
      },
      text_body: overrides.text ?? "A normal message body with a couple of words.",
      html_body: overrides.html ?? "",
      attachment_names: overrides.attachments ?? [],
    },
    request_id: overrides.request_id ?? "req-1",
    size_bytes: 512,
    correlation_id: overrides.correlation_id ?? "corr-1",
  };
}
