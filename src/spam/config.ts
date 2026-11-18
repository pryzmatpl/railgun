// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The policy configuration consumed by the engine.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §13 and
// packages/railgun/config/railgun.example.yaml.
//
// Pure module — no runtime imports (IR R-4.1).

import {DEFAULT_ROLE_ADDRESSES, type AlignmentMode, type DkimAlgorithm, type DnsFailurePolicy, type RemoteFailPolicy, type RoleAddressMode, type WarmupPolicy} from "../domain/identity.js";
import type { RecipientScope } from "../domain/policy.js";

/** Identity and DNS posture configuration (IR §13.1). */
export interface IdentityConfig {
  /** Deny sending when the sending domain publishes no SPF record. */
  readonly require_spf_record: boolean;
  /** Downgrade a DMARC mismatch to a warning instead of a deny. */
  readonly require_dmarc_aligned: boolean;
  /** `strict` (exact match) or `relaxed` (organizational domain). */
  readonly alignment_mode: AlignmentMode;
  readonly dns_timeout_ms: number;
  readonly dns_failure_policy: DnsFailurePolicy;
  readonly authorized_subdomains: readonly string[];
}

/** DKIM signer configuration (IR §13.1). */
export interface SignerConfig {
  readonly default_algorithm: DkimAlgorithm;
  /** MUST NOT be below 2048 (IR R-13.1.2). */
  readonly rsa_min_bits: number;
  readonly header_canonicalization: "relaxed" | "simple";
  readonly body_canonicalization: "relaxed" | "simple";
  readonly sign_headers: readonly string[];
  readonly key_dir: string | null;
}

/** The remote blocklist configuration (IR §10.2.2). */
export interface BlocklistConfig {
  readonly local: readonly string[];
  readonly remote: readonly { name: string; zone: string }[];
  readonly remote_fail_policy: RemoteFailPolicy;
  readonly cache_ttl_seconds: number;
}

/** Spam-scoring and content configuration (IR §11, §13.1). */
export interface SpamConfig {
  /** Below this score a message is allowed (subject to all other gates). */
  readonly allow_threshold: number;
  /** At or above this score a message is denied. */
  readonly deny_threshold: number;
  /** What happens in the review band. */
  readonly on_threshold: "accept" | "tag" | "quarantine" | "reject";
  readonly quarantine: boolean;
  readonly disarm_active_content: boolean;
  readonly strip_tracking_pixels: boolean;
  readonly blocklist: BlocklistConfig;
  readonly protect_role_addresses: boolean;
  readonly role_addresses: {
    readonly mode: RoleAddressMode;
    readonly list: readonly string[];
    readonly trap_recipients: readonly string[];
  };
  readonly duplicate_window_seconds: number;
  /** The version of the deterministic scoring model (IR R-11.1.1). */
  readonly model_version: string;
  /** Brands protected against lookalike domains. */
  readonly protected_brands: readonly string[];
}

/** Rate-limit and quota configuration (IR §9.1, §9.2). */
export interface RateLimitConfig {
  readonly messages_per_minute: number;
  readonly messages_per_hour: number;
  readonly messages_per_day: number;
  readonly recipients_per_message: number;
  readonly bytes_per_day: number;
  readonly concurrent_in_flight: number;
  readonly new_recipients_per_hour: number;
  readonly require_recipient_confirmation: boolean;
  /** Per-recipient hourly ceiling. */
  readonly recipient_messages_per_hour: number;
  /** Per-principal daily ceiling. */
  readonly principal_messages_per_day: number;
  /** Per-domain daily ceiling. */
  readonly domain_messages_per_day: number;
  /** SMTP command rate per minute. */
  readonly max_command_rate_per_minute: number;
}

/** Relay authorization configuration (IR §8.1, §13.1). */
export interface RelayConfig {
  readonly default_scope: RecipientScope;
  readonly allowlist: readonly string[];
  readonly allowlist_includes_subdomains: boolean;
}

/** Audit configuration (IR §14.1). */
export interface AuditConfig {
  readonly enabled: boolean;
  readonly hash_recipients: boolean;
  readonly write_failure_mode: "warn" | "strict";
  readonly salt_env: string;
}

/** The complete policy configuration. */
export interface PolicyConfig {
  readonly identity: IdentityConfig;
  readonly signer: SignerConfig;
  readonly spam: SpamConfig;
  readonly warmup: WarmupPolicy;
  readonly relay: RelayConfig;
  readonly rate_limit: RateLimitConfig;
  readonly audit: AuditConfig;
  /** The version stamped onto every decision record (IR R-5.2). */
  readonly policy_version: string;
}

/**
 * The shipped defaults. Every abuse-sensitive limit has a finite value — an
 * unset limit MUST NOT mean unlimited (IR R-9.1.3).
 */
export const DEFAULT_POLICY_CONFIG: PolicyConfig = Object.freeze({
  identity: Object.freeze({
    require_spf_record: false,
    require_dmarc_aligned: true,
    alignment_mode: "strict" as AlignmentMode,
    dns_timeout_ms: 3000,
    dns_failure_policy: "fail_open" as DnsFailurePolicy,
    authorized_subdomains: Object.freeze([]) as readonly string[],
  }),
  signer: Object.freeze({
    default_algorithm: "rsa-sha256" as DkimAlgorithm,
    rsa_min_bits: 2048,
    header_canonicalization: "relaxed" as const,
    body_canonicalization: "relaxed" as const,
    sign_headers: Object.freeze([
      "from",
      "to",
      "subject",
      "date",
      "message-id",
      "reply-to",
    ]),
    key_dir: null,
  }),
  spam: Object.freeze({
    allow_threshold: 0.35,
    deny_threshold: 0.7,
    on_threshold: "reject" as const,
    quarantine: true,
    disarm_active_content: true,
    strip_tracking_pixels: true,
    blocklist: Object.freeze({
      local: Object.freeze([]) as readonly string[],
      remote: Object.freeze([]) as readonly { name: string; zone: string }[],
      remote_fail_policy: "fail_open" as RemoteFailPolicy,
      cache_ttl_seconds: 3600,
    }),
    protect_role_addresses: true,
    role_addresses: Object.freeze({
      mode: "require_verified" as RoleAddressMode,
      list: DEFAULT_ROLE_ADDRESSES,
      trap_recipients: Object.freeze([]) as readonly string[],
    }),
    duplicate_window_seconds: 3600,
    model_version: "railgun-spam-1",
    protected_brands: Object.freeze([]) as readonly string[],
  }),
  warmup: Object.freeze({
    warmup_days: 30,
    ramp_multiplier: 1.5,
    warmup_daily_cap: 50,
    warmup_recipient_cap: 25,
    verified_only: true,
  }),
  relay: Object.freeze({
    default_scope: "none" as RecipientScope,
    allowlist: Object.freeze([]) as readonly string[],
    allowlist_includes_subdomains: false,
  }),
  rate_limit: Object.freeze({
    messages_per_minute: 60,
    messages_per_hour: 1000,
    messages_per_day: 10_000,
    recipients_per_message: 50,
    bytes_per_day: 268_435_456,
    concurrent_in_flight: 20,
    new_recipients_per_hour: 25,
    require_recipient_confirmation: false,
    recipient_messages_per_hour: 600,
    principal_messages_per_day: 10_000,
    domain_messages_per_day: 10_000,
    max_command_rate_per_minute: 600,
  }),
  audit: Object.freeze({
    enabled: true,
    hash_recipients: true,
    write_failure_mode: "warn" as const,
    salt_env: "RAILGUN_AUDIT_SALT",
  }),
  policy_version: "railgun-policy-1",
});

/** One configuration problem, naming the setting but never its value. */
export interface ConfigProblem {
  /** The dotted setting name, e.g. `spam.allow_threshold`. */
  readonly setting: string;
  readonly code: "CONFIG_INVALID" | "CONFIG_UNKNOWN";
  readonly message: string;
}

/**
 * Validates the policy configuration (IR R-13.1.2, R-13.1.3).
 *
 * An invalid or internally inconsistent configuration MUST prevent readiness
 * rather than silently disabling a control. Problems name the **setting**,
 * never its value.
 */
export function validatePolicyConfig(config: PolicyConfig): ConfigProblem[] {
  const problems: ConfigProblem[] = [];
  const fail = (setting: string, message: string): void => {
    problems.push({ setting, code: "CONFIG_INVALID", message });
  };

  if (config.spam.allow_threshold >= config.spam.deny_threshold) {
    fail("spam.allow_threshold", "allow_threshold must be below deny_threshold");
  }
  if (config.spam.allow_threshold < 0 || config.spam.deny_threshold > 1) {
    fail("spam.allow_threshold", "thresholds must lie within [0, 1]");
  }
  if (config.signer.rsa_min_bits < 2048) {
    fail("signer.rsa_min_bits", "rsa_min_bits must be at least 2048");
  }
  if (
    config.signer.default_algorithm !== "rsa-sha256" &&
    config.signer.default_algorithm !== "ed25519"
  ) {
    fail("signer.default_algorithm", "unknown DKIM algorithm");
  }
  if (
    config.signer.header_canonicalization !== "relaxed" &&
    config.signer.header_canonicalization !== "simple"
  ) {
    fail("signer.header_canonicalization", "unknown header canonicalization");
  }
  if (
    config.signer.body_canonicalization !== "relaxed" &&
    config.signer.body_canonicalization !== "simple"
  ) {
    fail("signer.body_canonicalization", "unknown body canonicalization");
  }
  if (config.identity.alignment_mode !== "strict" && config.identity.alignment_mode !== "relaxed") {
    fail("identity.alignment_mode", "unknown alignment mode");
  }
  if (
    config.identity.dns_failure_policy !== "fail_open" &&
    config.identity.dns_failure_policy !== "fail_closed"
  ) {
    fail("identity.dns_failure_policy", "unknown DNS failure policy");
  }
  if (
    config.spam.role_addresses.mode !== "allow" &&
    config.spam.role_addresses.mode !== "throttle" &&
    config.spam.role_addresses.mode !== "deny" &&
    config.spam.role_addresses.mode !== "require_verified"
  ) {
    fail("spam.role_addresses.mode", "unknown role-address protection mode");
  }
  if (
    config.spam.blocklist.remote_fail_policy !== "fail_open" &&
    config.spam.blocklist.remote_fail_policy !== "fail_closed"
  ) {
    fail("spam.blocklist.remote_fail_policy", "unknown remote blocklist fail policy");
  }
  if (
    config.relay.default_scope !== "none" &&
    config.relay.default_scope !== "allowlist" &&
    config.relay.default_scope !== "same_domain_only" &&
    config.relay.default_scope !== "verified_recipients_only" &&
    config.relay.default_scope !== "all"
  ) {
    fail("relay.default_scope", "unknown recipient scope");
  }
  if (config.warmup.warmup_days <= 0) {
    fail("warmup.warmup_days", "warmup_days must be positive");
  }
  if (config.warmup.ramp_multiplier < 1) {
    fail("warmup.ramp_multiplier", "ramp_multiplier must be at least 1");
  }
  if (config.warmup.warmup_daily_cap <= 0) {
    fail("warmup.warmup_daily_cap", "warmup_daily_cap must be positive");
  }
  if (config.warmup.warmup_recipient_cap <= 0) {
    fail("warmup.warmup_recipient_cap", "warmup_recipient_cap must be positive");
  }
  if (config.audit.write_failure_mode !== "warn" && config.audit.write_failure_mode !== "strict") {
    fail("audit.write_failure_mode", "unknown audit write failure mode");
  }
  // An unset abuse-sensitive limit must never mean unlimited (IR R-9.1.3).
  const unlimited: readonly [string, number][] = [
    ["rate_limit.messages_per_minute", config.rate_limit.messages_per_minute],
    ["rate_limit.messages_per_hour", config.rate_limit.messages_per_hour],
    ["rate_limit.messages_per_day", config.rate_limit.messages_per_day],
    ["rate_limit.recipients_per_message", config.rate_limit.recipients_per_message],
    ["rate_limit.bytes_per_day", config.rate_limit.bytes_per_day],
    ["rate_limit.new_recipients_per_hour", config.rate_limit.new_recipients_per_hour],
    ["rate_limit.recipient_messages_per_hour", config.rate_limit.recipient_messages_per_hour],
    ["rate_limit.principal_messages_per_day", config.rate_limit.principal_messages_per_day],
    ["rate_limit.domain_messages_per_day", config.rate_limit.domain_messages_per_day],
  ];
  for (const [setting, value] of unlimited) {
    if (!Number.isFinite(value) || value <= 0) {
      fail(setting, "an abuse-sensitive limit must be a positive finite number");
    }
  }
  return problems;
}
