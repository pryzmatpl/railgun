// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The outbound delivery engine's value contracts and ports.
 *
 * Contract: `docs/design/railgun-direct-mx-delivery-engine-ir.md` (unit D).
 *
 * This module is pure — it declares the seams (IR §7) and the value types the
 * engine exchanges with them. Every runtime import in the package's outbound
 * subsystem is a Node built-in; no third-party SMTP client is used.
 */

import type {
  BounceRecord,
  DeliveryAttempt,
  EnvelopeRecipient,
  Message,
} from "../domain/persistence/types.js";
import type { Clock, IdGenerator } from "../domain/persistence/ports.js";

/* -------------------------------------------------------------------------- */
/* Outcomes                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * The outcome of one delivery attempt against one envelope recipient.
 *
 * `accepted` means the remote MTA returned a final `250` for `DATA` — that is
 * acceptance, not proof of mailbox delivery (R-CLS-6). Only a DSN can move a
 * recipient to `delivered`.
 */
export type DeliveryOutcome =
  | "accepted"
  | "deferred"
  | "bounced"
  | "failed";

/**
 * The canonical error codes the engine emits.
 *
 * The table mirrors IR R-CLS-4. Every code maps to exactly one outcome so a
 * caller can branch on the code without re-deriving it from the SMTP code.
 */
export const DELIVERY_ERROR_CODES = Object.freeze([
  "temporary_failure",
  "mailbox_unavailable",
  "user_not_local",
  "policy_refused",
  "message_too_large",
  "network_transient",
  "timeout",
  "dns_temporary",
  "dns_no_mx",
  "reverse_dns_mismatch",
  "tls_unavailable",
  "tls_certificate_invalid",
  "tls_handshake_transient",
  "auth_insecure_channel",
  "auth_failed",
  "delivery_loop",
  "store_unavailable",
  "protocol_error",
  "relay_refused",
  "attempt_exhausted",
] as const);

export type DeliveryErrorCode = (typeof DELIVERY_ERROR_CODES)[number];

/* -------------------------------------------------------------------------- */
/* DNS                                                                         */
/* -------------------------------------------------------------------------- */

/** One MX record. */
export interface MxRecord {
  /** The exchange hostname. */
  readonly exchange: string;
  /** The MX preference; lower is preferred. */
  readonly preference: number;
}

/**
 * The resolver seam (IR §7).
 *
 * The engine accepts an implementation of this port so tests can supply a
 * deterministic fake instead of patching globals (R-DNS-9).
 */
export interface DnsResolver {
  /** Resolve the MX records of a routing domain. */
  resolveMx(domain: string): Promise<readonly MxRecord[]>;
  /** Resolve the IPv4 addresses of a host. */
  resolve4(host: string): Promise<readonly string[]>;
  /** Resolve the IPv6 addresses of a host. */
  resolve6(host: string): Promise<readonly string[]>;
  /** Resolve the PTR names of an address. */
  resolvePtr(address: string): Promise<readonly string[]>;
}

/**
 * The TTL-bounded cache over a {@link DnsResolver} (R-DNS-8).
 *
 * The cache is exposed as a seam so an operator can flush it and so the engine
 * can invalidate an entry when a cached host stops resolving (R-DNS-8).
 */
export interface DnsCache {
  /** The resolver the cache reads through to. */
  readonly resolver: DnsResolver;
  /** Drop every cached entry. */
  flush(): void;
  /** Drop the cached entries for one host. */
  invalidate(host: string): void;
  /** The cached TTL of an entry, or `null` when the entry is absent or stale. */
  ttlOf(host: string): number | null;
}

/* -------------------------------------------------------------------------- */
/* Transport                                                                   */
/* -------------------------------------------------------------------------- */

/** The TLS posture of a session (R-TLS-7). */
export type TlsMode = "none" | "starttls" | "implicit" | "failed";

/** One SMTP reply: the numeric code, the text and the enhanced status code. */
export interface SmtpResponse {
  /** The three-digit reply code. */
  readonly code: number;
  /** The reply text with the code prefixes removed. */
  readonly text: string;
  /** The enhanced status code, when the peer supplied one. */
  readonly enhancedCode: string | null;
  /** The raw reply, sanitized and bounded. */
  readonly raw: string;
}

/** The capabilities advertised by the peer in its EHLO response. */
export interface SmtpCapabilities {
  /** The advertised ESMTP keywords, upper-cased. */
  readonly keywords: readonly string[];
  /** The advertised maximum message size, in bytes. */
  readonly maxMessageBytes: number | null;
  /** True when the peer advertised `PIPELINING`. */
  readonly pipelining: boolean;
  /** True when the peer advertised `STARTTLS`. */
  readonly starttls: boolean;
  /** True when the peer advertised `8BITMIME`. */
  readonly eightBitMime: boolean;
  /** True when the peer advertised `AUTH` with a mechanism list. */
  readonly authMechanisms: readonly string[];
}

/** The TLS facts recorded on an attempt (R-TLS-7, R-FIN-3). */
export interface TlsFacts {
  readonly mode: TlsMode;
  readonly protocol: string | null;
  readonly cipher: string | null;
  /** The SHA-256 digest of the DER leaf certificate. */
  readonly certFingerprint: string | null;
}

/** The transport seam (IR §7): one connection and one dialogue. */
export interface SmtpTransport {
  /** Open the connection. */
  connect(): Promise<void>;
  /** Send one command and read its reply. */
  command(verb: string, args?: string): Promise<SmtpResponse>;
  /** Send the message body and read the final reply. */
  data(body: Uint8Array): Promise<SmtpResponse>;
  /** Close the session politely. */
  quit(): Promise<void>;
  /** Tear the session down without a `QUIT`. */
  destroy(): void;
  /** The capabilities the peer advertised, once `EHLO` has been sent. */
  readonly capabilities: SmtpCapabilities | null;
  /** The TLS facts of the session, once the handshake has completed. */
  readonly tls: TlsFacts | null;
}

/* -------------------------------------------------------------------------- */
/* Events and audit                                                            */
/* -------------------------------------------------------------------------- */

/** The exact observability event names (R-OBS-2). */
export const DELIVERY_EVENT_NAMES = Object.freeze([
  "delivery_attempt_started",
  "delivery_tls_negotiated",
  "delivery_tls_failed",
  "delivery_smtp_response",
  "delivery_delivered",
  "delivery_deferred",
  "delivery_bounced",
  "delivery_loop_rejected",
  "delivery_finalized",
] as const);

export type DeliveryEventName = (typeof DELIVERY_EVENT_NAMES)[number];

/** One structured observability event (R-OBS-1). */
export interface DeliveryEvent {
  readonly event: DeliveryEventName;
  readonly ts: string;
  readonly messageId: string;
  readonly requestId: string;
  /** The recipient, hashed or redacted per the audit policy. */
  readonly recipient: string;
  readonly domain: string;
  readonly mode: "direct" | "relay";
  readonly mxHost: string | null;
  readonly remoteIp: string | null;
  readonly remotePort: number | null;
  readonly tlsMode: TlsMode;
  readonly tlsProtocol: string | null;
  readonly tlsCipher: string | null;
  readonly certFingerprint: string | null;
  readonly smtpCode: number | null;
  /** The sanitized, bounded peer response. */
  readonly smtpResponse: string | null;
  readonly enhancedCode: string | null;
  readonly errorCode: DeliveryErrorCode | null;
  readonly deliveryState: DeliveryOutcome | null;
  readonly attempt: number;
  readonly durationMs: number;
}

/** The structured-event sink (IR §7). */
export interface EventSink {
  emit(event: DeliveryEvent): void;
}

/** The append-only, hash-chained audit sink (IR §7, R-OBS-3). */
export interface AuditSink {
  /**
   * Append one decision record.
   *
   * The record must be durable before the decision is reported to the caller.
   */
  append(input: {
    readonly action: string;
    readonly subjectId: string;
    readonly outcome: string;
    readonly reasonCode: string | null;
    readonly metadata: Readonly<Record<string, unknown>>;
  }): Promise<void>;
}

/* -------------------------------------------------------------------------- */
/* Sinks                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * The bounce sink (IR §7).
 *
 * The engine requests the bounce and the suppression; the *policy* that
 * decides whether a suppression is created belongs to the anti-spam layer, so
 * the sink returns the suppression id it created (R-FIN-6).
 */
export interface BounceSink {
  /** Create a bounce record and request a suppression for the recipient. */
  record(input: {
    readonly tenantId: string;
    readonly messageId: string | null;
    readonly envelopeId: string | null;
    readonly recipient: string;
    readonly smtpCode: number | null;
    readonly dsnCode: string | null;
    readonly dsnClass: string | null;
    readonly bounceClass: "hard" | "soft" | "complaint";
    readonly diagnostic: string | null;
    readonly remoteId: string | null;
  }): Promise<{ bounce: BounceRecord; suppressionId: string | null }>;
}

/**
 * The durable attempt store (IR §7).
 *
 * The store owns the attempt start/complete writes, the outbox claim and
 * release, and the recipient state transitions.
 */
export interface DeliveryAttemptStore {
  /** Claim the outbox item for one envelope recipient. */
  claim(input: {
    readonly tenantId: string;
    readonly owner: string;
    readonly limit: number;
  }): Promise<readonly OutboxLease[]>;
  /** Record the start of an attempt (R-FIN-1). */
  startAttempt(attempt: DeliveryAttempt): Promise<void>;
  /** Record the outcome of an attempt (R-FIN-1). */
  completeAttempt(attempt: DeliveryAttempt): Promise<void>;
  /** Read the current envelope recipient record. */
  envelope(envelopeId: string): Promise<EnvelopeRecipient | null>;
  /** Read the message the envelope belongs to. */
  message(messageId: string): Promise<Message | null>;
  /**
   * Apply the terminal or deferred outcome to the recipient and the queue in
   * one durable transaction (R-FIN-2).
   */
  finalize(input: {
    readonly itemId: string;
    readonly owner: string;
    readonly envelopeId: string;
    readonly status: EnvelopeRecipient["status"];
    readonly smtpCode: number | null;
    readonly response: string | null;
    readonly errorCode: string | null;
    readonly nextAttemptAt: string | null;
    readonly messageStatus: Message["status"];
  }): Promise<void>;
}

/** An outbox item claimed by a worker. */
export interface OutboxLease {
  readonly id: string;
  readonly messageId: string;
  readonly envelopeId: string;
  readonly tenantId: string;
  readonly attemptCount: number;
  readonly maxAttempts: number;
}

/* -------------------------------------------------------------------------- */
/* The delivery request                                                        */
/* -------------------------------------------------------------------------- */

/** The artifact handed to the engine for one envelope recipient. */
export interface DeliveryRequest {
  readonly messageId: string;
  readonly requestId: string;
  readonly tenantId: string;
  readonly envelopeId: string;
  readonly recipient: string;
  readonly envelopeSender: string;
  /** The normalized artifact; transmitted byte-identically (R-SMTP-6). */
  readonly artifact: Uint8Array;
  /** The recipient's routing domain. */
  readonly domain: string;
  /** The attempt number, starting at 1. */
  readonly attempt: number;
  /** The hop limit for the loop marker (R-LOOP-2). */
  readonly loopLimit: number;
}

/** The result of one delivery attempt. */
export interface DeliveryResult {
  readonly messageId: string;
  readonly envelopeId: string;
  readonly recipient: string;
  readonly outcome: DeliveryOutcome;
  readonly errorCode: DeliveryErrorCode | null;
  readonly smtpCode: number | null;
  readonly smtpResponse: string | null;
  readonly enhancedCode: string | null;
  readonly mxHost: string | null;
  readonly remoteIp: string | null;
  readonly remotePort: number | null;
  readonly tls: TlsFacts | null;
  readonly attempt: number;
  readonly durationMs: number;
  /** True when the attempt reached a remote MTA and it accepted the message. */
  readonly remoteAccepted: boolean;
}

/* -------------------------------------------------------------------------- */
/* The engine's own dependencies                                                */
/* -------------------------------------------------------------------------- */

/** The clock and id source, injected so backoff and ids stay testable. */
export interface DeliveryRuntime {
  readonly clock: Clock;
  readonly ids: IdGenerator;
}
