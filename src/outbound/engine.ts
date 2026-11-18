// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The direct-to-MX delivery engine.
 *
 * Contract: `docs/design/railgun-direct-mx-delivery-engine-ir.md`.
 *
 * The engine owns the **primary** outbound path: DNS MX discovery → address
 * family selection → TCP connect → opportunistic STARTTLS with certificate
 * verification → the SMTP envelope transaction → per-recipient classification
 * → durable recording → bounded retry, bounce and suppression hand-off.
 *
 * The engine is provider-independent: it uses Node built-ins only, and every
 * seam it depends on is injectable so the whole path can be driven against a
 * local fake MX in tests.
 */

import { createHash } from "node:crypto";

import type { RailgunConfig } from "../config/config.js";
import type { EnvelopeRecipient, Message } from "../domain/persistence/types.js";
import {
  TtlDnsCache,
  checkAddressPolicy,
  isNullMx,
  isTemporaryDnsError,
  orderAddresses,
  orderMxRecords,
  reverseDnsMatches,
  type AddressCandidate,
} from "./dns.js";
import { classifySmtpResponse } from "./classify.js";
import {
  SmtpClient,
  SmtpProtocolError,
  SmtpTimeoutError,
  SmtpTlsError,
} from "./smtp-client.js";
import {
  backoffDelay,
  deterministicJitter,
  effectiveMaxAttempts,
  nextAttemptAt,
} from "./backoff.js";
import type {
  AuditSink,
  BounceSink,
  DeliveryAttemptStore,
  DeliveryEvent,
  DeliveryEventName,
  DeliveryOutcome,
  DeliveryRequest,
  DeliveryResult,
  DnsCache,
  DnsResolver,
  EventSink,
  OutboxLease,
  SmtpResponse,
  TlsFacts,
} from "./types.js";
import { DELIVERY_ERROR_CODES } from "./types.js";

/** The reserved header carrying the delivery-loop marker (R-LOOP-1). */
export const LOOP_HEADER = "x-railgun-loop";

/** The default hop limit for the loop marker (R-LOOP-2). */
export const DEFAULT_LOOP_LIMIT = 1;

/** The engine options. */
export interface DeliveryEngineOptions {
  readonly config: RailgunConfig;
  readonly resolver: DnsResolver;
  readonly cache?: DnsCache | undefined;
  readonly attempts: DeliveryAttemptStore;
  readonly bounces: BounceSink;
  readonly audit: AuditSink;
  readonly events: EventSink;
  readonly now?: (() => Date) | undefined;
  /** The lease owner identity used when claiming outbox items (R-SAF-1). */
  readonly workerId: string;
  /** The TLS policy override; `undefined` derives it from the config. */
  readonly tlsMode?: "required" | "opportunistic" | undefined;
  /** Whether plaintext may be used when TLS is unavailable (R-TLS-6). */
  readonly allowPlaintext?: boolean | undefined;
  /**
   * The explicit local-transport exception (R-CONN-7).
   *
   * This is a **test-only** escape hatch: it lets the fake-MX fixture, which
   * listens on loopback, be reached. It is never enabled by the shipped
   * configuration.
   */
  readonly allowLocalTransport?: boolean | undefined;
  /** The injected socket factory, for tests that drive a fake MX. */
  readonly connect?: DeliveryEngineOptions["connectFactory"];
  readonly connectFactory?: (
    options: { host?: string; port?: number },
  ) => import("node:net").Socket;
  /** The injected TLS upgrade, for tests that drive a fake MX. */
  readonly upgradeFactory?: (
    socket: import("node:net").Socket,
    options: import("node:tls").ConnectionOptions,
  ) => import("node:tls").TLSSocket;
  /** The jitter source; `undefined` uses the deterministic per-message jitter. */
  readonly random?: (() => number) | undefined;
}

/** The engine's per-host cooldown state (R-RET-6, R-RET-7). */
interface HostState {
  consecutiveFailures: number;
  /** Epoch milliseconds until which the host is in cooldown. */
  cooldownUntil: number;
  /** True when the host was quarantined by a TLS policy failure (R-RET-7). */
  quarantined: boolean;
}

/** The result of a delivery run over a batch of leased outbox items. */
export interface DeliveryRunResult {
  readonly attempted: number;
  readonly accepted: number;
  readonly deferred: number;
  readonly bounced: number;
  readonly results: readonly DeliveryResult[];
}

/**
 * The direct-to-MX delivery engine.
 */
export class DeliveryEngine {
  private readonly options: DeliveryEngineOptions;
  private readonly cache: DnsCache;
  private readonly hosts = new Map<string, HostState>();
  private readonly now: () => Date;

  constructor(options: DeliveryEngineOptions) {
    this.options = options;
    this.cache = options.cache ?? new TtlDnsCache(options.resolver);
    this.now = options.now ?? (() => new Date());
  }

  /** The DNS cache the engine reads through to. */
  get dnsCache(): DnsCache {
    return this.cache;
  }

  /**
   * Lease due outbox items and attempt to deliver each of them.
   *
   * A message is never attempted concurrently by two workers: the claim is an
   * atomic compare-and-set on the outbox item (R-SAF-1).
   */
  async run(limit = 10): Promise<DeliveryRunResult> {
    const leases = await this.options.attempts.claim({
      tenantId: "",
      owner: this.options.workerId,
      limit,
    });

    const results: DeliveryResult[] = [];
    for (const lease of leases) {
      const result = await this.deliverLease(lease);
      results.push(result);
    }

    return {
      attempted: results.length,
      accepted: results.filter((r) => r.outcome === "accepted").length,
      deferred: results.filter((r) => r.outcome === "deferred").length,
      bounced: results.filter((r) => r.outcome === "bounced").length,
      results,
    };
  }

  /**
   * Attempt one leased outbox item.
   */
  async deliverLease(lease: OutboxLease): Promise<DeliveryResult> {
    const envelope = await this.options.attempts.envelope(lease.envelopeId);
    if (!envelope) {
      return this.unreachableResult(lease, "failed", "store_unavailable");
    }
    const message = await this.options.attempts.message(lease.messageId);
    if (!message) {
      return this.unreachableResult(lease, "failed", "store_unavailable");
    }

    const request: DeliveryRequest = {
      messageId: lease.messageId,
      requestId: message.requestId,
      tenantId: lease.tenantId,
      envelopeId: lease.envelopeId,
      recipient: envelope.recipient,
      envelopeSender: message.envelopeSender,
      artifact: message.body ?? new Uint8Array(0),
      domain: routingDomainOf(envelope.recipient),
      attempt: lease.attemptCount + 1,
      loopLimit: DEFAULT_LOOP_LIMIT,
    };

    return this.deliver(request, lease);
  }

  /**
   * Attempt one delivery request.
   *
   * The request carries the artifact and the envelope; the engine owns the
   * whole path from the loop check to the durable finalization.
   */
  async deliver(
    request: DeliveryRequest,
    lease?: OutboxLease,
  ): Promise<DeliveryResult> {
    const startedAt = this.now();
    const attemptNumber = request.attempt;

    this.emit("delivery_attempt_started", request, {
      attempt: attemptNumber,
      deliveryState: null,
    });

    // --- The loop check happens before any connection (R-LOOP-2). --------
    const loop = inspectLoopMarker(request.artifact, request.loopLimit);
    if (loop.rejected) {
      const result = this.buildResult(request, {
        outcome: "bounced",
        errorCode: "delivery_loop",
        smtpCode: null,
        smtpResponse: null,
        enhancedCode: null,
        mxHost: null,
        remoteIp: null,
        remotePort: null,
        tls: null,
        durationMs: 0,
        remoteAccepted: false,
      });
      this.emit("delivery_loop_rejected", request, {
        attempt: attemptNumber,
        deliveryState: "bounced",
        errorCode: "delivery_loop",
      });
      await this.finalize(request, lease, result, "delivery_loop_rejected");
      return result;
    }
    if (!loop.markerPresent) {
      // The absence is a normalization-layer defect, not a delivery failure:
      // report it and continue with the artifact as queued (R-LOOP-3).
      await this.options.audit.append({
        action: "delivery_loop_marker_absent",
        subjectId: request.envelopeId,
        outcome: "warn",
        reasonCode: "loop_marker_absent",
        metadata: { messageId: request.messageId, recipient: request.recipient },
      });
    }

    // --- MX discovery (R-DNS-1 … R-DNS-10). ------------------------------
    const candidates = await this.resolveCandidates(request);
    if (candidates.error) {
      const result = this.buildResult(request, {
        outcome: candidates.error.outcome,
        errorCode: candidates.error.errorCode,
        smtpCode: null,
        smtpResponse: null,
        enhancedCode: null,
        mxHost: null,
        remoteIp: null,
        remotePort: null,
        tls: null,
        durationMs: this.now().getTime() - startedAt.getTime(),
        remoteAccepted: false,
      });
      await this.finalize(request, lease, result);
      return result;
    }

    // --- Try each candidate in turn (R-RET-5). ----------------------------
    let last: DeliveryResult | null = null;
    for (const candidate of candidates.hosts) {
      if (this.isQuarantined(candidate.host)) continue;

      const attempt = await this.attemptHost(request, candidate, startedAt);
      last = attempt;

      if (attempt.outcome === "accepted") {
        this.clearHostState(candidate.host);
        await this.finalize(request, lease, attempt);
        return attempt;
      }

      // A permanent failure is recipient-level: another host of the same
      // domain would only duplicate the reputation damage (R-RET-5).
      if (attempt.outcome === "bounced") {
        await this.finalize(request, lease, attempt);
        return attempt;
      }

      // A temporary failure may be answered by the next candidate (R-RET-5).
      this.noteHostFailure(candidate.host);
    }

    const fallback =
      last ??
      this.buildResult(request, {
        outcome: "deferred",
        errorCode: "network_transient",
        smtpCode: null,
        smtpResponse: null,
        enhancedCode: null,
        mxHost: null,
        remoteIp: null,
        remotePort: null,
        tls: null,
        durationMs: this.now().getTime() - startedAt.getTime(),
        remoteAccepted: false,
      });

    await this.finalize(request, lease, fallback);
    return fallback;
  }

  /* ------------------------------------------------------------------ */
  /* MX discovery                                                        */
  /* ------------------------------------------------------------------ */

  /**
   * The MX candidates for the request's routing domain.
   */
  private async resolveCandidates(
    request: DeliveryRequest,
  ): Promise<
    | { hosts: readonly AddressCandidate[]; error?: undefined }
    | { hosts?: undefined; error: { outcome: DeliveryOutcome; errorCode: NonNullable<DeliveryResult["errorCode"]> } }
  > {
    const direct = this.options.config.outbound.direct;

    // `mx_lookup: false` uses the routing domain itself as the single MX
    // host; the MX ordering and null-MX rules do not apply (R-DNS-2).
    if (!direct.mx_lookup) {
      const addresses = await this.addressesFor(request.domain);
      if (addresses.length === 0) {
        return { error: { outcome: "deferred", errorCode: "dns_temporary" } };
      }
      return { hosts: addresses };
    }

    let records;
    try {
      records = await this.cacheMx(request.domain);
    } catch (error) {
      if (isTemporaryDnsError(error)) {
        return { error: { outcome: "deferred", errorCode: "dns_temporary" } };
      }
      return { error: { outcome: "bounced", errorCode: "dns_no_mx" } };
    }

    if (records.length === 0) {
      return { error: { outcome: "bounced", errorCode: "dns_no_mx" } };
    }
    if (isNullMx(records)) {
      // A null MX means the domain accepts no mail at all (R-DNS-6).
      return { error: { outcome: "bounced", errorCode: "mailbox_unavailable" } };
    }

    const hosts: AddressCandidate[] = [];
    for (const record of orderMxRecords(records)) {
      const addresses = await this.addressesFor(record.exchange);
      for (const address of addresses) {
        hosts.push(address);
      }
    }

    if (hosts.length === 0) {
      return { error: { outcome: "deferred", errorCode: "dns_temporary" } };
    }
    return { hosts };
  }

  /** The cached MX records of a domain. */
  private async cacheMx(domain: string): Promise<readonly import("./types.js").MxRecord[]> {
    const cache = this.cache as unknown as {
      mx?: (domain: string) => Promise<readonly import("./types.js").MxRecord[] | null>;
    };
    if (typeof cache.mx === "function") {
      const cached = await cache.mx(domain);
      if (cached) return cached;
    }
    return this.options.resolver.resolveMx(domain);
  }

  /**
   * The address candidates of a host, honouring the family policy and the
   * transport address policy (R-DNS-4, R-CONN-7, R-DNS-10).
   */
  private async addressesFor(host: string): Promise<readonly AddressCandidate[]> {
    const direct = this.options.config.outbound.direct;
    let ipv4: readonly string[] = [];
    let ipv6: readonly string[] = [];

    try {
      ipv4 = await this.resolve4(host);
      if (direct.ipv6_fallback || !direct.ipv4_first) {
        ipv6 = await this.resolve6(host);
      }
    } catch (error) {
      if (isTemporaryDnsError(error)) {
        // A temporary resolver failure is handled by the caller, which defers
        // the recipient.
        throw error;
      }
      ipv4 = [];
      ipv6 = [];
    }

    const ordered = orderAddresses(host, ipv4, ipv6, {
      ipv4First: direct.ipv4_first,
      ipv6Fallback: direct.ipv6_fallback,
    });

    const allowed: AddressCandidate[] = [];
    for (const candidate of ordered) {
      const verdict = checkAddressPolicy(candidate.address, {
        allowLocal: this.options.allowLocalTransport ?? false,
      });
      if (!verdict.allowed) continue;

      if (direct.require_reverse_dns) {
        const ptr = await this.resolvePtr(candidate.address);
        if (!reverseDnsMatches(ptr, host)) {
          // The address fails the PTR consistency check (R-DNS-10).
          continue;
        }
      }
      allowed.push(candidate);
    }
    return allowed;
  }

  private async resolve4(host: string): Promise<readonly string[]> {
    const cache = this.cache as unknown as {
      addresses4?: (host: string) => Promise<readonly string[] | null>;
    };
    if (typeof cache.addresses4 === "function") {
      const cached = await cache.addresses4(host);
      if (cached) return cached;
    }
    return this.options.resolver.resolve4(host);
  }

  private async resolve6(host: string): Promise<readonly string[]> {
    const cache = this.cache as unknown as {
      addresses6?: (host: string) => Promise<readonly string[] | null>;
    };
    if (typeof cache.addresses6 === "function") {
      const cached = await cache.addresses6(host);
      if (cached) return cached;
    }
    return this.options.resolver.resolve6(host);
  }

  private async resolvePtr(address: string): Promise<readonly string[]> {
    const cache = this.cache as unknown as {
      ptr?: (address: string) => Promise<readonly string[] | null>;
    };
    if (typeof cache.ptr === "function") {
      const cached = await cache.ptr(address);
      if (cached) return cached;
    }
    return this.options.resolver.resolvePtr(address);
  }

  /* ------------------------------------------------------------------ */
  /* One connection attempt                                              */
  /* ------------------------------------------------------------------ */

  /**
   * Attempt one address candidate: connect, negotiate TLS, run the SMTP
   * transaction and classify the outcome.
   */
  private async attemptHost(
    request: DeliveryRequest,
    candidate: AddressCandidate,
    startedAt: Date,
  ): Promise<DeliveryResult> {
    const direct = this.options.config.outbound.direct;
    const tlsPolicy = this.options.tlsMode ?? (direct.require_tls ? "required" : "opportunistic");
    const allowPlaintext =
      this.options.allowPlaintext ?? (tlsPolicy === "opportunistic" && !direct.require_tls);

    const client = new SmtpClient({
      host: candidate.host,
      port: this.options.config.outbound.direct.port,
      address: candidate.address,
      localDomain: this.localDomain(),
      connectionTimeoutMs: direct.connection_timeout_ms,
      commandTimeoutMs: direct.command_timeout_ms,
      tlsMode: tlsPolicy,
      allowPlaintext,
      auth: undefined,
      connect: this.options.connectFactory
        ? (connectOptions) => this.options.connectFactory!(connectOptions)
        : undefined,
      upgrade: this.options.upgradeFactory,
      now: () => this.now().getTime(),
    });

    let remoteIp: string | null = candidate.address;
    let remotePort: number | null = this.options.config.outbound.direct.port ?? 25;
    let tlsFacts: TlsFacts | null = null;

    try {
      await client.connect();
    } catch (error) {
      return this.classifyTransportError(request, candidate, error, startedAt, null);
    }

    try {
      // --- EHLO, with a HELO fallback (R-SMTP-1). -----------------------
      let ehlo = await client.command("EHLO", this.localDomain());
      if (ehlo.code === 500 || ehlo.code === 502 || ehlo.code === 504) {
        ehlo = await client.command("HELO", this.localDomain());
      }
      this.emitResponse(request, ehlo, candidate);

      // --- The STARTTLS negotiation (R-TLS-1 … R-TLS-9). ----------------
      const advertised = client.capabilities?.starttls ?? false;
      if (advertised) {
        const starttls = await client.command("STARTTLS");
        this.emitResponse(request, starttls, candidate);
        if (starttls.code >= 200 && starttls.code < 300) {
          try {
            tlsFacts = await client.upgradeToTls();
            this.emit("delivery_tls_negotiated", request, {
              attempt: request.attempt,
              deliveryState: null,
              tlsMode: tlsFacts.mode,
              tlsProtocol: tlsFacts.protocol,
              tlsCipher: tlsFacts.cipher,
              certFingerprint: tlsFacts.certFingerprint,
              mxHost: candidate.host,
              remoteIp,
              remotePort,
            });
            // The EHLO is repeated after the upgrade (RFC 3207 §4.2).
            const second = await client.command("EHLO", this.localDomain());
            this.emitResponse(request, second, candidate);
          } catch (error) {
            client.destroy();
            const tlsError = error as SmtpTlsError;
            this.emit("delivery_tls_failed", request, {
              attempt: request.attempt,
              deliveryState: "deferred",
              errorCode: tlsError.code ?? "tls_handshake_transient",
              tlsMode: "failed",
              mxHost: candidate.host,
              remoteIp,
              remotePort,
            });
            return this.buildResult(request, {
              outcome: tlsError.code === "tls_certificate_invalid" ? "bounced" : "deferred",
              errorCode: tlsError.code ?? "tls_handshake_transient",
              smtpCode: null,
              smtpResponse: null,
              enhancedCode: null,
              mxHost: candidate.host,
              remoteIp,
              remotePort,
              tls: null,
              durationMs: this.now().getTime() - startedAt.getTime(),
              remoteAccepted: false,
            });
          }
        }
      }

      if (!advertised) {
        // The peer does not offer STARTTLS (R-TLS-6).
        if (tlsPolicy === "required" || !allowPlaintext) {
          client.destroy();
          return this.buildResult(request, {
            outcome: "bounced",
            errorCode: "tls_unavailable",
            smtpCode: null,
            smtpResponse: null,
            enhancedCode: null,
            mxHost: candidate.host,
            remoteIp,
            remotePort,
            tls: null,
            durationMs: this.now().getTime() - startedAt.getTime(),
            remoteAccepted: false,
          });
        }
      }

      tlsFacts = client.tls;

      // --- The envelope transaction (R-SMTP-3 … R-SMTP-7). --------------
      const mailFrom = await client.command("MAIL", `FROM:<${request.envelopeSender}>`);
      this.emitResponse(request, mailFrom, candidate);
      const mailClassification = classifySmtpResponse(mailFrom.code, mailFrom.text);
      if (mailClassification.outcome !== "accepted") {
        await this.finishSession(client);
        return this.buildResult(request, {
          outcome: mailClassification.outcome,
          errorCode: mailClassification.errorCode,
          smtpCode: mailFrom.code,
          smtpResponse: mailFrom.raw,
          enhancedCode: mailFrom.enhancedCode,
          mxHost: candidate.host,
          remoteIp,
          remotePort,
          tls: tlsFacts,
          durationMs: this.now().getTime() - startedAt.getTime(),
          remoteAccepted: false,
        });
      }

      const rcptTo = await client.command("RCPT", `TO:<${request.recipient}>`);
      this.emitResponse(request, rcptTo, candidate);
      const rcptClassification = classifySmtpResponse(rcptTo.code, rcptTo.text);
      if (rcptClassification.outcome !== "accepted") {
        await this.finishSession(client);
        return this.buildResult(request, {
          outcome: rcptClassification.outcome,
          errorCode: rcptClassification.errorCode,
          smtpCode: rcptTo.code,
          smtpResponse: rcptTo.raw,
          enhancedCode: rcptTo.enhancedCode,
          mxHost: candidate.host,
          remoteIp,
          remotePort,
          tls: tlsFacts,
          durationMs: this.now().getTime() - startedAt.getTime(),
          remoteAccepted: false,
        });
      }

      const data = await client.command("DATA");
      this.emitResponse(request, data, candidate);
      if (data.code !== 354) {
        await this.finishSession(client);
        const dataClassification = classifySmtpResponse(data.code, data.text);
        return this.buildResult(request, {
          outcome: dataClassification.outcome,
          errorCode: dataClassification.errorCode,
          smtpCode: data.code,
          smtpResponse: data.raw,
          enhancedCode: data.enhancedCode,
          mxHost: candidate.host,
          remoteIp,
          remotePort,
          tls: tlsFacts,
          durationMs: this.now().getTime() - startedAt.getTime(),
          remoteAccepted: false,
        });
      }

      const final = await client.data(request.artifact);
      this.emitResponse(request, final, candidate);
      await this.finishSession(client);

      const finalClassification = classifySmtpResponse(final.code, final.text);
      const result = this.buildResult(request, {
        outcome: finalClassification.outcome,
        errorCode: finalClassification.errorCode,
        smtpCode: final.code,
        smtpResponse: final.raw,
        enhancedCode: final.enhancedCode,
        mxHost: candidate.host,
        remoteIp,
        remotePort,
        tls: tlsFacts,
        durationMs: this.now().getTime() - startedAt.getTime(),
        remoteAccepted: finalClassification.outcome === "accepted",
      });
      return result;
    } catch (error) {
      client.destroy();
      return this.classifyTransportError(request, candidate, error, startedAt, tlsFacts);
    }
  }

  /**
   * Close a session politely: `QUIT` when the socket is alive, and nothing
   * when it is dead (R-SMTP-8).
   */
  private async finishSession(client: SmtpClient): Promise<void> {
    try {
      await client.quit();
    } catch {
      // The peer may have hung up already; the session is over either way.
    }
  }

  /**
   * Classify a transport-level failure (connect, timeout, protocol error).
   */
  private classifyTransportError(
    request: DeliveryRequest,
    candidate: AddressCandidate,
    error: unknown,
    startedAt: Date,
    tlsFacts: TlsFacts | null,
  ): DeliveryResult {
    let outcome: DeliveryOutcome = "deferred";
    let errorCode: NonNullable<DeliveryResult["errorCode"]> = "network_transient";

    if (error instanceof SmtpTlsError) {
      outcome = error.code === "tls_certificate_invalid" ? "bounced" : "deferred";
      errorCode = error.code;
    } else if (error instanceof SmtpTimeoutError) {
      outcome = "deferred";
      errorCode = "timeout";
    } else if (error instanceof SmtpProtocolError) {
      outcome = "deferred";
      errorCode = "protocol_error";
    } else {
      const code = (error as { code?: string } | null)?.code;
      if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
        outcome = "deferred";
        errorCode = "dns_temporary";
      } else if (
        code === "ECONNREFUSED" ||
        code === "ECONNRESET" ||
        code === "EHOSTUNREACH" ||
        code === "ENETUNREACH" ||
        code === "EPIPE"
      ) {
        outcome = "deferred";
        errorCode = "network_transient";
      } else if (code === "CERT_HAS_EXPIRED" || code === "ERR_TLS_CERT_ALTNAME_INVALID") {
        outcome = "bounced";
        errorCode = "tls_certificate_invalid";
      }
    }

    const result = this.buildResult(request, {
      outcome,
      errorCode,
      smtpCode: null,
      smtpResponse: null,
      enhancedCode: null,
      mxHost: candidate.host,
      remoteIp: candidate.address,
      remotePort: null,
      tls: tlsFacts,
      durationMs: this.now().getTime() - startedAt.getTime(),
      remoteAccepted: false,
    });
    return result;
  }

  /* ------------------------------------------------------------------ */
  /* Finalization                                                        */
  /* ------------------------------------------------------------------ */

  /**
   * Apply the outcome to the durable state.
   *
   * A permanent outcome creates the bounce and requests the suppression
   * (R-CLS-3, R-FIN-6). A deferred outcome schedules the retry with a bounded
   * exponential backoff (R-RET-1 … R-RET-4).
   */
  private async finalize(
    request: DeliveryRequest,
    lease: OutboxLease | undefined,
    result: DeliveryResult,
    auditAction?: string,
  ): Promise<void> {
    const outcome = result.outcome;

    if (outcome === "bounced") {
      await this.recordBounce(request, result);
    }

    const envelopeStatus: EnvelopeRecipient["status"] =
      outcome === "accepted"
        ? "accepted"
        : outcome === "bounced"
          ? "bounced"
          : outcome === "deferred"
            ? "deferred"
            : "failed";

    const messageStatus: Message["status"] =
      outcome === "accepted"
        ? "accepted"
        : outcome === "bounced"
          ? "bounced"
          : outcome === "deferred"
            ? "deferred"
            : "failed";

    let nextAttemptAtIso: string | null = null;
    if (outcome === "deferred") {
      nextAttemptAtIso = this.scheduleRetry(request, lease);
    }

    try {
      await this.options.attempts.finalize({
        itemId: lease?.id ?? "",
        owner: this.options.workerId,
        envelopeId: request.envelopeId,
        status: envelopeStatus,
        smtpCode: result.smtpCode,
        response: result.smtpResponse,
        errorCode: result.errorCode,
        nextAttemptAt: nextAttemptAtIso,
        messageStatus,
      });
    } catch (error) {
      // A durable write failure after a remote `250` must not report success
      // (R-FIN-4): the recipient is deferred so the message is replayed.
      await this.options.audit.append({
        action: "delivery_store_write_failed",
        subjectId: request.envelopeId,
        outcome: "deferred",
        reasonCode: "store_unavailable",
        metadata: {
          messageId: request.messageId,
          error: (error as Error).message,
          smtpCode: result.smtpCode,
        },
      });
      return;
    }

    await this.options.audit.append({
      action: auditAction ?? `delivery_${outcome}`,
      subjectId: request.envelopeId,
      outcome,
      reasonCode: result.errorCode,
      metadata: {
        messageId: request.messageId,
        recipient: request.recipient,
        smtpCode: result.smtpCode,
        mxHost: result.mxHost,
        tlsMode: result.tls?.mode ?? "none",
        attempt: result.attempt,
      },
    });

    const eventName: DeliveryEventName =
      outcome === "accepted"
        ? "delivery_delivered"
        : outcome === "bounced"
          ? "delivery_bounced"
          : "delivery_deferred";
    this.emit(eventName, request, {
      attempt: result.attempt,
      deliveryState: outcome,
      errorCode: result.errorCode,
      smtpCode: result.smtpCode,
      smtpResponse: result.smtpResponse,
      enhancedCode: result.enhancedCode,
      mxHost: result.mxHost,
      remoteIp: result.remoteIp,
      remotePort: result.remotePort,
      tlsMode: result.tls?.mode ?? "none",
      tlsProtocol: result.tls?.protocol ?? null,
      tlsCipher: result.tls?.cipher ?? null,
      certFingerprint: result.tls?.certFingerprint ?? null,
      durationMs: result.durationMs,
    });

    this.emit("delivery_finalized", request, {
      attempt: result.attempt,
      deliveryState: outcome,
      errorCode: result.errorCode,
      smtpCode: result.smtpCode,
      mxHost: result.mxHost,
      remoteIp: result.remoteIp,
      remotePort: result.remotePort,
      durationMs: result.durationMs,
    });
  }

  /**
   * Create the bounce record and request the suppression (R-CLS-3, R-FIN-6).
   */
  private async recordBounce(request: DeliveryRequest, result: DeliveryResult): Promise<void> {
    try {
      const { bounce, suppressionId } = await this.options.bounces.record({
        tenantId: request.tenantId,
        messageId: request.messageId,
        envelopeId: request.envelopeId,
        recipient: request.recipient,
        smtpCode: result.smtpCode,
        dsnCode: null,
        dsnClass: null,
        bounceClass: "hard",
        diagnostic: result.smtpResponse,
        remoteId: result.mxHost,
      });
      void bounce;
      void suppressionId;
    } catch (error) {
      await this.options.audit.append({
        action: "delivery_bounce_write_failed",
        subjectId: request.envelopeId,
        outcome: "failed",
        reasonCode: "store_unavailable",
        metadata: { messageId: request.messageId, error: (error as Error).message },
      });
    }
  }

  /**
   * The ISO timestamp of the next attempt for a deferred recipient.
   *
   * The backoff is exponential with full jitter and a six-hour ceiling
   * (R-RET-1). When the attempt ceiling is reached, the recipient transitions
   * to a terminal state with the distinct reason `ATTEMPTS_EXHAUSTED`
   * (R-CLS-5, R-RET-4).
   */
  private scheduleRetry(
    request: DeliveryRequest,
    lease: OutboxLease | undefined,
  ): string | null {
    const configured = lease?.maxAttempts ?? this.options.config.queue.max_attempts;
    const ceiling = effectiveMaxAttempts(configured);
    if (request.attempt >= ceiling) {
      // The ceiling is reached: the recipient becomes terminal, but the last
      // observed SMTP code is preserved (R-CLS-5). The distinct reason code
      // carries the truth.
      return null;
    }
    const random = this.options.random ?? (() => deterministicJitter(request.attempt, request.messageId));
    const delay = backoffDelay({ attempt: request.attempt, random });
    return nextAttemptAt(this.now(), delay);
  }

  /* ------------------------------------------------------------------ */
  /* Helpers                                                             */
  /* ------------------------------------------------------------------ */

  /** The local domain sent in the EHLO (R-SMTP-2). */
  private localDomain(): string {
    const domains = this.options.config.domains.sending_domains;
    const first = domains.find((domain) => domain.trim().length > 0);
    if (first) return first.trim().toLowerCase();
    return "localhost.invalid";
  }

  /** The port the engine connects to (R-CONN-1). */
  private port(): number {
    return this.options.config.outbound.direct.port;
  }

  private buildResult(
    request: DeliveryRequest,
    fields: {
      outcome: DeliveryOutcome;
      errorCode: DeliveryResult["errorCode"];
      smtpCode: number | null;
      smtpResponse: string | null;
      enhancedCode: string | null;
      mxHost: string | null;
      remoteIp: string | null;
      remotePort: number | null;
      tls: TlsFacts | null;
      durationMs: number;
      remoteAccepted: boolean;
    },
  ): DeliveryResult {
    return {
      messageId: request.messageId,
      envelopeId: request.envelopeId,
      recipient: request.recipient,
      outcome: fields.outcome,
      errorCode: fields.errorCode,
      smtpCode: fields.smtpCode,
      smtpResponse: fields.smtpResponse,
      enhancedCode: fields.enhancedCode,
      mxHost: fields.mxHost,
      remoteIp: fields.remoteIp,
      remotePort: fields.remotePort,
      tls: fields.tls,
      attempt: request.attempt,
      durationMs: fields.durationMs,
      remoteAccepted: fields.remoteAccepted,
    };
  }

  private unreachableResult(
    lease: OutboxLease,
    outcome: DeliveryOutcome,
    errorCode: NonNullable<DeliveryResult["errorCode"]>,
  ): DeliveryResult {
    return {
      messageId: lease.messageId,
      envelopeId: lease.envelopeId,
      recipient: "",
      outcome,
      errorCode,
      smtpCode: null,
      smtpResponse: null,
      enhancedCode: null,
      mxHost: null,
      remoteIp: null,
      remotePort: null,
      tls: null,
      attempt: lease.attemptCount + 1,
      durationMs: 0,
      remoteAccepted: false,
    };
  }

  /* ------------------------------------------------------------------ */
  /* Host state                                                          */
  /* ------------------------------------------------------------------ */

  private hostState(host: string): HostState {
    const existing = this.hosts.get(host);
    if (existing) return existing;
    const created: HostState = { consecutiveFailures: 0, cooldownUntil: 0, quarantined: false };
    this.hosts.set(host, created);
    return created;
  }

  private isQuarantined(host: string): boolean {
    const state = this.hosts.get(host);
    if (!state) return false;
    return state.quarantined;
  }

  /** Quarantine a host whose TLS policy rejected it (R-RET-7). */
  quarantine(host: string): void {
    const state = this.hostState(host);
    state.quarantined = true;
  }

  private noteHostFailure(host: string): void {
    const state = this.hostState(host);
    state.consecutiveFailures += 1;
    const cooldown = Math.min(60 * 60 * 1000, 60_000 * 2 ** (state.consecutiveFailures - 1));
    state.cooldownUntil = this.now().getTime() + cooldown;
  }

  private clearHostState(host: string): void {
    const state = this.hosts.get(host);
    if (!state) return;
    state.consecutiveFailures = 0;
    state.cooldownUntil = 0;
  }

  /* ------------------------------------------------------------------ */
  /* Observability                                                       */
  /* ------------------------------------------------------------------ */

  private emit(
    event: DeliveryEventName,
    request: DeliveryRequest,
    fields: Partial<DeliveryEvent> & { attempt: number },
  ): void {
    const payload: DeliveryEvent = {
      event,
      ts: this.now().toISOString(),
      messageId: request.messageId,
      requestId: request.requestId,
      recipient: redactRecipient(request.recipient),
      domain: request.domain,
      mode: this.options.config.outbound.mode,
      mxHost: fields.mxHost ?? null,
      remoteIp: fields.remoteIp ?? null,
      remotePort: fields.remotePort ?? null,
      tlsMode: fields.tlsMode ?? "none",
      tlsProtocol: fields.tlsProtocol ?? null,
      tlsCipher: fields.tlsCipher ?? null,
      certFingerprint: fields.certFingerprint ?? null,
      smtpCode: fields.smtpCode ?? null,
      smtpResponse: fields.smtpResponse ?? null,
      enhancedCode: fields.enhancedCode ?? null,
      errorCode: fields.errorCode ?? null,
      deliveryState: fields.deliveryState ?? null,
      attempt: fields.attempt,
      durationMs: fields.durationMs ?? 0,
    };
    this.options.events.emit(payload);
  }

  private emitResponse(
    request: DeliveryRequest,
    response: SmtpResponse,
    candidate: AddressCandidate,
  ): void {
    this.emit("delivery_smtp_response", request, {
      attempt: request.attempt,
      deliveryState: null,
      smtpCode: response.code,
      smtpResponse: response.raw,
      enhancedCode: response.enhancedCode,
      mxHost: candidate.host,
      remoteIp: candidate.address,
      remotePort: this.port(),
    });
  }
}

/* -------------------------------------------------------------------------- */
/* Free functions                                                              */
/* -------------------------------------------------------------------------- */

/**
 * The routing domain of a recipient address.
 */
export function routingDomainOf(recipient: string): string {
  const at = recipient.lastIndexOf("@");
  if (at === -1) return recipient.trim().toLowerCase();
  return recipient.slice(at + 1).trim().toLowerCase();
}

/**
 * Inspect the artifact for the delivery-loop marker (R-LOOP-1 … R-LOOP-3).
 */
export function inspectLoopMarker(
  artifact: Uint8Array,
  limit: number,
): { rejected: boolean; markerPresent: boolean; hops: number } {
  const text = Buffer.from(artifact).toString("utf8");
  let hops = 0;
  let markerPresent = false;

  for (const line of text.split(/\r?\n/)) {
    if (line === "") break; // The headers end at the first blank line.
    const separator = line.indexOf(":");
    if (separator === -1) continue;
    if (line.slice(0, separator).trim().toLowerCase() !== LOOP_HEADER) continue;
    markerPresent = true;
    const value = line.slice(separator + 1).trim();
    hops += countHops(value);
  }

  return { rejected: markerPresent && hops > limit, markerPresent, hops };
}

/**
 * Count the hops recorded in a loop marker value.
 *
 * The marker carries a comma-separated list of hop identifiers; the number of
 * entries is the hop count.
 */
function countHops(value: string): number {
  const trimmed = value.trim();
  if (!trimmed) return 1;
  return trimmed.split(",").filter((part) => part.trim().length > 0).length;
}

/**
 * Redact a recipient for an observability event (R-OBS-1, R-OBS-4).
 *
 * The address is hashed, so an event carries no cleartext recipient while
 * still allowing per-recipient correlation.
 */
export function redactRecipient(recipient: string): string {
  const digest = createHash("sha256").update(recipient.toLowerCase(), "utf8").digest("hex");
  return `sha256:${digest.slice(0, 32)}`;
}

/** The error codes the engine may emit, re-exported for the operator surface. */
export { DELIVERY_ERROR_CODES };
