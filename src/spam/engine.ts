// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The policy engine façade.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §5.1, §5.2,
// §6, §8 and packages/railgun/docs/CONTRACT-IMPLEMENTATION-CHECKLIST.md §7.2.
//
// The engine exposes three semantic operations:
//
//   authorizeSubmission — the full submission gate sequence.
//   authorizeRelay      — the INV-1 relay-authorization gate.
//   signAndFinalize     — the fail-closed DKIM signing step.
//
// The engine never imports from `interfaces/`; the surfaces are projections of
// the engine, not the other way round (IR R-4.1).

import {
  isAtLeastAsRestrictive,
  mostRestrictive,
  REASON_CODES,
  type PolicyDecision,
  type Principal,
  type Recipient,
  type RecipientDecision,
  type SubmissionDecision,
  type SubmissionRequest,
} from "../domain/policy.js";
import { parseAddress } from "../security/address.js";
import { signDkim, type DkimSignInput, type DkimSignResult } from "../signer/dkim.js";
import type {
  AuditSink,
  BlocklistStore,
  Clock,
  DkimKeyStore,
  DkimPrivateKeyLoader,
  DnsResolver,
  DuplicateContentStore,
  RateLimitStore,
  RemoteBlocklistClient,
  ReputationStore,
  SendingDomainStore,
  SuppressionStore,
  VerifiedRecipientStore,
  WarmupStore,
} from "../ports/index.js";
import { checkSuppression } from "./abuse.js";
import { runCheapGates, type PrecheckResult } from "./cheap-gates.js";
import {
  appendAudit,
  auditFailureRecord,
  buildDecisionRecord,
  type DecisionExtras,
} from "./decision.js";
import { contentHmac, scoreContent, scoreToDecision } from "./content.js";
import type { PolicyConfig } from "./config.js";
import { resolveIdentityPosture } from "./identity.js";
import { checkLimits, checkWarmup } from "./limits.js";
import { authorizeRelay } from "./relay.js";
import { validateRequestShape } from "./shape.js";

/** The dependencies the engine needs. Every one is an interface. */
export interface PolicyEngineDeps {
  readonly clock: Clock;
  readonly config: PolicyConfig;
  readonly suppression: SuppressionStore;
  readonly blocklist: BlocklistStore;
  /** Optional remote blocklist client; `null` disables remote lookups. */
  readonly remoteBlocklist?: RemoteBlocklistClient | null;
  readonly rateLimits: RateLimitStore;
  readonly verifiedRecipients: VerifiedRecipientStore;
  readonly warmup: WarmupStore;
  readonly reputation: ReputationStore;
  readonly duplicates: DuplicateContentStore;
  readonly dkimKeys: DkimKeyStore;
  readonly dkimKeyLoader: DkimPrivateKeyLoader;
  readonly sendingDomains: SendingDomainStore;
  readonly dns: DnsResolver;
  readonly audit: AuditSink;
  /** The tenant-scoped secret used for salted content hashing. */
  readonly tenant_secret: string;
}

/**
 * Normalizes an address into a recipient. Returns `null` for an unusable
 * address.
 */
export function toRecipient(address: string): Recipient | null {
  const parsed = parseAddress(address);
  if (parsed === null) {
    return null;
  }
  return { address: parsed.local + "@" + parsed.domain, domain: parsed.domain };
}

/**
 * The policy engine.
 */
export class PolicyEngine {
  readonly #deps: PolicyEngineDeps;

  constructor(deps: PolicyEngineDeps) {
    this.#deps = deps;
  }

  /**
   * Runs the cheap gates — suppression, blocklist, role-address and relay
   * authorization — without touching the MIME body (IR R-6.3.1, R-6.3.2).
   *
   * This is what the SMTP surface calls at `MAIL FROM` / `RCPT TO` so that an
   * unauthorized recipient is **rejected at `RCPT TO`**, never silently
   * dropped (SECURITY.md).
   */
  async precheck(
    request: Pick<SubmissionRequest, "principal" | "envelope" | "source_ip">,
  ): Promise<PrecheckResult> {
    return runCheapGates(this.#deps, request);
  }

  /**
   * The full submission evaluation.
   *
   * The gates run in the normative order of IR §6.1, cheap before expensive:
   * gates 0–12 complete before any content scoring or signing happens.
   */
  async authorizeSubmission(request: SubmissionRequest): Promise<SubmissionDecision> {
    const config = this.#deps.config;
    const { principal, envelope, message } = request;
    const now = this.#deps.clock.now();

    // Gates 0, 2 and 4 — request shape, sender-domain authorization and
    // header hygiene.
    const shape = validateRequestShape(request, config.identity.authorized_subdomains);
    if (shape.decision !== null && shape.reason_code !== null) {
      return this.#decision(
        request,
        shape.decision,
        shape.reason_code,
        [shape.rule_id],
        [],
      );
    }
    const senderDomain = shape.sender_domain;

    // Gate 12 — DKIM key availability for the sending domain (cheap: it is a
    // store lookup, not a signature computation).
    const dkimKey = await this.#deps.dkimKeys.findActive(senderDomain);
    if (dkimKey === null || dkimKey.status !== "active") {
      return this.#decision(
        request,
        "deny",
        REASON_CODES.DKIM_KEY_UNAVAILABLE,
        ["gate.dkim.key_unavailable"],
        [],
      );
    }

    // Gates 5–8 — per-recipient abuse and relay checks.
    const precheck = await this.precheck(request);
    const perRecipient = [...precheck.recipients];

    // Gates 9–11 — quotas, rate limits and warmup.
    const limits = await checkLimits(
      this.#deps.rateLimits,
      config.rate_limit,
      {
        tenant_id: principal.tenant_id,
        principal_id: principal.principal_id,
        sender_domain: senderDomain,
        recipient: envelope.recipients[0]?.address ?? "",
        recipient_is_new: await this.#isNewRecipient(
          principal.tenant_id,
          envelope.recipients[0]?.address ?? "",
        ),
        now_ms: now,
      },
      envelope.recipients.length,
      request.size_bytes,
    );
    if (!limits.allowed) {
      return this.#decision(
        request,
        "throttle",
        REASON_CODES.RATE_LIMITED,
        ["gate.rate.limited"],
        perRecipient,
        {
          evidence: { dimension: limits.dimension },
          matched_limit: limits.limit_value,
          reset_at: new Date(limits.reset_at_ms).toISOString(),
          retry_at: new Date(limits.reset_at_ms).toISOString(),
        },
      );
    }

    const domainRecord = await this.#deps.sendingDomains.get(
      principal.tenant_id,
      senderDomain,
    );
    if (domainRecord !== null) {
      const warmup = await checkWarmup(
        this.#deps.warmup,
        config.warmup,
        principal.tenant_id,
        senderDomain,
        Date.parse(domainRecord.created_at),
        now,
        envelope.recipients.length,
      );
      if (!warmup.allowed) {
        return this.#decision(
          request,
          "throttle",
          REASON_CODES.WARMUP_LIMITED,
          ["gate.warmup.limited"],
          perRecipient,
          {
            matched_limit: warmup.limit_value,
            reset_at: new Date(warmup.reset_at_ms).toISOString(),
            retry_at: new Date(warmup.reset_at_ms).toISOString(),
          },
        );
      }
    }

    // Gate 13 — content scoring.
    const subject = message.headers["subject"] ?? "";
    const hmac = contentHmac(this.#deps.tenant_secret, subject, message.text_body + message.html_body);
    const duplicate = await this.#deps.duplicates.recordAndCheck(
      principal.tenant_id,
      hmac,
      config.spam.duplicate_window_seconds,
    );
    const identity = await resolveIdentityPosture(
      this.#deps.dns,
      this.#deps.sendingDomains,
      config.identity,
      senderDomain,
      principal.tenant_id,
      envelope.sender.split("@")[1]?.toLowerCase() ?? "",
      dkimKey !== null,
    );
    const score = scoreContent({
      message,
      content_hmac: hmac,
      cold_relationship: duplicate,
      abuse_history: false,
      sender_auth_mismatch: !identity.spf.aligned,
      tenant_secret: this.#deps.tenant_secret,
      protected_brands: config.spam.protected_brands,
      duplicate_content: duplicate,
    });
    const scored = scoreToDecision(
      score.score,
      config.spam.allow_threshold,
      config.spam.deny_threshold,
      config.spam.quarantine,
    );
    if (scored.decision !== "allow") {
      return this.#decision(
        request,
        scored.decision,
        scored.reason_code,
        ["gate.content.spam_threshold"],
        perRecipient,
        {
          spam_score: score.score,
          spam_model_version: score.model_version,
          evidence: { features: score.features },
        },
      );
    }

    // The message-level decision is the most restrictive of the per-recipient
    // outcomes and the message-level gates (IR R-5.2.2, R-6.4.1).
    let effective: PolicyDecision = "allow";
    let reasonCode: string = REASON_CODES.QUEUED;
    let suppressionReason: string | undefined;
    const ruleIds: string[] = [];
    for (const recipientDecision of perRecipient) {
      if (isAtLeastAsRestrictive(recipientDecision.decision, effective)) {
        effective = recipientDecision.decision;
        reasonCode = recipientDecision.reason_code;
        suppressionReason = recipientDecision.evidence?.suppression_reason;
      }
      ruleIds.push(...recipientDecision.rule_ids);
    }

    const outcome = await this.#decision(
      request,
      effective,
      reasonCode,
      ruleIds,
      perRecipient,
      {
        spam_score: score.score,
        spam_model_version: score.model_version,
        evidence: {
          features: score.features,
          ...(suppressionReason !== undefined ? { suppression_reason: suppressionReason } : {}),
        },
      },
    );
    return outcome;
  }

  /**
   * The INV-1 gate. Consulted by the SMTP surface, the HTTP surface, the MCP
   * surface **and** the direct-to-MX outbound path immediately before the
   * first `RCPT TO` of a transaction (IR R-5.1.2, R-8.2).
   */
  async authorizeRelay(
    tenantId: string,
    principal: Principal,
    targetDomain: string,
  ): Promise<{ allowed: boolean; reason_code: string; rule_ids: readonly string[] }> {
    const result = authorizeRelay(principal, targetDomain, this.#deps.config.relay, {
      sending_domains: principal.sending_domains,
      recipient_verified: false,
    });
    void tenantId;
    return {
      allowed: result.allowed,
      reason_code: result.reason_code,
      rule_ids: [result.rule_id],
    };
  }

  /**
   * The delivery-time re-check performed immediately before the outbound
   * transaction (IR R-8.2.1). A newly-suppressed recipient terminates as
   * `suppressed` **without an SMTP transaction** (INV-3).
   */
  async recheckBeforeDelivery(
    tenantId: string,
    sendingDomain: string,
    recipients: readonly Recipient[],
  ): Promise<{ suppressed: readonly Recipient[]; allowed: readonly Recipient[] }> {
    const now = this.#deps.clock.now();
    const suppressed: Recipient[] = [];
    const allowed: Recipient[] = [];
    for (const recipient of recipients) {
      const result = await checkSuppression(
        this.#deps.suppression,
        tenantId,
        sendingDomain,
        recipient.address,
        now,
      );
      if (result.decision === "deny") {
        suppressed.push(recipient);
      } else {
        allowed.push(recipient);
      }
    }
    return { suppressed, allowed };
  }

  /**
   * Signs the message, fail-closed (IR R-5.1.3, R-7.1.7).
   *
   * A signing failure is a `deny`, never a silent unsigned send.
   */
  async signAndFinalize(
    input: {
      readonly headers: readonly { name: string; value: string }[];
      readonly body: string;
      readonly domain: string;
      readonly selector: string;
      readonly timestamp: number;
    },
  ): Promise<DkimSignResult> {
    const config = this.#deps.config;
    const key = await this.#deps.dkimKeys.findActive(input.domain);
    if (key === null || key.status !== "active") {
      return {
        ok: false,
        reason_code: "DKIM_KEY_UNAVAILABLE",
        error: "no active signing key for domain",
      };
    }
    const material = await this.#deps.dkimKeyLoader.load(key.secret_ref);
    if (material === null) {
      return {
        ok: false,
        reason_code: "DKIM_KEY_UNAVAILABLE",
        error: "signing key material could not be loaded",
      };
    }
    const signInput: DkimSignInput = {
      headers: input.headers,
      body: input.body,
      domain: input.domain,
      selector: input.selector,
      algorithm: key.algorithm,
      private_key_pem: material.pem,
      canonicalization: {
        header: config.signer.header_canonicalization,
        body: config.signer.body_canonicalization,
      },
      timestamp: input.timestamp,
      sign_headers: config.signer.sign_headers,
    };
    return signDkim(signInput);
  }

  async #isNewRecipient(tenantId: string, recipient: string): Promise<boolean> {
    if (recipient.length === 0) {
      return false;
    }
    return !(await this.#deps.verifiedRecipients.isVerified(tenantId, recipient));
  }

  async #decision(
    request: SubmissionRequest,
    decision: PolicyDecision,
    reasonCode: string,
    ruleIds: readonly string[],
    recipients: readonly RecipientDecision[],
    extra: DecisionExtras = {},
  ): Promise<SubmissionDecision> {
    const config = this.#deps.config;
    const record = buildDecisionRecord(
      request,
      config,
      decision,
      reasonCode,
      ruleIds,
      recipients,
      extra,
    );

    // The decision is durably audited before it is reported as final
    // (IR R-5.2.3, R-14.1.7).
    if (config.audit.enabled) {
      const written = await appendAudit(this.#deps.audit, record);
      if (!written.ok && config.audit.write_failure_mode === "strict") {
        // Fail closed: never a send without an audit trail.
        return {
          decision: "deny",
          recipients: [],
          record: auditFailureRecord(record),
        };
      }
    }

    return { decision, recipients, record };
  }
}

/**
 * Combines two decisions into the more restrictive one. Exported for the
 * surfaces that aggregate per-recipient outcomes.
 */
export { mostRestrictive };

// Re-exported so a surface has one import site for the policy façade.
export { hashRecipient } from "./decision.js";
export { runCheapGates } from "./cheap-gates.js";
export type { PrecheckResult } from "./cheap-gates.js";
