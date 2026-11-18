// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The identity checks: SPF record presence, DMARC posture and DKIM key
// availability for a sending domain.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §7.2, §7.3,
// §7.4 and verification obligations V-6, V-7, V-8.
//
// RailGun **reads and verifies** DNS records; it never writes them
// (IR §7.3.6). DNS is the only permitted network egress in the policy path
// (IR R-4.2).

import {
  evaluateDmarcPosture,
  postureBlocksSending,
  selectDmarcRecord,
  type DmarcEvaluation,
} from "../security/dmarc.js";
import { evaluateSpfRecord, type SpfEvaluation } from "../security/spf.js";
import { domainsAligned } from "../security/address.js";
import type { DnsResolver, SendingDomainStore } from "../ports/index.js";
import type { IdentityConfig } from "./config.js";

/** The SPF posture of a sending domain. */
export interface SpfPosture {
  /** Whether a usable SPF record is published. */
  readonly present: boolean;
  readonly evaluation: SpfEvaluation;
  /** `SPF_NOT_ALIGNED` when the envelope and header domains disagree. */
  readonly aligned: boolean;
  /** The reason the domain is not aligned, when it is not. */
  readonly reason?: string;
}

/**
 * Evaluates the SPF posture of a sending domain.
 *
 * This is a **pre-flight self-check**: it confirms that the `From` domain is
 * one the principal may send from and that a published SPF record exists
 * (unless the deployment marks the domain `spf_check: disabled`). It is a
 * local sanity check, not a claim about how the receiving server evaluates
 * SPF (IR §7.2.1).
 */
export async function evaluateSpfPosture(
  resolver: DnsResolver,
  domain: string,
  envelopeDomain: string,
  identity: IdentityConfig,
): Promise<SpfPosture> {
  const aligned = domainsAligned(domain, envelopeDomain, identity.alignment_mode);
  let evaluation: SpfEvaluation;
  try {
    const txts = await resolver.resolveTxt(domain);
    evaluation = evaluateSpfRecord(txts);
  } catch {
    evaluation = { result: "error", record: null, error: "dns_unavailable" };
  }

  if (!aligned) {
    return {
      present: evaluation.result !== "none",
      evaluation,
      aligned: false,
      reason: "envelope and header domains are not aligned",
    };
  }
  return { present: evaluation.result !== "none", evaluation, aligned: true };
}

/**
 * Evaluates the DMARC posture of a sending domain (IR §7.3.2, §7.3.3).
 */
export async function evaluateDmarc(
  resolver: DnsResolver,
  domain: string,
  options: {
    readonly previously_verified: boolean;
    readonly dns_failure_policy: "fail_open" | "fail_closed";
    readonly dkim_aligned: boolean;
    readonly spf_aligned: boolean;
  },
): Promise<DmarcEvaluation> {
  let txts: readonly string[];
  try {
    txts = await resolver.resolveTxt(`_dmarc.${domain}`);
  } catch {
    txts = [];
  }
  const { record, conflicting } = selectDmarcRecord(txts);
  const evaluation = evaluateDmarcPosture({
    record,
    previously_verified: options.previously_verified,
    dns_failure_policy: options.dns_failure_policy,
    dkim_aligned: options.dkim_aligned,
    spf_aligned: options.spf_aligned,
  });
  if (!conflicting) {
    return evaluation;
  }
  return { ...evaluation, conflicting_policy: true };
}

/**
 * Whether a DMARC posture must block sending (IR §7.3.3).
 */
export function dmarcBlocks(
  evaluation: DmarcEvaluation,
  previouslyVerified: boolean,
  failurePolicy: "fail_open" | "fail_closed",
): boolean {
  return postureBlocksSending(evaluation.posture, previouslyVerified, failurePolicy);
}

/**
 * Reads the published DKIM DNS record and reports whether it matches the
 * key RailGun holds (IR R-7.1.10).
 *
 * A mismatch is an operator-facing **warning** in `doctor`, never a send
 * failure on its own.
 */
export async function verifyPublishedDkimRecord(
  resolver: DnsResolver,
  domain: string,
  selector: string,
  expectedPublicKey: string,
): Promise<{ present: boolean; matches: boolean; error?: string }> {
  let txts: readonly string[];
  try {
    txts = await resolver.resolveTxt(`${selector}._domainkey.${domain}`);
  } catch (error) {
    return { present: false, matches: false, error: (error as Error).message };
  }
  if (txts.length === 0) {
    return { present: false, matches: false };
  }
  const joined = txts.join("");
  const match = /p=([A-Za-z0-9+/=]+)/.exec(joined);
  if (match === null || match[1] === undefined) {
    return { present: true, matches: false, error: "no_p_tag" };
  }
  const published = match[1]
    .replace(/\s+/g, "")
    .replace(/(?=[A-Za-z0-9+/=]{20})(?:[^A-Za-z0-9+/=]|=)/g, "")
    .trim();
  const expected = expectedPublicKey.replace(/\s+/g, "").trim();
  return { present: true, matches: published === expected };
}

/**
 * Resolves the identity posture of a sending domain in one pass, so the
 * policy engine makes a single, consistent identity decision (IR §5.2.4).
 */
export interface IdentityPosture {
  readonly spf: SpfPosture;
  readonly dmarc: DmarcEvaluation;
  /** Whether a DKIM key is available for the domain. */
  readonly dkim_key_available: boolean;
  /** The sending domain record, when one exists. */
  readonly domain_record: Awaited<ReturnType<SendingDomainStore["get"]>>;
}

/**
 * Computes the identity posture of a sending domain.
 */
export async function resolveIdentityPosture(
  resolver: DnsResolver,
  domainStore: SendingDomainStore,
  identity: IdentityConfig,
  domain: string,
  tenantId: string,
  envelopeDomain: string,
  dkimKeyAvailable: boolean,
): Promise<IdentityPosture> {
  const domainRecord = await domainStore.get(tenantId, domain);
  const previouslyVerified = domainRecord?.status === "verified";

  const spf = await evaluateSpfPosture(resolver, domain, envelopeDomain, identity);
  const dmarc = await evaluateDmarc(resolver, domain, {
    previously_verified: previouslyVerified,
    dns_failure_policy: domainRecord?.dmarc_failure_policy ?? identity.dns_failure_policy,
    dkim_aligned: dkimKeyAvailable,
    spf_aligned: spf.aligned,
  });

  return { spf, dmarc, dkim_key_available: dkimKeyAvailable, domain_record: domainRecord };
}
