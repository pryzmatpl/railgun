// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Binds the policy engine to the SMTP submission surface's policy hooks.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §8.2 and
// packages/railgun/docs/CONTRACT-IMPLEMENTATION-CHECKLIST.md §7.2 (A-9, A-11).
//
// The SMTP surface rejects an unauthorized recipient **at `RCPT TO`**, never
// silently dropping it (SECURITY.md). Every denial here happens before the
// session opens an outbound transaction, so a denial produces **zero SMTP
// transactions** (IR INV-3, R-15.2.1).

import type { Principal, Recipient } from "../domain/policy.js";
import type { PolicyEngine } from "./engine.js";
import { toRecipient } from "./engine.js";

/**
 * The subset of the SMTP surface's policy-hook contract this adapter needs.
 * It is declared structurally so the adapter does not depend on the SMTP
 * module's internal types.
 */
export interface SmtpHookContext {
  readonly tenantId: string;
  readonly principalId: string;
  readonly sourceIp: string;
  readonly tls: boolean;
  readonly envelopeSender: string | null;
  readonly recipient: string | null;
  readonly declaredSize: number | null;
  readonly receivedSize: number | null;
  readonly rawMessage: Uint8Array | null;
  readonly headers: readonly { readonly name: string; readonly value: string }[];
  readonly correlationId: string;
}

/** The outcome shape the SMTP session consumes. */
export type SmtpPolicyOutcome =
  | { readonly action: "allow" }
  | {
      readonly action: "reject";
      readonly code: number;
      readonly reason: string;
      readonly retryAfterSeconds?: number;
    }
  | {
      readonly action: "defer";
      readonly code: number;
      readonly reason: string;
      readonly retryAfterSeconds?: number;
    }
  | {
      readonly action: "quarantine";
      readonly code: number;
      readonly reason: string;
    };

/** The principal resolver the adapter needs. */
export type PrincipalResolver = (context: SmtpHookContext) => Promise<Principal | null>;

/**
 * The SMTP reply codes for each policy outcome (IR §12.1).
 *
 * - Permanent refusal → `550 5.7.1`.
 * - Throttle / deferral → `450 4.7.1`.
 */
export const SMTP_POLICY_CODES = Object.freeze({
  reject: 550,
  defer: 450,
  quarantine: 550,
});

/**
 * Maps a policy decision to an SMTP outcome.
 */
export function toSmtpOutcome(
  decision: "allow" | "deny" | "throttle" | "quarantine" | "reject",
  reason: string,
  retryAt?: string,
): SmtpPolicyOutcome {
  switch (decision) {
    case "allow":
      return { action: "allow" };
    case "throttle":
      return {
        action: "defer",
        code: SMTP_POLICY_CODES.defer,
        reason,
        ...(retryAt !== undefined
          ? {
              retryAfterSeconds: Math.max(
                1,
                Math.ceil((Date.parse(retryAt) - Date.now()) / 1000),
              ),
            }
          : {}),
      };
    case "quarantine":
      return { action: "quarantine", code: SMTP_POLICY_CODES.quarantine, reason };
    case "deny":
    case "reject":
      return { action: "reject", code: SMTP_POLICY_CODES.reject, reason };
    default:
      return { action: "reject", code: SMTP_POLICY_CODES.reject, reason };
  }
}

/**
 * Builds the SMTP policy hooks backed by the policy engine.
 *
 * The hooks map one-to-one onto the engine's gates:
 *
 * - `authorizeSender`     → the sender-domain gate (H2).
 * - `authorizeRecipient`  → the relay-authorization gate (H1, INV-1).
 * - `checkSuppression`    → the suppression gate (H4).
 * - `checkBlocklist`      → the blocklist gate (H5).
 * - `checkRoleAddress`    → the role-address gate (H6).
 * - `checkRateLimit`      → the rate-limit and quota gates (H3).
 * - `scoreContent`        → the content-scoring gate (H7).
 */
export function createSmtpPolicyHooks(
  engine: PolicyEngine,
  resolvePrincipal: PrincipalResolver,
): {
  authorizeSender(context: SmtpHookContext): Promise<SmtpPolicyOutcome>;
  authorizeRecipient(context: SmtpHookContext): Promise<SmtpPolicyOutcome>;
  checkRateLimit(context: SmtpHookContext): Promise<SmtpPolicyOutcome>;
  checkSuppression(context: SmtpHookContext): Promise<SmtpPolicyOutcome>;
  checkBlocklist(context: SmtpHookContext): Promise<SmtpPolicyOutcome>;
  checkRoleAddress(context: SmtpHookContext): Promise<SmtpPolicyOutcome>;
  scoreContent(context: SmtpHookContext): Promise<SmtpPolicyOutcome>;
} {
  const principalFor = async (context: SmtpHookContext): Promise<Principal | null> =>
    resolvePrincipal(context);

  return {
    async authorizeSender(context) {
      const principal = await principalFor(context);
      if (principal === null) {
        return { action: "reject", code: 530, reason: "UNAUTHORIZED" };
      }
      const sender = context.envelopeSender ?? "";
      const domain = sender.split("@")[1]?.toLowerCase() ?? "";
      const result = await engine.authorizeRelay(context.tenantId, principal, domain);
      if (!result.allowed) {
        return {
          action: "reject",
          code: SMTP_POLICY_CODES.reject,
          reason: result.reason_code,
        };
      }
      return { action: "allow" };
    },

    async authorizeRecipient(context) {
      const principal = await principalFor(context);
      if (principal === null) {
        return { action: "reject", code: 530, reason: "UNAUTHORIZED" };
      }
      const recipient = context.recipient ?? "";
      const parsed = toRecipient(recipient);
      if (parsed === null) {
        return {
          action: "reject",
          code: SMTP_POLICY_CODES.reject,
          reason: "VALIDATION_FAILED",
        };
      }
      const result = await engine.authorizeRelay(context.tenantId, principal, parsed.domain);
      if (!result.allowed) {
        return {
          action: "reject",
          code: SMTP_POLICY_CODES.reject,
          reason: result.reason_code,
        };
      }
      return { action: "allow" };
    },

    async checkSuppression(context) {
      const principal = await principalFor(context);
      if (principal === null) {
        return { action: "reject", code: 530, reason: "UNAUTHORIZED" };
      }
      const recipient = context.recipient ?? "";
      const parsed = toRecipient(recipient);
      if (parsed === null) {
        return { action: "allow" };
      }
      const result = await engine.precheck({
        principal,
        envelope: {
          sender: context.envelopeSender ?? "",
          recipients: [parsed],
        },
        source_ip: context.sourceIp,
      });
      const denial = result.recipients[0];
      if (denial !== undefined && denial.decision !== "allow") {
        return toSmtpOutcome(denial.decision, denial.reason_code);
      }
      return { action: "allow" };
    },

    async checkBlocklist(context) {
      const principal = await principalFor(context);
      if (principal === null) {
        return { action: "reject", code: 530, reason: "UNAUTHORIZED" };
      }
      const recipient = context.recipient ?? "";
      const parsed = toRecipient(recipient);
      if (parsed === null) {
        return { action: "allow" };
      }
      const result = await engine.precheck({
        principal,
        envelope: {
          sender: context.envelopeSender ?? "",
          recipients: [parsed],
        },
        source_ip: context.sourceIp,
      });
      const denial = result.recipients[0];
      if (denial !== undefined && denial.decision !== "allow") {
        return toSmtpOutcome(denial.decision, denial.reason_code);
      }
      return { action: "allow" };
    },

    async checkRoleAddress(context) {
      const principal = await principalFor(context);
      if (principal === null) {
        return { action: "reject", code: 530, reason: "UNAUTHORIZED" };
      }
      const recipient = context.recipient ?? "";
      const parsed = toRecipient(recipient);
      if (parsed === null) {
        return { action: "allow" };
      }
      const result = await engine.precheck({
        principal,
        envelope: {
          sender: context.envelopeSender ?? "",
          recipients: [parsed],
        },
        source_ip: context.sourceIp,
      });
      const denial = result.recipients[0];
      if (denial !== undefined && denial.decision !== "allow") {
        return toSmtpOutcome(denial.decision, denial.reason_code);
      }
      return { action: "allow" };
    },

    async checkRateLimit(context) {
      const principal = await principalFor(context);
      if (principal === null) {
        return { action: "reject", code: 530, reason: "UNAUTHORIZED" };
      }
      const recipient = context.recipient ?? "";
      const parsed = toRecipient(recipient);
      const size = context.receivedSize ?? context.declaredSize ?? 0;
      const decision = await engine.authorizeSubmission({
        principal,
        envelope: {
          sender: context.envelopeSender ?? "",
          recipients: parsed === null ? [] : [parsed],
        },
        message: {
          headers: headersToMap(context.headers),
          text_body: "",
          html_body: "",
          attachment_names: [],
        },
        request_id: context.correlationId,
        size_bytes: size,
        correlation_id: context.correlationId,
        source_ip: context.sourceIp,
      });
      if (decision.decision === "allow") {
        return { action: "allow" };
      }
      return toSmtpOutcome(
        decision.decision,
        decision.record.reason_code,
        decision.record.retry_at,
      );
    },

    async scoreContent(context) {
      const principal = await principalFor(context);
      if (principal === null) {
        return { action: "reject", code: 530, reason: "UNAUTHORIZED" };
      }
      const recipient = context.recipient ?? "";
      const parsed = toRecipient(recipient);
      const decision = await engine.authorizeSubmission({
        principal,
        envelope: {
          sender: context.envelopeSender ?? "",
          recipients: parsed === null ? [] : [parsed],
        },
        message: {
          headers: headersToMap(context.headers),
          text_body: "",
          html_body: "",
          attachment_names: [],
        },
        request_id: context.correlationId,
        size_bytes: context.receivedSize ?? context.declaredSize ?? 0,
        correlation_id: context.correlationId,
        source_ip: context.sourceIp,
      });
      if (decision.decision === "allow") {
        return { action: "allow" };
      }
      return toSmtpOutcome(
        decision.decision,
        decision.record.reason_code,
        decision.record.retry_at,
      );
    },
  };
}

/**
 * Converts the SMTP surface's header list into the engine's header map.
 */
export function headersToMap(
  headers: readonly { readonly name: string; readonly value: string }[],
): Record<string, string> {
  const map: Record<string, string> = {};
  for (const header of headers) {
    const name = header.name.toLowerCase();
    map[name] = map[name] === undefined ? header.value : `${map[name]}, ${header.value}`;
  }
  return map;
}

/**
 * The recipient the SMTP surface rejects when the principal is not
 * authorized. Exported so a surface can report the same address it
 * rejected.
 */
export function rejectedRecipient(
  recipients: readonly Recipient[],
  domain: string,
): Recipient | null {
  return recipients.find((r) => r.domain === domain) ?? null;
}
