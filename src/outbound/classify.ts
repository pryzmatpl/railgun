// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * SMTP response classification.
 *
 * Contract: `docs/design/railgun-direct-mx-delivery-engine-ir.md` §3.6
 * (R-CLS-1 … R-CLS-6).
 *
 * Classification is made from the *actual* SMTP response code, never from a
 * boolean success flag: a `4xx` is always temporary and a `5xx` is always
 * permanent. Collapsing the two is forbidden by pipeline IR Rule T-4.
 */

import type { DeliveryErrorCode, DeliveryOutcome } from "./types.js";

/** The classification of one SMTP reply. */
export interface SmtpClassification {
  readonly outcome: DeliveryOutcome;
  readonly errorCode: DeliveryErrorCode | null;
  /** True when the reply is a temporary failure that shall be retried. */
  readonly temporary: boolean;
  /** True when the reply is a permanent failure that shall bounce. */
  readonly permanent: boolean;
}

/**
 * Extract the enhanced status code from a reply text.
 *
 * The enhanced code is an RFC 3463 triplet such as `5.1.1`, optionally
 * preceded by a class (`5`) and optionally followed by a diagnostic.
 */
export function extractEnhancedCode(text: string): string | null {
  const match = /\b([245])\.(\d{1,3})\.(\d{1,3})\b/.exec(text);
  if (match) return `${match[1]}.${match[2]}.${match[3]}`;
  return null;
}

/**
 * The permanent-failure code for a `5xx` reply (R-CLS-4).
 *
 * The enhanced status code refines the generic `mailbox_unavailable`: a
 * `5.1.x` is a user problem (`user_not_local`), a `5.7.x` is a policy refusal
 * (`policy_refused`), and `5.3.4` is a size problem (`message_too_large`).
 */
export function permanentCodeFor(
  code: number,
  enhancedCode: string | null,
): DeliveryErrorCode {
  if (code === 552) return "message_too_large";
  if (enhancedCode) {
    if (enhancedCode.startsWith("5.1.")) return "user_not_local";
    if (enhancedCode.startsWith("5.7.")) return "policy_refused";
    if (enhancedCode === "5.3.4" || enhancedCode === "5.2.3") return "message_too_large";
  }
  return "mailbox_unavailable";
}

/**
 * Classify one SMTP reply (R-CLS-1 … R-CLS-4).
 *
 * A `2xx` is a success; a `4xx` is temporary; a `5xx` is permanent. Any other
 * code is treated as temporary, because an unrecognised reply is not evidence
 * of a permanent mailbox-level failure.
 */
export function classifySmtpResponse(
  code: number,
  text: string,
): SmtpClassification {
  const enhancedCode = extractEnhancedCode(text);
  if (code >= 200 && code < 300) {
    return { outcome: "accepted", errorCode: null, temporary: false, permanent: false };
  }
  if (code >= 400 && code < 500) {
    return {
      outcome: "deferred",
      errorCode: "temporary_failure",
      temporary: true,
      permanent: false,
    };
  }
  if (code >= 500 && code < 600) {
    return {
      outcome: "bounced",
      errorCode: permanentCodeFor(code, enhancedCode),
      temporary: false,
      permanent: true,
    };
  }
  return {
    outcome: "deferred",
    errorCode: "temporary_failure",
    temporary: true,
    permanent: false,
  };
}

/**
 * Classify an SMTP reply, but refuse it when it arrived at the wrong stage.
 *
 * A `250` on `RCPT TO` is not a delivery acceptance; only the final reply to
 * `DATA` accepts the message (R-SMTP-4).
 */
export function classifyFinalResponse(
  code: number,
  text: string,
): SmtpClassification {
  return classifySmtpResponse(code, text);
}
