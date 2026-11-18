// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The fail-closed live-delivery gate.
 *
 * The live run is the only RailGun test that may touch the network and the
 * only one that may read a credential from the environment. It therefore
 * starts with an explicit precondition check:
 *
 *   - the operator opted in (`RAILGUN_LIVE=1`);
 *   - the credential is present in the environment (never in a file, never in
 *     the repository);
 *   - exactly one explicitly approved recipient is named;
 *   - no credential is quoted, padded or otherwise malformed.
 *
 * When any precondition fails the gate refuses to run and no network
 * connection is opened. The decision is returned as data so the caller can
 * report it without echoing a secret.
 *
 * Contract: `docs/design/481de2b7-e002-4cdc-95e0-0adc9068e2c4.md` §4.1
 * (V-LIVE-1 … V-LIVE-7).
 */

/** One precondition and its outcome. */
export interface LiveGateCheck {
  /** The stable name of the check. */
  readonly name: string;
  /** Whether the check passed. */
  readonly ok: boolean;
  /** A short, secret-free explanation. */
  readonly detail: string;
}

/** The decision the gate reached. */
export interface LiveGateDecision {
  /** Whether the live run may proceed. */
  readonly allowed: boolean;
  /** Every check that was evaluated. */
  readonly checks: readonly LiveGateCheck[];
  /** The approved recipient, when the gate allowed the run. */
  readonly recipient?: string | undefined;
}

/** The environment the gate reads. */
export interface LiveGateEnvironment {
  /** Whether the operator opted in. */
  readonly optedIn: boolean;
  /** The credential value read from the environment; never returned. */
  readonly credential: string | undefined;
  /** The approved recipient read from the environment. */
  readonly recipient: string | undefined;
}

/** The options that configure the gate. */
export interface LiveGateOptions {
  /** The environment variable names, so the gate stays configurable. */
  readonly optInVariable?: string;
  readonly credentialVariable?: string;
  readonly recipientVariable?: string;
  /** The credential length below which the value is refused. */
  readonly minimumCredentialLength?: number;
}

/** The default environment variable names. */
export const DEFAULT_LIVE_OPT_IN_VARIABLE = "RAILGUN_LIVE";
export const DEFAULT_LIVE_CREDENTIAL_VARIABLE = "RAILGUN_LIVE_SMTP_PASSWORD";
export const DEFAULT_LIVE_RECIPIENT_VARIABLE = "RAILGUN_LIVE_APPROVED_RECIPIENT";

/**
 * A deliberately strict address shape: one mailbox, no display name, no
 * comma-separated list and no whitespace.
 */
const APPROVED_RECIPIENT = /^[^\s@,<>"']+@[^\s@,<>"'.]+(?:\.[^\s@,<>"'.]+)+$/;

/** Read the gate inputs from an environment map without touching the process env. */
export function resolveLiveGate(
  environment: Readonly<Record<string, string | undefined>>,
  options: LiveGateOptions = {},
): LiveGateDecision {
  const optInVariable = options.optInVariable ?? DEFAULT_LIVE_OPT_IN_VARIABLE;
  const credentialVariable = options.credentialVariable ?? DEFAULT_LIVE_CREDENTIAL_VARIABLE;
  const recipientVariable = options.recipientVariable ?? DEFAULT_LIVE_RECIPIENT_VARIABLE;
  const minimumCredentialLength = options.minimumCredentialLength ?? 8;

  const checks: LiveGateCheck[] = [];

  const optedIn = environment[optInVariable] === "1" || environment[optInVariable] === "true";
  checks.push({
    name: "opt-in",
    ok: optedIn,
    detail: optedIn
      ? `${optInVariable}=1`
      : `Set ${optInVariable}=1 to allow a live delivery run`,
  });

  const credential = environment[credentialVariable];
  const credentialPresent = typeof credential === "string" && credential.length > 0;
  checks.push({
    name: "credential-present",
    ok: credentialPresent,
    detail: credentialPresent
      ? `${credentialVariable} is present (value not shown)`
      : `${credentialVariable} is not set`,
  });

  let credentialWellFormed = false;
  if (credentialPresent && credential !== undefined) {
    const quoted =
      (credential.startsWith('"') && credential.endsWith('"')) ||
      (credential.startsWith("'") && credential.endsWith("'"));
    const padded = credential !== credential.trim();
    credentialWellFormed = !quoted && !padded && credential.length >= minimumCredentialLength;
    checks.push({
      name: "credential-well-formed",
      ok: credentialWellFormed,
      detail: credentialWellFormed
        ? `${credentialVariable} is well formed (value not shown)`
        : `${credentialVariable} must not be quote-wrapped or padded and must be at least ${minimumCredentialLength} characters`,
    });
  } else {
    checks.push({
      name: "credential-well-formed",
      ok: false,
      detail: `${credentialVariable} is not set`,
    });
  }

  const recipient = environment[recipientVariable];
  const recipientPresent = typeof recipient === "string" && recipient.length > 0;
  const recipientWellFormed = recipientPresent && recipient !== undefined && APPROVED_RECIPIENT.test(recipient);
  checks.push({
    name: "approved-recipient",
    ok: recipientWellFormed,
    detail: recipientWellFormed
      ? `${recipientVariable} names one approved recipient`
      : `${recipientVariable} must name exactly one approved recipient address`,
  });

  const allowed = checks.every((check) => check.ok);
  return allowed && recipientPresent && recipient !== undefined
    ? { allowed: true, checks, recipient }
    : { allowed: false, checks };
}

/**
 * Evaluate the gate and throw when the live run must not proceed.
 *
 * The thrown error names the failing checks only; it never contains a
 * credential, because the checks are built from names and booleans.
 */
export function evaluateLiveGate(
  environment: Readonly<Record<string, string | undefined>>,
  options: LiveGateOptions = {},
): LiveGateDecision {
  const decision = resolveLiveGate(environment, options);
  if (!decision.allowed) {
    const failed = decision.checks.filter((check) => !check.ok).map((check) => check.name);
    throw new Error(`The live delivery gate refused to run; failed checks: ${failed.join(", ")}`);
  }
  return decision;
}
