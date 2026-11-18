// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The package-wide verification suite for RailGun.
 *
 * The pieces exported here are the ones an operator or a release pipeline
 * needs outside the test runner:
 *
 *   - {@link scanForSecrets} / {@link assertNoSecretLeak} — credential-hygiene
 *     proof (source, log and audit scans with zero matches).
 *   - {@link resolveLiveGate} — the fail-closed precondition check for the
 *     opt-in live delivery run.
 *   - {@link runReleaseChecks} — the single release command required by the
 *     verification IR.
 *
 * Contract: `docs/design/481de2b7-e002-4cdc-95e0-0adc9068e2c4.md`.
 */

/* -------------------------------------------------------------------------- */
/* The fake MX harness                                                          */
/* -------------------------------------------------------------------------- */

export { startFakeMxServer } from "./fake-mx.js";
export type { FakeMxReply, FakeMxScript, FakeMxServer, FakeMxSession } from "./fake-mx.js";

/* -------------------------------------------------------------------------- */
/* Credential hygiene                                                          */
/* -------------------------------------------------------------------------- */

export {
  DEFAULT_IGNORED_DIRECTORIES,
  DEFAULT_SCANNED_EXTENSIONS,
  REDACTION_SENTINEL,
  assertNoSecretLeak,
  redactSecret,
  scanForSecrets,
} from "./secret-scan.js";
export type { SecretMatch, SecretScanOptions, SecretScanResult } from "./secret-scan.js";

/* -------------------------------------------------------------------------- */
/* The live gate                                                                */
/* -------------------------------------------------------------------------- */

export {
  DEFAULT_LIVE_CREDENTIAL_VARIABLE,
  DEFAULT_LIVE_OPT_IN_VARIABLE,
  DEFAULT_LIVE_RECIPIENT_VARIABLE,
  evaluateLiveGate,
  resolveLiveGate,
} from "./live-gate.js";
export type {
  LiveGateCheck,
  LiveGateDecision,
  LiveGateEnvironment,
  LiveGateOptions,
} from "./live-gate.js";

/* -------------------------------------------------------------------------- */
/* Release checks                                                              */
/* -------------------------------------------------------------------------- */

export { releaseCheckTargets } from "./release-checks.js";
export type { ReleaseCheckTarget } from "./release-checks.js";
