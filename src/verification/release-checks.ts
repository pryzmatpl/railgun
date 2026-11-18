// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The release-check plan.
 *
 * The release gate is a list of independently runnable checks. Every check
 * exits non-zero on failure, and the live (T5) delivery check is never part
 * of the list: it can only be started explicitly by an operator.
 *
 * Contract: `docs/design/481de2b7-e002-4cdc-95e0-0adc9068e2c4.md` §5.4
 * (V-REL-12 … V-REL-15).
 */

/** One release check. */
export interface ReleaseCheckTarget {
  /** The stable identifier of the check. */
  readonly id: string;
  /** What the check proves. */
  readonly description: string;
  /** The command that runs it, relative to the package root. */
  readonly command: readonly string[];
  /** Whether the check needs Docker or a network. */
  readonly kind: "local" | "docker";
}

/**
 * The ordered release checks.
 *
 * The live-delivery check is intentionally absent: V-REL-14 forbids it from
 * being triggered implicitly by the release command.
 */
export function releaseCheckTargets(): readonly ReleaseCheckTarget[] {
  return [
    {
      id: "typecheck",
      description: "TypeScript type check",
      command: ["npm", "run", "--silent", "typecheck"],
      kind: "local",
    },
    {
      id: "tests",
      description: "Unit and integration Vitest suites (T1-T4)",
      command: ["npm", "run", "--silent", "test"],
      kind: "local",
    },
    {
      id: "licence-headers",
      description: "GPL-3.0-or-later header and LICENSE scan",
      command: ["npm", "run", "--silent", "lint:licence"],
      kind: "local",
    },
    {
      id: "standalone-install",
      description: "Fresh standalone npm install and build outside the monorepo",
      command: ["node", "scripts/release-check.mjs", "--only", "standalone-install"],
      kind: "local",
    },
    {
      id: "npm-pack",
      description: "npm pack and self-install of the produced tarball",
      command: ["node", "scripts/release-check.mjs", "--only", "npm-pack"],
      kind: "local",
    },
    {
      id: "docker",
      description: "Docker image build and health check",
      command: ["node", "scripts/release-check.mjs", "--only", "docker"],
      kind: "docker",
    },
  ];
}
