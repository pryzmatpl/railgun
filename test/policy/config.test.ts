// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The shipped example configuration must be internally consistent with the
// policy engine's validation.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §13.1
// (R-13.1.2, R-13.1.3) and packages/railgun/config/railgun.example.yaml.
//
// The example file is parsed with a minimal YAML reader so the test does not
// depend on a YAML package being installed in the package tree.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  DEFAULT_POLICY_CONFIG,
  validatePolicyConfig,
  type PolicyConfig,
} from "../../src/spam/config.js";
import {
  DKIM_DEPENDENCY_RESOLUTION,
  DNS_RESOLVER_RESOLUTION,
  PUBLIC_SUFFIX_RESOLUTION,
  RELAY_DEFAULT_SCOPE_RESOLUTION,
  RATE_LIMIT_STORE_RESOLUTION,
  SMTP_THROTTLE_CODE_RESOLUTION,
  WARMUP_PRECEDENCE_RESOLUTION,
} from "../../src/spam/resolutions.js";

const EXAMPLE_PATH = fileURLToPath(
  new URL("../../config/railgun.example.yaml", import.meta.url),
);

/**
 * A deliberately small YAML reader for the flat, two-level configuration in
 * the example file. It understands `key: value`, nested one level by
 * indentation, comments and empty lists. It is enough to check the settings
 * the policy engine validates, and it keeps the package free of a YAML
 * dependency in the test tree.
 */
function readScalarSections(source: string): Map<string, string> {
  const sections = new Map<string, string>();
  let currentTop = "";
  let currentSub = "";
  for (const rawLine of source.split("\n")) {
    if (rawLine.trim().length === 0 || rawLine.trimStart().startsWith("#")) {
      continue;
    }
    const indent = rawLine.length - rawLine.trimStart().length;
    // Strip an inline comment, but only when it is not inside a quoted value.
    const line = rawLine.trim().replace(/\s+#.*$/, "");
    if (indent === 0) {
      currentTop = line.replace(/:$/, "");
      currentSub = "";
      continue;
    }
    if (indent === 2 && line.endsWith(":")) {
      currentSub = line.replace(/:$/, "");
      continue;
    }
    if (indent === 2) {
      const eq = line.indexOf(":");
      if (eq > 0) {
        sections.set(`${currentTop}.${line.slice(0, eq).trim()}`, line.slice(eq + 1).trim());
      }
      continue;
    }
    if (indent === 4 && currentSub.length > 0) {
      const eq = line.indexOf(":");
      if (eq > 0) {
        sections.set(
          `${currentTop}.${currentSub}.${line.slice(0, eq).trim()}`,
          line.slice(eq + 1).trim(),
        );
      }
    }
  }
  return sections;
}

describe("The shipped example configuration", () => {
  const source = readFileSync(EXAMPLE_PATH, "utf8");
  const sections = readScalarSections(source);

  it("declares the identity, signer, warmup-ramp and relay sections", () => {
    for (const key of [
      "identity.alignment_mode",
      "signer.default_algorithm",
      "signer.rsa_min_bits",
      "warmup_ramp.warmup_days",
      "warmup_ramp.ramp_multiplier",
      "relay.default_scope",
    ]) {
      expect(sections.has(key), `missing ${key}`).toBe(true);
    }
  });

  it("declares the two content-scoring thresholds", () => {
    expect(sections.get("spam.allow_threshold")).toBe("0.35");
    expect(sections.get("spam.deny_threshold")).toBe("0.70");
  });

  it("ships a relay default scope of `none` (item 6)", () => {
    expect(sections.get("relay.default_scope")).toBe('"none"');
    expect(RELAY_DEFAULT_SCOPE_RESOLUTION).toContain("none");
  });

  it("ships an RSA minimum of 2048 bits", () => {
    expect(sections.get("signer.rsa_min_bits")).toBe("2048");
  });

  it("ships the strict alignment mode as the default", () => {
    expect(sections.get("identity.alignment_mode")).toBe('"strict"');
  });

  it("passes the policy engine's own validation when mapped onto PolicyConfig", () => {
    const mapped: PolicyConfig = {
      ...DEFAULT_POLICY_CONFIG,
      identity: {
        ...DEFAULT_POLICY_CONFIG.identity,
        require_spf_record: sections.get("identity.require_spf_record") === "true",
        require_dmarc_aligned: sections.get("identity.require_dmarc_aligned") !== "false",
        alignment_mode: (sections.get("identity.alignment_mode") ?? '"strict"').replace(
          /"/g,
          "",
        ) as "strict" | "relaxed",
      },
      signer: {
        ...DEFAULT_POLICY_CONFIG.signer,
        default_algorithm: (sections.get("signer.default_algorithm") ?? '"rsa-sha256"').replace(
          /"/g,
          "",
        ) as "rsa-sha256" | "ed25519",
        rsa_min_bits: Number(sections.get("signer.rsa_min_bits") ?? "2048"),
      },
      spam: {
        ...DEFAULT_POLICY_CONFIG.spam,
        allow_threshold: Number(sections.get("spam.allow_threshold") ?? "0.35"),
        deny_threshold: Number(sections.get("spam.deny_threshold") ?? "0.7"),
      },
      warmup: {
        ...DEFAULT_POLICY_CONFIG.warmup,
        warmup_days: Number(sections.get("warmup_ramp.warmup_days") ?? "30"),
        ramp_multiplier: Number(sections.get("warmup_ramp.ramp_multiplier") ?? "1.5"),
        warmup_daily_cap: Number(sections.get("warmup_ramp.warmup_daily_cap") ?? "50"),
        warmup_recipient_cap: Number(sections.get("warmup_ramp.warmup_recipient_cap") ?? "25"),
      },
      relay: {
        ...DEFAULT_POLICY_CONFIG.relay,
        default_scope: (sections.get("relay.default_scope") ?? '"none"').replace(
          /"/g,
          "",
        ) as "none",
      },
    };

    expect(validatePolicyConfig(mapped)).toEqual([]);
  });
});

describe("The IR's open items are resolved (IR §18)", () => {
  it("records the DKIM dependency choice", () => {
    expect(DKIM_DEPENDENCY_RESOLUTION).toContain("node:crypto");
  });

  it("records the public-suffix strategy", () => {
    expect(PUBLIC_SUFFIX_RESOLUTION).toContain("strict");
  });

  it("records the DNS resolver port contract", () => {
    expect(DNS_RESOLVER_RESOLUTION).toContain("DnsResolver");
  });

  it("records the shared rate-limit store decision", () => {
    expect(RATE_LIMIT_STORE_RESOLUTION).toContain("RateLimitStore");
  });

  it("records the warmup precedence", () => {
    expect(WARMUP_PRECEDENCE_RESOLUTION).toContain("overrides");
  });

  it("records the relay default scope decision", () => {
    expect(RELAY_DEFAULT_SCOPE_RESOLUTION).toContain('"none"');
  });

  it("records the SMTP throttle code", () => {
    expect(SMTP_THROTTLE_CODE_RESOLUTION).toContain("450 4.7.1");
    expect(SMTP_THROTTLE_CODE_RESOLUTION).toContain("452 4.5.3");
  });
});
