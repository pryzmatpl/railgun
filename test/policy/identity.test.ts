// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// SPF alignment and record parsing, DMARC policy and posture mapping.
//
// Covers IR verification obligations V-5, V-6, V-7 and V-8.

import { describe, expect, it } from "vitest";

import {
  domainsAligned,
  isDomainWithin,
  isLookalikeDomain,
  organizationalDomain,
  parseAddress,
} from "../../src/security/address.js";
import {
  evaluateSpfRecord,
  parseSpfRecord,
  selectSpfRecord,
  spfExcludesSender,
} from "../../src/security/spf.js";
import {
  evaluateDmarcPosture,
  parseDmarcRecord,
  postureBlocksSending,
  selectDmarcRecord,
} from "../../src/security/dmarc.js";
import { evaluateSpfPosture } from "../../src/spam/identity.js";
import { DEFAULT_POLICY_CONFIG } from "../../src/spam/config.js";
import { StaticDnsResolver } from "./fakes.js";

describe("Address parsing and normalization", () => {
  it("parses a plain address", () => {
    const parsed = parseAddress("Alice@Example.COM");
    expect(parsed?.local).toBe("alice");
    expect(parsed?.domain).toBe("example.com");
  });

  it("parses a display name", () => {
    const parsed = parseAddress("Alice Smith <alice@example.com>");
    expect(parsed?.display_name).toBe("Alice Smith");
    expect(parsed?.domain).toBe("example.com");
  });

  it("rejects an address with CR/LF (header injection)", () => {
    expect(parseAddress("alice@example.com\r\nBcc: victim@evil.test")).toBeNull();
  });

  it("rejects an address without a domain", () => {
    expect(parseAddress("alice")).toBeNull();
    expect(parseAddress("@example.com")).toBeNull();
    expect(parseAddress("alice@")).toBeNull();
  });
});

describe("SPF alignment (V-5)", () => {
  it("treats an exact domain match as aligned", () => {
    expect(domainsAligned("example.com", "example.com", "strict")).toBe(true);
  });

  it("treats a subdomain as unaligned in strict mode", () => {
    expect(domainsAligned("mail.example.com", "example.com", "strict")).toBe(false);
  });

  it("treats a subdomain as aligned in relaxed mode", () => {
    expect(domainsAligned("mail.example.com", "example.com", "relaxed")).toBe(true);
  });

  it("treats an unrelated domain as unaligned in both modes", () => {
    expect(domainsAligned("evil.test", "example.com", "strict")).toBe(false);
    expect(domainsAligned("evil.test", "example.com", "relaxed")).toBe(false);
  });

  it("splits the organizational domain with a public-suffix-aware list", () => {
    expect(organizationalDomain("mail.example.co.uk")).toBe("example.co.uk");
    expect(organizationalDomain("example.co.uk")).toBe("example.co.uk");
    expect(organizationalDomain("mail.example.com")).toBe("example.com");
  });

  it("detects a lookalike domain within a distance of one", () => {
    expect(isLookalikeDomain("paypa1.com", ["paypal.com"], 1)).toBe(true);
    expect(isLookalikeDomain("paypal.com", ["paypal.com"], 1)).toBe(false);
    expect(isLookalikeDomain("completely-different.test", ["paypal.com"], 1)).toBe(
      false,
    );
  });

  it("reports an unaligned envelope/header pair as SPF_NOT_ALIGNED", async () => {
    const resolver = new StaticDnsResolver({
      "example.com": ["v=spf1 ip4:198.51.100.1 -all"],
    });
    const posture = await evaluateSpfPosture(
      resolver,
      "example.com",
      "other.test",
      DEFAULT_POLICY_CONFIG.identity,
    );
    expect(posture.aligned).toBe(false);
    expect(posture.reason).toBeDefined();
  });

  it("reports an aligned pair as aligned", async () => {
    const resolver = new StaticDnsResolver({
      "example.com": ["v=spf1 ip4:198.51.100.1 -all"],
    });
    const posture = await evaluateSpfPosture(
      resolver,
      "example.com",
      "example.com",
      DEFAULT_POLICY_CONFIG.identity,
    );
    expect(posture.aligned).toBe(true);
    expect(posture.present).toBe(true);
  });
});

describe("SPF record parsing (V-6)", () => {
  it("parses the mechanisms of a record", () => {
    const record = parseSpfRecord(
      "v=spf1 ip4:198.51.100.1 ip6:2001:db8::/32 include:_spf.example.net a mx ptr exists:_check.example.net ~all",
    );
    expect(record.error).toBeUndefined();
    expect(record.mechanisms.map((m) => m.name)).toEqual([
      "ip4",
      "ip6",
      "include",
      "a",
      "mx",
      "ptr",
      "exists",
      "all",
    ]);
    expect(record.all_qualifier).toBe("~");
    expect(record.lookup_count).toBe(5);
  });

  it("parses the redirect modifier", () => {
    const record = parseSpfRecord("v=spf1 redirect=_spf.example.net");
    expect(record.modifiers.redirect).toBe("_spf.example.net");
    expect(record.lookup_count).toBe(1);
  });

  it("parses the ip4 CIDR length", () => {
    const record = parseSpfRecord("v=spf1 ip4:198.51.100.0/24 -all");
    const ip4 = record.mechanisms.find((m) => m.name === "ip4");
    expect(ip4?.cidr).toBe(24);
    expect(ip4?.value).toBe("198.51.100.0");
  });

  it("reports the -all and ~all outcomes", () => {
    expect(evaluateSpfRecord(["v=spf1 ip4:198.51.100.1 -all"]).result).toBe("fail");
    expect(evaluateSpfRecord(["v=spf1 ip4:198.51.100.1 ~all"]).result).toBe("fail");
    expect(evaluateSpfRecord(["v=spf1 ip4:198.51.100.1 +all"]).result).toBe("pass");
  });

  it("reports a record with no all mechanism as neutral", () => {
    expect(evaluateSpfRecord(["v=spf1 ip4:198.51.100.1"]).result).toBe("neutral");
  });

  it("reports the 10-lookup limit as TOO_MANY_LOOKUPS without evaluating further", () => {
    const mechanisms = Array.from(
      { length: 11 },
      (_unused, index) => `include:_s${index}.example.net`,
    ).join(" ");
    const evaluation = evaluateSpfRecord([`v=spf1 ${mechanisms} -all`]);
    expect(evaluation.result).toBe("toomanylookups");
    expect(evaluation.record?.too_many_lookups).toBe(true);
    expect(evaluation.record?.lookup_count).toBe(11);
  });

  it("reports the absence of a record as none", () => {
    expect(evaluateSpfRecord([]).result).toBe("none");
  });

  it("reports a malformed record as an error", () => {
    expect(parseSpfRecord("not an spf record").error).toBe("missing_version");
    expect(parseSpfRecord("").error).toBe("empty_record");
  });

  it("reports conflicting SPF records", () => {
    const { conflicting } = selectSpfRecord([
      "v=spf1 -all",
      "v=spf1 ip4:198.51.100.1 -all",
    ]);
    expect(conflicting).toBe(true);
  });

  it("flags a record that excludes the sender", () => {
    const record = parseSpfRecord("v=spf1 include:_spf.other.net -all");
    expect(spfExcludesSender(record, ["our-sending-host.net"])).toBe(true);
    expect(spfExcludesSender(record, ["other.net"])).toBe(false);
  });
});

describe("DMARC policy (V-7)", () => {
  it("parses a full DMARC record", () => {
    const record = parseDmarcRecord(
      "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; rua=mailto:r@example.com; ruf=mailto:f@example.com; pct=50; fo=1",
    );
    expect(record?.policy).toBe("reject");
    expect(record?.subdomain_policy).toBe("quarantine");
    expect(record?.adkim).toBe("strict");
    expect(record?.aspf).toBe("strict");
    expect(record?.rua).toBe("mailto:r@example.com");
    expect(record?.ruf).toBe("mailto:f@example.com");
    expect(record?.pct).toBe(50);
    expect(record?.fo).toBe("1");
  });

  it("rejects a record without a valid p= tag", () => {
    expect(parseDmarcRecord("v=DMARC1; rua=mailto:r@example.com")).toBeNull();
    expect(parseDmarcRecord("v=DMARC1; p=bogus")).toBeNull();
    expect(parseDmarcRecord("not dmarc")).toBeNull();
  });

  it("reports a conflicting p= across several records", () => {
    const { conflicting } = selectDmarcRecord([
      "v=DMARC1; p=none",
      "v=DMARC1; p=reject",
    ]);
    expect(conflicting).toBe(true);
  });

  it("reports no valid record", () => {
    const { record, error } = selectDmarcRecord(["nothing here"]);
    expect(record).toBeNull();
    expect(error).toBe("no_valid_record");
  });
});

describe("DMARC posture mapping to send behaviour (V-8)", () => {
  it("maps a satisfiable policy to `aligned`", () => {
    const evaluation = evaluateDmarcPosture({
      record: parseDmarcRecord("v=DMARC1; p=reject; adkim=r; aspf=r"),
      previously_verified: true,
      dns_failure_policy: "fail_closed",
      dkim_aligned: true,
      spf_aligned: true,
    });
    expect(evaluation.posture).toBe("aligned");
    expect(postureBlocksSending(evaluation.posture, true, "fail_closed")).toBe(false);
  });

  it("maps `p=none` to `relaxed_only`", () => {
    const evaluation = evaluateDmarcPosture({
      record: parseDmarcRecord("v=DMARC1; p=none"),
      previously_verified: true,
      dns_failure_policy: "fail_closed",
      dkim_aligned: true,
      spf_aligned: true,
    });
    expect(evaluation.posture).toBe("relaxed_only");
    expect(postureBlocksSending(evaluation.posture, true, "fail_closed")).toBe(false);
  });

  it("maps an unsatisfiable policy to `mismatched` and blocks sending", () => {
    const evaluation = evaluateDmarcPosture({
      record: parseDmarcRecord("v=DMARC1; p=reject; adkim=s; aspf=s"),
      previously_verified: true,
      dns_failure_policy: "fail_closed",
      dkim_aligned: false,
      spf_aligned: false,
    });
    expect(evaluation.posture).toBe("mismatched");
    expect(postureBlocksSending(evaluation.posture, true, "fail_closed")).toBe(true);
  });

  it("maps `adkim=s` with only SPF alignment to `mismatched`", () => {
    const evaluation = evaluateDmarcPosture({
      record: parseDmarcRecord("v=DMARC1; p=reject; adkim=s; aspf=r"),
      previously_verified: true,
      dns_failure_policy: "fail_closed",
      dkim_aligned: false,
      spf_aligned: true,
    });
    expect(evaluation.posture).toBe("mismatched");
  });

  it("maps an unavailable record to `unknown`", () => {
    const evaluation = evaluateDmarcPosture({
      record: null,
      previously_verified: true,
      dns_failure_policy: "fail_closed",
      dkim_aligned: true,
      spf_aligned: true,
    });
    expect(evaluation.posture).toBe("unknown");
    expect(evaluation.error).toBe("record_unavailable");
  });

  it("fails closed for a previously verified domain with an unknown posture", () => {
    expect(postureBlocksSending("unknown", true, "fail_closed")).toBe(true);
    expect(postureBlocksSending("unknown", true, "fail_open")).toBe(true);
  });

  it("fails open for a never-verified domain with an unknown posture", () => {
    expect(postureBlocksSending("unknown", false, "fail_open")).toBe(false);
    expect(postureBlocksSending("unknown", false, "fail_closed")).toBe(true);
  });
});

describe("Domain containment", () => {
  it("recognizes a subdomain relationship", () => {
    expect(isDomainWithin("mail.example.com", "example.com")).toBe(true);
    expect(isDomainWithin("example.com", "example.com")).toBe(true);
    expect(isDomainWithin("evil.test", "example.com")).toBe(false);
    expect(isDomainWithin("notexample.com", "example.com")).toBe(false);
  });
});
