// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * `railgun doctor` — configuration, runtime and connectivity diagnosis.
 *
 * The command validates configuration, required runtime resources and
 * connectivity assumptions without starting a public listener and without
 * sending mail. It never prints a secret: credentials are reported by name
 * and presence only.
 */
import path from "node:path";

import { EXIT, CliError } from "../cli/errors.js";
import { type CommandContext } from "../cli/context.js";
import { renderJson, renderTable } from "../cli/output.js";
import { ConfigLoadError, loadConfig } from "../config/load.js";
import { resolveSecret } from "../config/config.js";
import { probePathWritable } from "../services/operator.js";

/** The classification of one diagnostic check. */
export type CheckStatus = "ok" | "warn" | "fail";

/** One diagnostic check. */
export interface DoctorCheck {
  name: string;
  status: CheckStatus;
  /** A safe diagnostic: names and states, never values. */
  detail: string;
  /**
   * The configuration fields this check failed on, when it is a
   * configuration check. The field names are safe; their values are not
   * disclosed.
   */
  fields?: string[];
}

/** The doctor result. */
export interface DoctorReport {
  checks: DoctorCheck[];
  /** The aggregate status: `fail` if any check failed, else `warn` if any warned. */
  status: CheckStatus;
}

/**
 * Run the doctor checks.
 *
 * Each check is independently classified; an optional or incomplete
 * integration is a `warn`, never a silent `ok`.
 */
export async function runDoctor(context: CommandContext): Promise<DoctorReport> {
  const checks: DoctorCheck[] = [];

  checks.push(checkRuntime());
  checks.push(...checkConfiguration(context));

  let config = null;
  try {
    config = loadConfig({
      configPath: context.options.configPath,
      env: context.env,
    }).config;
  } catch (cause) {
    if (cause instanceof ConfigLoadError) {
      checks.push({
        name: "store",
        status: "warn",
        detail: "skipped: configuration is invalid",
      });
      checks.push({
        name: "queue",
        status: "warn",
        detail: "skipped: configuration is invalid",
      });
      checks.push({
        name: "outbound",
        status: "warn",
        detail: "skipped: configuration is invalid",
      });
      return { checks, status: "fail" };
    }
    throw cause;
  }

  checks.push(...checkStore(context, config));
  checks.push(...checkQueue(config));
  checks.push(...checkOutbound(context, config));
  checks.push(...checkDkim(context, config));
  checks.push(...checkSecrets(context, config));

  const status: CheckStatus = checks.some((check) => check.status === "fail")
    ? "fail"
    : checks.some((check) => check.status === "warn")
      ? "warn"
      : "ok";

  return { checks, status };
}

/** The runtime check: the interpreter and platform RailGun is running on. */
function checkRuntime(): DoctorCheck {
  const major = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
  if (major < 22) {
    return {
      name: "runtime",
      status: "fail",
      detail: `node ${process.version} (${process.platform} ${process.arch}) — Node.js 22 or newer is required`,
    };
  }
  return {
    name: "runtime",
    status: "ok",
    detail: `node ${process.version} (${process.platform} ${process.arch})`,
  };
}

/**
 * The configuration check.
 *
 * A broken configuration is a `fail`, and the diagnostic names the offending
 * field — never its value.
 */
function checkConfiguration(context: CommandContext): DoctorCheck[] {
  try {
    const loaded = loadConfig({ configPath: context.options.configPath, env: context.env });
    const source = loaded.configPath ?? "shipped defaults";
    const checks: DoctorCheck[] = [
      { name: "configuration", status: "ok", detail: `loaded from ${source}` },
    ];
    if (loaded.envSources.length > 0) {
      checks.push({
        name: "environment overlay",
        status: "ok",
        detail: `${loaded.envSources.length} variable(s) applied: ${loaded.envSources.join(", ")}`,
      });
    }
    return checks;
  } catch (cause) {
    if (cause instanceof ConfigLoadError) {
      const fields = cause.diagnostics.map((diagnostic) => diagnostic.field).join(", ");
      return [
        {
          name: "configuration",
          status: "fail",
          detail:
            cause.diagnostics.length > 0
              ? `${cause.message} (${fields})`
              : cause.message,
          ...(cause.diagnostics.length > 0
            ? { fields: cause.diagnostics.map((diagnostic) => diagnostic.field) }
            : {}),
        },
      ];
    }
    throw cause;
  }
}

/** The store check: the configured driver and whether its path is usable. */
function checkStore(context: CommandContext, config: ReturnType<typeof loadConfig>["config"]): DoctorCheck[] {
  const checks: DoctorCheck[] = [];
  if (config.store.driver === "postgres") {
    checks.push({
      name: "store",
      status: config.store.url ? "ok" : "fail",
      detail: config.store.url
        ? "postgres driver selected (URL present)"
        : "postgres driver selected but no store URL is configured",
    });
    return checks;
  }

  if (config.store.driver === "memory") {
    checks.push({
      name: "store",
      status: "warn",
      detail: "memory driver selected (test only — data is not durable)",
    });
    return checks;
  }

  const storePath = path.resolve(process.cwd(), config.store.path);
  const parent = path.dirname(storePath);
  const writable = probePathWritable(parent);
  checks.push({
    name: "store",
    status: writable.ok ? "ok" : "warn",
    detail: `sqlite ${config.store.path} — ${writable.detail}`,
  });
  return checks;
}

/** The queue check: the durable outbox settings. */
function checkQueue(config: ReturnType<typeof loadConfig>["config"]): DoctorCheck[] {
  return [
    {
      name: "queue",
      status: "ok",
      detail: `concurrency=${config.queue.concurrency} lease=${config.queue.lease_seconds}s max_attempts=${config.queue.max_attempts}`,
    },
  ];
}

/**
 * The outbound check.
 *
 * Direct mode is the primary path and is reported as `ok`; relay mode is an
 * explicit fallback and is reported as a `warn` so the operator knows the
 * deployment is not talking to recipient MX servers directly.
 */
function checkOutbound(
  context: CommandContext,
  config: ReturnType<typeof loadConfig>["config"],
): DoctorCheck[] {
  const checks: DoctorCheck[] = [];
  if (config.outbound.mode === "relay") {
    checks.push({
      name: "outbound",
      status: "warn",
      detail: `mode=relay host=${config.outbound.relay.host ?? "unset"} — relay is the fallback; direct MX is the default`,
    });
    return checks;
  }

  checks.push({
    name: "outbound",
    status: config.outbound.direct.mx_lookup ? "ok" : "fail",
    detail: `mode=direct mx_lookup=${config.outbound.direct.mx_lookup} require_tls=${config.outbound.direct.require_tls}`,
  });

  // A reverse-DNS requirement is only meaningful when a hostname is known;
  // there is no hostname to probe from configuration alone.
  checks.push({
    name: "reverse dns",
    status: config.outbound.direct.require_reverse_dns ? "warn" : "ok",
    detail: config.outbound.direct.require_reverse_dns
      ? "a published reverse DNS record is required for the outbound address"
      : "no reverse DNS requirement configured",
  });

  return checks;
}

/** The DKIM check: presence of a signing key, never the key material. */
function checkDkim(
  context: CommandContext,
  config: ReturnType<typeof loadConfig>["config"],
): DoctorCheck[] {
  const checks: DoctorCheck[] = [];
  if (!config.dkim.enabled) {
    checks.push({
      name: "dkim",
      status: "warn",
      detail: "DKIM signing is disabled — outbound mail will not be signed",
    });
    return checks;
  }

  const variableName = config.dkim.private_key_env;
  if (!variableName) {
    checks.push({
      name: "dkim",
      status: "fail",
      detail: "DKIM is enabled but no key environment variable is configured",
    });
    return checks;
  }

  let present = false;
  try {
    present = resolveSecret(variableName, context.env) !== undefined;
  } catch {
    present = false;
  }
  checks.push({
    name: "dkim",
    status: present ? "ok" : "fail",
    detail: present
      ? `signing key present via ${variableName} (value not shown)`
      : `signing key ${variableName} is not set — DKIM signing cannot start`,
  });
  return checks;
}

/**
 * The secrets check.
 *
 * Only presence is reported. A credential is never echoed, and the audit salt
 * is only reported as present or absent.
 */
function checkSecrets(
  context: CommandContext,
  config: ReturnType<typeof loadConfig>["config"],
): DoctorCheck[] {
  const checks: DoctorCheck[] = [];

  if (config.audit.salt_env) {
    let present = false;
    try {
      present = resolveSecret(config.audit.salt_env, context.env) !== undefined;
    } catch {
      present = false;
    }
    checks.push({
      name: "audit salt",
      status: present ? "ok" : "warn",
      detail: present
        ? `${config.audit.salt_env} is set (value not shown)`
        : `${config.audit.salt_env} is not set — recipient hashing falls back to an unkeyed digest`,
    });
  }

  if (config.auth.setup_token_env) {
    let present = false;
    try {
      present = resolveSecret(config.auth.setup_token_env, context.env) !== undefined;
    } catch {
      present = false;
    }
    checks.push({
      name: "setup token",
      status: present ? "ok" : "warn",
      detail: present
        ? `${config.auth.setup_token_env} is set (value not shown)`
        : `${config.auth.setup_token_env} is not set — a bootstrap token will be generated on first start`,
    });
  }

  return checks;
}

/**
 * The doctor command handler.
 *
 * The exit code distinguishes a configuration problem from a dependency
 * problem: an operator needs to know which one to fix.
 */
export async function doctorCommand(context: CommandContext): Promise<number> {
  const report = await runDoctor(context);

  if (report.status === "fail") {
    // In JSON mode stdout carries exactly one document, so the failure is
    // reported as the error envelope alone; the checklist is available in
    // human mode.
    const configurationFailed = report.checks.some(
      (check) => check.status === "fail" && check.name === "configuration",
    );
    const failedChecks = report.checks
      .filter((check) => check.status === "fail")
      .map((check) => check.name);
    const configFields = report.checks.flatMap((check) => check.fields ?? []);
    const details: Record<string, unknown> = {};
    if (failedChecks.length > 0) {
      details["failed_checks"] = failedChecks;
    }
    if (configFields.length > 0) {
      details["fields"] = configFields;
    }
    throw new CliError({
      code: configurationFailed ? "CONFIG_INVALID" : "DEPENDENCY_UNAVAILABLE",
      message: configurationFailed
        ? "The configuration is invalid"
        : "One or more doctor checks failed",
      exitCode: configurationFailed ? EXIT.CONFIG : EXIT.DEPENDENCY,
      details: Object.keys(details).length > 0 ? details : undefined,
    });
  }

  context.channel.stdout(
    context.options.json ? renderJson(report) : renderDoctorTable(report),
  );
  return EXIT.SUCCESS;
}

/** Render the doctor checklist as an aligned table. */
function renderDoctorTable(report: DoctorReport): string {
  return renderTable(
    ["CHECK", "STATUS", "DETAIL"],
    report.checks.map((check) => [check.name, check.status, check.detail]),
  );
}
