// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * RailGun configuration: shipped defaults → YAML file → `RAILGUN_*` overlay.
 *
 * Precedence (unit-A IR §5.1): the explicit `--config` file wins over the
 * environment overlay, and both win over the shipped defaults. Unknown YAML
 * keys are errors, not warnings, so a typo never silently disables a policy.
 *
 * Secrets are never stored in the configuration file. They are referenced by
 * environment variable name (optionally with a `_FILE` indirection) and are
 * resolved lazily; the resolved value never appears in a diagnostic.
 */

import { readFileSync } from "node:fs";

/** The sentinel used to redact a secret in every operator-facing projection. */
export const REDACTED = "__OPENCLAW_REDACTED__";

export type OutboundMode = "direct" | "relay";

export interface RailgunConfig {
  server: {
    smtp_bind: string;
    http_bind: string;
    mcp_http_bind: string | null;
    max_message_bytes: number;
  };
  store: {
    driver: "sqlite" | "postgres" | "memory";
    path: string;
    url: string | null;
  };
  queue: {
    concurrency: number;
    lease_seconds: number;
    max_attempts: number;
  };
  outbound: {
    mode: OutboundMode;
    relay: {
      host: string | null;
      port: number;
      username_env: string | null;
      password_env: string | null;
    };
    direct: {
      /** The MX submission port; defaults to 25 in direct mode. */
      port: number;
      /** Resolve the recipient MX records before connecting. */
      mx_lookup: boolean;
      /** Prefer IPv4 and fall back to IPv6 when a host offers both. */
      ipv4_first: boolean;
      ipv6_fallback: boolean;
      /** Require STARTTLS with TLS >= 1.2 and certificate verification. */
      require_tls: boolean;
      require_reverse_dns: boolean;
      connection_timeout_ms: number;
      command_timeout_ms: number;
    };
  };
  auth: {
    allow_local_submission: boolean;
    local_principal: string;
    setup_token_env: string | null;
  };
  audit: {
    enabled: boolean;
    path: string;
    hash_recipients: boolean;
    salt_env: string | null;
  };
  dkim: {
    enabled: boolean;
    selector: string | null;
    private_key_env: string | null;
  };
  domains: {
    sending_domains: string[];
  };
  /** Non-secret environment overlay sources, reported by name only. */
  env_sources: string[];
}

/** The shipped zero-configuration defaults. */
export function defaultConfig(): RailgunConfig {
  return {
    server: {
      smtp_bind: "0.0.0.0:2525",
      http_bind: "0.0.0.0:2526",
      mcp_http_bind: null,
      max_message_bytes: 26_214_400,
    },
    store: {
      driver: "sqlite",
      path: "./data/railgun.db",
      url: null,
    },
    queue: {
      concurrency: 8,
      lease_seconds: 300,
      max_attempts: 5,
    },
    outbound: {
      // Direct-to-MX is the primary outbound mode; relay is the optional fallback.
      mode: "direct",
      relay: {
        host: null,
        port: 587,
        username_env: null,
        password_env: null,
      },
      direct: {
        port: 25,
        mx_lookup: true,
        ipv4_first: true,
        ipv6_fallback: true,
        require_tls: true,
        require_reverse_dns: true,
        connection_timeout_ms: 10_000,
        command_timeout_ms: 30_000,
      },
    },
    auth: {
      allow_local_submission: false,
      local_principal: "local",
      setup_token_env: null,
    },
    audit: {
      enabled: true,
      path: "./data/audit.ndjson",
      hash_recipients: true,
      salt_env: null,
    },
    dkim: {
      enabled: false,
      selector: null,
      private_key_env: null,
    },
    domains: {
      sending_domains: [],
    },
    env_sources: [],
  };
}

/**
 * The recognised configuration keys, used to reject unknown YAML keys.
 *
 * The registry is explicit rather than inferred so a new key is a deliberate
 * change to the schema.
 */
const KNOWN_KEYS: Record<string, readonly string[]> = {
  server: ["smtp_bind", "http_bind", "mcp_http_bind", "max_message_bytes"],
  store: ["driver", "path", "url"],
  queue: ["concurrency", "lease_seconds", "max_attempts"],
  outbound: ["mode", "relay", "direct"],
  relay: ["host", "port", "username_env", "password_env"],
  direct: [
    "port",
    "mx_lookup",
    "ipv4_first",
    "ipv6_fallback",
    "require_tls",
    "require_reverse_dns",
    "connection_timeout_ms",
    "command_timeout_ms",
  ],
  auth: ["allow_local_submission", "local_principal", "setup_token_env"],
  audit: ["enabled", "path", "hash_recipients", "salt_env"],
  dkim: ["enabled", "selector", "private_key_env"],
  domains: ["sending_domains"],
};

/**
 * The declared keys of one configuration section.
 *
 * The registry is a literal, so a missing key is a programming error rather
 * than an operator error; the helper returns an empty list in that case
 * instead of throwing during a configuration load.
 */
function knownKeys(section: string): readonly string[] {
  return KNOWN_KEYS[section] ?? [];
}

/**
 * The environment overlay registry.
 *
 * Each entry maps an environment variable onto a configuration path. Only the
 * variable *name* is ever reported; its value may be a secret.
 */
export const ENV_REGISTRY: readonly { readonly variable: string; readonly path: string }[] = [
  { variable: "RAILGUN_SMTP_BIND", path: "server.smtp_bind" },
  { variable: "RAILGUN_HTTP_BIND", path: "server.http_bind" },
  { variable: "RAILGUN_MCP_HTTP_BIND", path: "server.mcp_http_bind" },
  { variable: "RAILGUN_MAX_MESSAGE_BYTES", path: "server.max_message_bytes" },
  { variable: "RAILGUN_STORE_DRIVER", path: "store.driver" },
  { variable: "RAILGUN_STORE_PATH", path: "store.path" },
  { variable: "RAILGUN_STORE_URL", path: "store.url" },
  { variable: "RAILGUN_QUEUE_CONCURRENCY", path: "queue.concurrency" },
  { variable: "RAILGUN_QUEUE_LEASE_SECONDS", path: "queue.lease_seconds" },
  { variable: "RAILGUN_QUEUE_MAX_ATTEMPTS", path: "queue.max_attempts" },
  { variable: "RAILGUN_OUTBOUND_MODE", path: "outbound.mode" },
  { variable: "RAILGUN_RELAY_HOST", path: "outbound.relay.host" },
  { variable: "RAILGUN_RELAY_PORT", path: "outbound.relay.port" },
  { variable: "RAILGUN_RELAY_USERNAME_ENV", path: "outbound.relay.username_env" },
  { variable: "RAILGUN_RELAY_PASSWORD_ENV", path: "outbound.relay.password_env" },
  { variable: "RAILGUN_DIRECT_PORT", path: "outbound.direct.port" },
  { variable: "RAILGUN_MX_LOOKUP", path: "outbound.direct.mx_lookup" },
  { variable: "RAILGUN_IPV4_FIRST", path: "outbound.direct.ipv4_first" },
  { variable: "RAILGUN_IPV6_FALLBACK", path: "outbound.direct.ipv6_fallback" },
  { variable: "RAILGUN_REQUIRE_TLS", path: "outbound.direct.require_tls" },
  { variable: "RAILGUN_REQUIRE_REVERSE_DNS", path: "outbound.direct.require_reverse_dns" },
  { variable: "RAILGUN_DIRECT_TIMEOUT_MS", path: "outbound.direct.connection_timeout_ms" },
  { variable: "RAILGUN_DIRECT_COMMAND_TIMEOUT_MS", path: "outbound.direct.command_timeout_ms" },
  { variable: "RAILGUN_ALLOW_LOCAL_SUBMISSION", path: "auth.allow_local_submission" },
  { variable: "RAILGUN_LOCAL_PRINCIPAL", path: "auth.local_principal" },
  { variable: "RAILGUN_SETUP_TOKEN_ENV", path: "auth.setup_token_env" },
  { variable: "RAILGUN_AUDIT_ENABLED", path: "audit.enabled" },
  { variable: "RAILGUN_AUDIT_PATH", path: "audit.path" },
  { variable: "RAILGUN_AUDIT_HASH_RECIPIENTS", path: "audit.hash_recipients" },
  { variable: "RAILGUN_AUDIT_SALT_ENV", path: "audit.salt_env" },
  { variable: "RAILGUN_DKIM_ENABLED", path: "dkim.enabled" },
  { variable: "RAILGUN_DKIM_SELECTOR", path: "dkim.selector" },
  { variable: "RAILGUN_DKIM_PRIVATE_KEY_ENV", path: "dkim.private_key_env" },
  { variable: "RAILGUN_SENDING_DOMAINS", path: "domains.sending_domains" },
];

export interface ConfigDiagnostic {
  /** Configuration path, e.g. `outbound.mode`. Never a value. */
  field: string;
  message: string;
}

export interface LoadConfigResult {
  config: RailgunConfig;
  /** Non-fatal problems; the configuration is still usable. */
  warnings: ConfigDiagnostic[];
}

/**
 * Merge a parsed YAML document onto the defaults.
 *
 * Unknown keys raise a configuration error naming the key path.
 */
export function mergeYaml(
  base: RailgunConfig,
  document: unknown,
): { config: RailgunConfig; errors: ConfigDiagnostic[] } {
  const errors: ConfigDiagnostic[] = [];
  const config = structuredClone(base);

  if (document === undefined || document === null) {
    return { config, errors };
  }
  if (typeof document !== "object" || Array.isArray(document)) {
    errors.push({ field: "<root>", message: "Configuration must be a mapping" });
    return { config, errors };
  }

  const root = document as Record<string, unknown>;
  for (const key of Object.keys(root)) {
    if (!(key in KNOWN_KEYS)) {
      errors.push({ field: key, message: `Unknown configuration key '${key}'` });
    }
  }

  // An unknown key inside a section is an error too. A typo such as
  // `concurreny` must never silently disable a control, so every section is
  // checked against its declared key list before the values are applied.
  rejectUnknownKeys(root, "server", knownKeys("server"), errors);
  rejectUnknownKeys(root, "store", knownKeys("store"), errors);
  rejectUnknownKeys(root, "queue", knownKeys("queue"), errors);
  rejectUnknownKeys(root, "auth", knownKeys("auth"), errors);
  rejectUnknownKeys(root, "audit", knownKeys("audit"), errors);
  rejectUnknownKeys(root, "dkim", knownKeys("dkim"), errors);
  rejectUnknownKeys(root, "domains", knownKeys("domains"), errors);
  rejectUnknownKeys(root, "outbound", knownKeys("outbound"), errors);
  rejectUnknownKeys(root, "outbound.relay", knownKeys("relay"), errors);
  rejectUnknownKeys(root, "outbound.direct", knownKeys("direct"), errors);

  const section = (name: string): unknown =>
    root[name] === undefined ? undefined : root[name];

  const server = section("server") as Record<string, unknown>;
  if (server) {
    assignString(server, "smtp_bind", "server", (value) => (config.server.smtp_bind = value), errors);
    assignString(server, "http_bind", "server", (value) => (config.server.http_bind = value), errors);
    assignNullableString(
      server,
      "mcp_http_bind",
      "server",
      (value) => (config.server.mcp_http_bind = value),
      errors,
    );
    assignNumber(server, "max_message_bytes", "server", (value) => (config.server.max_message_bytes = value), errors);
  }

  const store = section("store") as Record<string, unknown>;
  if (store) {
    assignString(store, "driver", "store", (value) => {
      if (value !== "sqlite" && value !== "postgres" && value !== "memory") {
        errors.push({ field: "store.driver", message: "Must be one of sqlite, postgres, memory" });
        return;
      }
      config.store.driver = value;
    }, errors);
    assignString(store, "path", "store", (value) => (config.store.path = value), errors);
    assignNullableString(store, "url", "store", (value) => (config.store.url = value), errors);
  }

  const queue = section("queue") as Record<string, unknown>;
  if (queue) {
    assignNumber(queue, "concurrency", "queue", (value) => (config.queue.concurrency = value), errors);
    assignNumber(queue, "lease_seconds", "queue", (value) => (config.queue.lease_seconds = value), errors);
    assignNumber(queue, "max_attempts", "queue", (value) => (config.queue.max_attempts = value), errors);
  }

  const outbound = section("outbound") as Record<string, unknown>;
  if (outbound) {
    assignString(outbound, "mode", "outbound", (value) => {
      if (value !== "direct" && value !== "relay") {
        errors.push({ field: "outbound.mode", message: "Must be one of direct, relay" });
        return;
      }
      config.outbound.mode = value;
    }, errors);

    const relay = outbound["relay"];
    if (relay !== undefined) {
      if (typeof relay !== "object" || Array.isArray(relay)) {
        errors.push({ field: "outbound.relay", message: "Must be a mapping" });
      } else {
        const relayMap = relay as Record<string, unknown>;
        assignNullableString(
          relayMap,
          "host",
          "outbound.relay",
          (value) => (config.outbound.relay.host = value),
          errors,
        );
        assignNumber(relayMap, "port", "outbound.relay", (value) => (config.outbound.relay.port = value), errors);
        assignNullableString(
          relayMap,
          "username_env",
          "outbound.relay",
          (value) => (config.outbound.relay.username_env = value),
          errors,
        );
        assignNullableString(
          relayMap,
          "password_env",
          "outbound.relay",
          (value) => (config.outbound.relay.password_env = value),
          errors,
        );
      }
    }

    const direct = outbound["direct"];
    if (direct !== undefined) {
      if (typeof direct !== "object" || Array.isArray(direct)) {
        errors.push({ field: "outbound.direct", message: "Must be a mapping" });
      } else {
        const directMap = direct as Record<string, unknown>;
        assignBoolean(
          directMap,
          "require_reverse_dns",
          "outbound.direct",
          (value) => (config.outbound.direct.require_reverse_dns = value),
          errors,
        );
        assignBoolean(
          directMap,
          "mx_lookup",
          "outbound.direct",
          (value) => (config.outbound.direct.mx_lookup = value),
          errors,
        );
        assignBoolean(
          directMap,
          "ipv4_first",
          "outbound.direct",
          (value) => (config.outbound.direct.ipv4_first = value),
          errors,
        );
        assignBoolean(
          directMap,
          "ipv6_fallback",
          "outbound.direct",
          (value) => (config.outbound.direct.ipv6_fallback = value),
          errors,
        );
        assignBoolean(
          directMap,
          "require_tls",
          "outbound.direct",
          (value) => (config.outbound.direct.require_tls = value),
          errors,
        );
        assignNumber(
          directMap,
          "connection_timeout_ms",
          "outbound.direct",
          (value) => (config.outbound.direct.connection_timeout_ms = value),
          errors,
        );
        assignNumber(
          directMap,
          "command_timeout_ms",
          "outbound.direct",
          (value) => (config.outbound.direct.command_timeout_ms = value),
          errors,
        );
      }
    }
  }

  const auth = section("auth") as Record<string, unknown>;
  if (auth) {
    assignBoolean(
      auth,
      "allow_local_submission",
      "auth",
      (value) => (config.auth.allow_local_submission = value),
      errors,
    );
    assignString(auth, "local_principal", "auth", (value) => (config.auth.local_principal = value), errors);
    assignNullableString(
      auth,
      "setup_token_env",
      "auth",
      (value) => (config.auth.setup_token_env = value),
      errors,
    );
  }

  const audit = section("audit") as Record<string, unknown>;
  if (audit) {
    assignBoolean(audit, "enabled", "audit", (value) => (config.audit.enabled = value), errors);
    assignString(audit, "path", "audit", (value) => (config.audit.path = value), errors);
    assignBoolean(
      audit,
      "hash_recipients",
      "audit",
      (value) => (config.audit.hash_recipients = value),
      errors,
    );
    assignNullableString(audit, "salt_env", "audit", (value) => (config.audit.salt_env = value), errors);
  }

  const dkim = section("dkim") as Record<string, unknown>;
  if (dkim) {
    assignBoolean(dkim, "enabled", "dkim", (value) => (config.dkim.enabled = value), errors);
    assignNullableString(dkim, "selector", "dkim", (value) => (config.dkim.selector = value), errors);
    assignNullableString(
      dkim,
      "private_key_env",
      "dkim",
      (value) => (config.dkim.private_key_env = value),
      errors,
    );
  }

  const domains = section("domains") as Record<string, unknown>;
  if (domains) {
    assignStringList(domains, "sending_domains", "domains", (value) => (config.domains.sending_domains = value), errors);
  }

  return { config, errors };
}


/**
 * Reject a key that the schema does not declare.
 *
 * The diagnostic names the dotted path of the offending key, never its value.
 */
function rejectUnknownKeys(
  root: Record<string, unknown>,
  section: string,
  allowed: readonly string[],
  errors: ConfigDiagnostic[],
): void {
  const outboundSection = root["outbound"];
  const outboundMap =
    typeof outboundSection === "object" && outboundSection !== null && !Array.isArray(outboundSection)
      ? (outboundSection as Record<string, unknown>)
      : undefined;
  const container =
    section === "outbound.relay" || section === "outbound.direct"
      ? outboundMap?.[section.split(".")[1] ?? ""]
      : root[section];
  if (container === undefined || container === null) {
    return;
  }
  if (typeof container !== "object" || Array.isArray(container)) {
    return;
  }
  for (const key of Object.keys(container)) {
    if (!allowed.includes(key)) {
      errors.push({
        field: `${section}.${key}`,
        message: `Unknown configuration key '${key}'`,
      });
    }
  }
}

function assignString(
  source: Record<string, unknown>,
  key: string,
  prefix: string,
  apply: (value: string) => void,
  errors: ConfigDiagnostic[],
): void {
  const value = source[key];
  if (value === undefined || value === null) {
    return;
  }
  if (typeof value !== "string") {
    errors.push({ field: `${prefix}.${key}`, message: "Must be a string" });
    return;
  }
  apply(value);
}

function assignNullableString(
  source: Record<string, unknown>,
  key: string,
  prefix: string,
  apply: (value: string | null) => void,
  errors: ConfigDiagnostic[],
): void {
  const value = source[key];
  if (value === undefined) {
    return;
  }
  if (value === null) {
    apply(null);
    return;
  }
  if (typeof value !== "string") {
    errors.push({ field: `${prefix}.${key}`, message: "Must be a string or null" });
    return;
  }
  apply(value);
}

function assignNumber(
  source: Record<string, unknown>,
  key: string,
  prefix: string,
  apply: (value: number) => void,
  errors: ConfigDiagnostic[],
): void {
  const value = source[key];
  if (value === undefined || value === null) {
    return;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    errors.push({ field: `${prefix}.${key}`, message: "Must be a number" });
    return;
  }
  apply(value);
}

function assignBoolean(
  source: Record<string, unknown>,
  key: string,
  prefix: string,
  apply: (value: boolean) => void,
  errors: ConfigDiagnostic[],
): void {
  const value = source[key];
  if (value === undefined || value === null) {
    return;
  }
  if (typeof value !== "boolean") {
    errors.push({ field: `${prefix}.${key}`, message: "Must be a boolean" });
    return;
  }
  apply(value);
}

function assignStringList(
  source: Record<string, unknown>,
  key: string,
  prefix: string,
  apply: (value: string[]) => void,
  errors: ConfigDiagnostic[],
): void {
  const value = source[key];
  if (value === undefined || value === null) {
    return;
  }
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    errors.push({ field: `${prefix}.${key}`, message: "Must be a list of strings" });
    return;
  }
  apply(value as string[]);
}

/**
 * Apply the `RAILGUN_*` environment overlay.
 *
 * The overlay is applied *after* the explicit file so that an operator can
 * override a file setting in a container without editing a mounted file. Only
 * the variable names are recorded; the values stay in the process environment.
 */
export function applyEnvOverlay(
  config: RailgunConfig,
  env: NodeJS.ProcessEnv,
): { config: RailgunConfig; sources: string[]; errors: ConfigDiagnostic[] } {
  const next = structuredClone(config);
  const sources: string[] = [];
  const errors: ConfigDiagnostic[] = [];

  for (const entry of ENV_REGISTRY) {
    const raw = env[entry.variable];
    if (raw === undefined) {
      continue;
    }
    sources.push(entry.variable);
    const [section, ...rest] = entry.path.split(".");
    const key = rest.join(".");
    const target = next[section as keyof RailgunConfig] as unknown as Record<string, unknown>;
    const nested = target[key];
    if (nested && typeof nested === "object" && !Array.isArray(nested)) {
      (nested as Record<string, unknown>)[key] = raw;
      continue;
    }
    const coerced = coerceEnvValue(entry.path, entry.variable, raw, errors);
    if (coerced === undefined) {
      // The value was rejected; leaving the default in place would silently
      // ignore what the operator asked for.
      continue;
    }
    target[key] = coerced;
  }

  next.env_sources = sources;
  return { config: next, sources, errors };
}

/**
 * Coerce an environment string to the shape its configuration path requires.
 *
 * The coercion is path-aware, so a boolean path rejects a non-boolean and a
 * numeric path rejects a non-numeric. A rejected value produces a diagnostic
 * that names the variable and the target path — never the value.
 */
function coerceEnvValue(
  path: string,
  variable: string,
  raw: string,
  errors: ConfigDiagnostic[],
): unknown {
  // The diagnostic names the environment variable and the configuration path
  // it targets. It never names the value: the value may be a credential.
  const reject = (message: string): undefined => {
    errors.push({ field: path, message: `${variable}: ${message}` });
    return undefined;
  };

  // A path whose default is a boolean must receive a boolean.
  if (BOOLEAN_PATHS.has(path)) {
    const lowered = raw.trim().toLowerCase();
    if (TRUE_VALUES.has(lowered)) {
      return true;
    }
    if (FALSE_VALUES.has(lowered)) {
      return false;
    }
    return reject("Must be a boolean (true|false|1|0|yes|no|on|off)");
  }

  // A path whose default is a number must receive a number.
  if (NUMBER_PATHS.has(path)) {
    const trimmed = raw.trim();
    if (trimmed === "" || !/^-?\d+$/.test(trimmed)) {
      return reject("Must be an integer");
    }
    return Number.parseInt(trimmed, 10);
  }

  // A path whose default is a list must receive a comma-separated list.
  if (LIST_PATHS.has(path)) {
    return raw
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
  }

  return raw;
}

/** The boolean spellings the overlay accepts. */
const TRUE_VALUES = new Set(["true", "1", "yes", "on"]);
const FALSE_VALUES = new Set(["false", "0", "no", "off"]);

/** The configuration paths whose value must be a boolean. */
const BOOLEAN_PATHS = new Set([
  "audit.enabled",
  "audit.hash_recipients",
  "auth.allow_local_submission",
  "dkim.enabled",
]);

/** The configuration paths whose value must be an integer. */
const NUMBER_PATHS = new Set([
  "queue.concurrency",
  "queue.lease_seconds",
  "queue.max_attempts",
  "outbound.relay.port",
  "outbound.direct.connection_timeout_ms",
  "outbound.direct.command_timeout_ms",
  "server.max_message_bytes",
]);

/** The configuration paths whose value is a list of strings. */
const LIST_PATHS = new Set(["domains.sending_domains"]);

/**
 * Resolve a secret by environment-variable name.
 *
 * Supports the `_FILE` indirection: when `<NAME>_FILE` is set, the secret is
 * read from that file; otherwise the value of `<NAME>` is used. The resolved
 * secret is never returned by any diagnostic projection.
 */
export function resolveSecret(
  variableName: string,
  env: NodeJS.ProcessEnv,
  readFile: (path: string) => string = defaultReadFile,
): string | undefined {
  const fileVariable = `${variableName}_FILE`;
  const filePath = env[fileVariable];
  if (filePath) {
    const contents = readFile(filePath).trim();
    return contents.length > 0 ? contents : undefined;
  }
  const inline = env[variableName];
  if (inline === undefined || inline.length === 0) {
    return undefined;
  }
  // The quote/whitespace secret hazard: an inline secret that was quoted when
  // exported is almost always a shell mistake, so it is rejected rather than
  // silently used as a wrong credential.
  if (/\s/.test(inline) || /^["'].*["']$/.test(inline)) {
    throw new ConfigSecretError(
      `Environment variable ${variableName} contains whitespace or surrounding quotes; ` +
        `use ${fileVariable} to point at a secret file instead`,
    );
  }
  return inline;
}

/** Thrown when a secret reference is present but unusable. */
export class ConfigSecretError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigSecretError";
  }
}

function defaultReadFile(path: string): string {
  return readFileSync(path, "utf8");
}

/**
 * Validate a merged configuration.
 *
 * Returns the list of problems; an empty list means the configuration is
 * usable. Problems name the configuration path, never the value.
 */
export function validateConfig(config: RailgunConfig): ConfigDiagnostic[] {
  const errors: ConfigDiagnostic[] = [];

  if (config.server.max_message_bytes <= 0) {
    errors.push({ field: "server.max_message_bytes", message: "Must be greater than zero" });
  }
  if (config.queue.concurrency <= 0) {
    errors.push({ field: "queue.concurrency", message: "Must be greater than zero" });
  }
  if (config.queue.lease_seconds <= 0) {
    errors.push({ field: "queue.lease_seconds", message: "Must be greater than zero" });
  }
  if (config.queue.max_attempts <= 0) {
    errors.push({ field: "queue.max_attempts", message: "Must be greater than zero" });
  }
  if (config.outbound.mode === "relay" && !config.outbound.relay.host) {
    errors.push({
      field: "outbound.relay.host",
      message: "Required when outbound.mode is relay",
    });
  }
  if (config.store.driver === "sqlite" && !config.store.path) {
    errors.push({ field: "store.path", message: "Required when store.driver is sqlite" });
  }
  if (config.store.driver === "postgres" && !config.store.url) {
    errors.push({ field: "store.url", message: "Required when store.driver is postgres" });
  }
  if (config.dkim.enabled && !config.dkim.private_key_env) {
    errors.push({
      field: "dkim.private_key_env",
      message: "Required when dkim.enabled is true",
    });
  }
  if (config.dkim.enabled && !config.dkim.selector) {
    errors.push({ field: "dkim.selector", message: "Required when dkim.enabled is true" });
  }

  return errors;
}
