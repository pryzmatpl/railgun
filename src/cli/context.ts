// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Shared command context.
 *
 * Every command receives the same context: the parsed global options, the
 * output channel and the selected transport. The context resolves the
 * configuration lazily, so `--help` and `--version` work without a valid
 * configuration.
 */
import type { FlagSpec } from "./args.js";
import { CliError } from "./errors.js";
import { type OutputChannel } from "./output.js";
import { ConfigLoadError, type LoadedConfig } from "../config/load.js";
import { composeServices, type OperatorServices } from "../services/compose.js";
import { FetchHttpClient, RemoteOperatorClient } from "../services/remote.js";

/** The global options every command accepts. */
export const GLOBAL_FLAGS: readonly FlagSpec[] = [
  {
    name: "config",
    type: "string",
    short: "c",
    description: "Path to the YAML configuration file",
    placeholder: "<path>",
  },
  {
    name: "json",
    type: "boolean",
    description: "Emit exactly one machine-readable JSON document on stdout",
  },
  {
    name: "url",
    type: "string",
    description: "Operate against a remote RailGun HTTP API instead of the local store",
    placeholder: "<url>",
  },
  {
    name: "api-key",
    type: "string",
    description: "Credential for a remote API (prefer RAILGUN_API_KEY)",
    placeholder: "<key>",
  },
  {
    name: "timeout",
    type: "string",
    description: "Bound the command with a duration such as 30s or 5m",
    placeholder: "<duration>",
  },
  {
    name: "help",
    type: "boolean",
    short: "h",
    description: "Show help for the command",
  },
  {
    name: "version",
    type: "boolean",
    description: "Show the RailGun version",
  },
];

/** The resolved global options. */
export interface GlobalOptions {
  configPath: string | undefined;
  json: boolean;
  url: string | undefined;
  apiKey: string | undefined;
  timeoutMs: number;
  help: boolean;
  version: boolean;
}

/** The environment a command runs in. */
export interface CommandContext {
  readonly options: GlobalOptions;
  readonly channel: OutputChannel;
  readonly env: NodeJS.ProcessEnv;
  /** Compose the local application services. */
  services(): OperatorServices;
  /** The remote client, when `--url` was supplied. */
  remote(): RemoteOperatorClient;
  /** True when the command is in remote mode. */
  readonly isRemote: boolean;
}

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Parse the global options.
 *
 * Global options may appear before or after the command word, so the whole
 * argv slice is scanned and every recognised global flag is collected wherever
 * it appears. A flag the global parser does not know is left untouched for
 * the command parser: `--reason`, for example, belongs to `suppress add`, and
 * rejecting it here would make every command-specific flag unusable.
 */
export function parseGlobalOptions(argv: readonly string[]): {
  global: GlobalOptions;
  rest: string[];
} {
  const known = new Set<string>(GLOBAL_FLAGS.map((flag) => flag.name));
  const knownShort = new Set<string>(
    GLOBAL_FLAGS.filter((flag) => flag.short).map((flag) => flag.short!),
  );

  const flags = new Map<string, string | boolean>();
  const rest: string[] = [];

  let index = 0;
  let onlyPositionals = false;
  while (index < argv.length) {
    const token = argv[index] ?? "";
    index += 1;

    if (onlyPositionals) {
      rest.push(token);
      continue;
    }
    if (token === "--") {
      onlyPositionals = true;
      rest.push(token);
      continue;
    }

    if (token.startsWith("--")) {
      const body = token.slice(2);
      const equals = body.indexOf("=");
      const name = equals === -1 ? body : body.slice(0, equals);
      if (!known.has(name)) {
        // Not a global flag: hand it to the command parser untouched.
        rest.push(token);
        continue;
      }
      const spec = GLOBAL_FLAGS.find((flag) => flag.name === name)!;
      if (spec.type === "boolean") {
        flags.set(name, true);
        continue;
      }
      if (equals !== -1) {
        flags.set(name, body.slice(equals + 1));
        continue;
      }
      const next = argv[index];
      if (next === undefined) {
        throw CliError.usage(`Option '--${name}' requires a value`);
      }
      index += 1;
      flags.set(name, next);
      continue;
    }

    if (token.startsWith("-") && token.length > 1 && token !== "-") {
      const short = token.slice(1);
      if (!knownShort.has(short)) {
        rest.push(token);
        continue;
      }
      const spec = GLOBAL_FLAGS.find((flag) => flag.short === short)!;
      if (spec.type === "boolean") {
        flags.set(spec.name, true);
        continue;
      }
      const next = argv[index];
      if (next === undefined) {
        throw CliError.usage(`Option '-${short}' requires a value`);
      }
      index += 1;
      flags.set(spec.name, next);
      continue;
    }

    rest.push(token);
  }

  const rawTimeout = flags.get("timeout");
  const timeoutMs = typeof rawTimeout === "string" ? parseDuration(rawTimeout) : DEFAULT_TIMEOUT_MS;

  return {
    global: {
      configPath: typeof flags.get("config") === "string" ? (flags.get("config") as string) : undefined,
      json: flags.get("json") === true,
      url: typeof flags.get("url") === "string" ? (flags.get("url") as string) : undefined,
      apiKey: resolveApiKey(flags.get("api-key")),
      timeoutMs,
      help: flags.get("help") === true,
      version: flags.get("version") === true,
    },
    rest,
  };
}

/**
 * Resolve the API key.
 *
 * The flag is accepted for transports that need it, but the environment
 * variable is preferred because a command-line argument is visible in the
 * process list.
 */
function resolveApiKey(flagValue: unknown): string | undefined {
  const fromEnv = process.env["RAILGUN_API_KEY"];
  if (typeof flagValue === "string" && flagValue.length > 0) {
    return flagValue;
  }
  return fromEnv && fromEnv.length > 0 ? fromEnv : undefined;
}

/** Parse a duration such as `30s`, `5m`, `1h` or a bare second count. */
export function parseDuration(raw: string): number {
  const match = /^(\d+)(ms|s|m|h)?$/.exec(raw.trim());
  if (!match) {
    throw CliError.usage(`Invalid duration '${raw}': expected a value such as 30s, 5m or 1h`);
  }
  const amount = Number.parseInt(match[1] ?? "0", 10);
  const unit = match[2] ?? "s";
  const factor = unit === "ms" ? 1 : unit === "s" ? 1000 : unit === "m" ? 60_000 : 3_600_000;
  if (amount <= 0) {
    throw CliError.usage(`Invalid duration '${raw}': must be greater than zero`);
  }
  return amount * factor;
}

/**
 * Build the command context.
 *
 * Configuration is loaded lazily so that `--help` and `--version` succeed
 * even when the configuration is invalid.
 */
export function createContext(options: GlobalOptions, channel: OutputChannel): CommandContext {
  let servicesCache: OperatorServices | undefined;

  return {
    options,
    channel,
    env: process.env,
    get isRemote(): boolean {
      return options.url !== undefined;
    },
    services(): OperatorServices {
      if (!servicesCache) {
        try {
          servicesCache = composeServices({
            configPath: options.configPath,
            env: process.env,
          });
        } catch (cause) {
          if (cause instanceof ConfigLoadError) {
            throw new CliError({
              code: cause.code,
              message: cause.message,
              exitCode: 3,
              details:
                cause.diagnostics.length > 0
                  ? { fields: cause.diagnostics.map((diagnostic) => diagnostic.field) }
                  : undefined,
            });
          }
          throw cause;
        }
      }
      return servicesCache;
    },
    remote(): RemoteOperatorClient {
      if (!options.url) {
        throw CliError.usage("No remote API URL was configured");
      }
      return new RemoteOperatorClient(
        new FetchHttpClient({
          baseUrl: options.url,
          apiKey: options.apiKey,
          timeoutMs: options.timeoutMs,
        }),
      );
    },
  };
}

/** Re-export for command modules that need the loaded configuration type. */
export type { LoadedConfig };
