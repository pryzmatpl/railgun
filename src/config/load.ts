// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Configuration loading for the operator CLI.
 *
 * Three-layer precedence: shipped defaults → explicit `--config` YAML file →
 * `RAILGUN_*` environment overlay. A malformed or invalid configuration is a
 * configuration error (exit code 3); the CLI fails closed rather than
 * degrading to a partially-applied configuration.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";

import {
  type ConfigDiagnostic,
  type RailgunConfig,
  applyEnvOverlay,
  defaultConfig,
  mergeYaml,
  validateConfig,
} from "./config.js";

export class ConfigLoadError extends Error {
  readonly diagnostics: ConfigDiagnostic[];
  readonly code: "CONFIG_UNREADABLE" | "CONFIG_INVALID";

  constructor(
    code: "CONFIG_UNREADABLE" | "CONFIG_INVALID",
    message: string,
    diagnostics: ConfigDiagnostic[] = [],
  ) {
    super(message);
    this.name = "ConfigLoadError";
    this.code = code;
    this.diagnostics = diagnostics;
  }
}

export interface LoadConfigOptions {
  /** Explicit `--config` path. When absent, `RAILGUN_CONFIG` is consulted. */
  configPath?: string | undefined;
  env?: NodeJS.ProcessEnv | undefined;
  /** Directory that relative paths in the configuration resolve against. */
  baseDir?: string | undefined;
}

export interface LoadedConfig {
  config: RailgunConfig;
  /** Absolute path of the configuration file that was applied, if any. */
  configPath: string | undefined;
  /** Environment variable names that contributed to the overlay. */
  envSources: string[];
  /** Non-fatal diagnostics. */
  warnings: ConfigDiagnostic[];
}

/**
 * Load and validate the effective configuration.
 *
 * Throws {@link ConfigLoadError} when the file is unreadable, unparsable or
 * invalid, so the caller can map it onto exit code 3.
 */
export function loadConfig(options: LoadConfigOptions = {}): LoadedConfig {
  const env = options.env ?? process.env;
  const explicitPath = options.configPath ?? env["RAILGUN_CONFIG"];
  const warnings: ConfigDiagnostic[] = [];

  let base = defaultConfig();
  let resolvedPath: string | undefined;

  if (explicitPath) {
    resolvedPath = path.resolve(explicitPath);
    let raw: string;
    try {
      raw = readFileSync(resolvedPath, "utf8");
    } catch {
      throw new ConfigLoadError(
        "CONFIG_UNREADABLE",
        `Configuration file could not be read: ${resolvedPath}`,
        [{ field: "<config>", message: "File is not readable" }],
      );
    }

    let document: unknown;
    try {
      document = parseYaml(raw);
    } catch {
      throw new ConfigLoadError(
        "CONFIG_INVALID",
        `Configuration file is not valid YAML: ${resolvedPath}`,
        [{ field: "<config>", message: "File is not valid YAML" }],
      );
    }

    const merged = mergeYaml(base, document);
    if (merged.errors.length > 0) {
      throw new ConfigLoadError(
        "CONFIG_INVALID",
        "Configuration is invalid",
        merged.errors,
      );
    }
    base = merged.config;
  }

  const overlaid = applyEnvOverlay(base, env);
  // An environment value that could not be parsed is a configuration error:
  // the overlay must fail closed rather than leave the default in place and
  // silently ignore what the operator asked for.
  if (overlaid.errors.length > 0) {
    throw new ConfigLoadError(
      "CONFIG_INVALID",
      "Environment overlay contains an invalid value",
      overlaid.errors,
    );
  }
  const errors = validateConfig(overlaid.config);
  if (errors.length > 0) {
    throw new ConfigLoadError("CONFIG_INVALID", "Configuration is invalid", errors);
  }

  const baseDir = options.baseDir ?? process.cwd();
  const config = withResolvedPaths(overlaid.config, baseDir);

  return {
    config,
    configPath: resolvedPath,
    envSources: overlaid.sources,
    warnings,
  };
}

/**
 * Resolve relative filesystem paths against the configuration base directory.
 *
 * This keeps the store, audit and data paths stable regardless of the
 * process working directory.
 */
function withResolvedPaths(config: RailgunConfig, baseDir: string): RailgunConfig {
  const next = structuredClone(config);
  if (next.store.driver === "sqlite" && next.store.path) {
    next.store.path = path.resolve(baseDir, next.store.path);
  }
  if (next.audit.path) {
    next.audit.path = path.resolve(baseDir, next.audit.path);
  }
  return next;
}

/** Find the configuration file the operator explicitly selected, if any. */
export function selectedConfigPath(
  cliPath: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  return cliPath ?? env["RAILGUN_CONFIG"];
}
