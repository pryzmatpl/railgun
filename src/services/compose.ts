// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The application-service composition root.
 *
 * One place builds the effective configuration, the operator store and the
 * operator services. Both `serve` and the local operator commands use it, so
 * local mode and HTTP mode observe the same state and the same semantics.
 */
import path from "node:path";

import { type RailgunConfig } from "../config/config.js";
import { type LoadedConfig, loadConfig } from "../config/load.js";
import {
  FileOperatorStore,
  MemoryOperatorStore,
  type OperatorStore,
  ServiceError,
} from "./operator.js";
import type { Principal } from "../domain/types.js";

/** The services the operator CLI depends on. */
export interface OperatorServices {
  readonly config: RailgunConfig;
  readonly loaded: LoadedConfig;
  readonly store: OperatorStore;
  readonly principal: Principal;
}

/** Options for building the composition root. */
export interface ComposeOptions {
  configPath?: string | undefined;
  env?: NodeJS.ProcessEnv | undefined;
  baseDir?: string | undefined;
  /** Override the principal for tests and for explicit local principal selection. */
  principal?: Principal | undefined;
  /** Override the store, for tests and for a shared remote-backed store. */
  store?: OperatorStore | undefined;
}

/**
 * Build the composition root.
 *
 * Throws {@link ConfigLoadError} when the configuration is invalid; the CLI
 * maps that onto exit code 3.
 */
export function composeServices(options: ComposeOptions = {}): OperatorServices {
  const loaded = loadConfig({
    configPath: options.configPath,
    env: options.env,
    baseDir: options.baseDir ?? process.cwd(),
  });

  const store =
    options.store ??
    buildStore(loaded.config);

  const principal = options.principal ?? resolveLocalPrincipal(loaded.config);

  return { config: loaded.config, loaded, store, principal };
}

/**
 * Build the operator store for the effective configuration.
 *
 * The local operator commands run as short-lived processes, so the store must
 * outlive the process: a file-backed store keeps the operator state next to
 * the configured database so a later invocation observes the same
 * suppressions, administrators and queue depth.
 *
 * The `memory` driver is the explicit exception: it is a test driver, so it
 * stays in memory and the operator is told the state is not durable.
 */
function buildStore(config: RailgunConfig): OperatorStore {
  const auditPath = config.audit.enabled ? config.audit.path : undefined;
  if (config.store.driver === "memory") {
    return new MemoryOperatorStore({ auditPath });
  }
  const statePath = `${config.store.path}.operator.json`;
  return new FileOperatorStore({ statePath, auditPath });
}

/**
 * Resolve the local principal.
 *
 * Local operator commands act as the configured local principal. When local
 * submission is denied, the principal still exists but carries no scopes, so
 * an administrative mutation is denied by default rather than silently
 * allowed.
 */
function resolveLocalPrincipal(config: RailgunConfig): Principal {
  const scopes = config.auth.allow_local_submission ? ["read", "admin", "send"] : ["read"];
  return {
    id: config.auth.local_principal || "local",
    tenant: "default",
    scopes,
  };
}

/** Assert that the principal holds a required scope, failing closed. */
export function requireScope(principal: Principal, scope: string): void {
  if (!principal.scopes.includes(scope)) {
    throw new ServiceError(
      "INSUFFICIENT_SCOPE",
      `The principal does not hold the '${scope}' scope`,
      { required_scope: scope },
    );
  }
}

/** The audit sink for a service call. */
export function auditRecord(
  principal: Principal,
  action: string,
  target: string | null,
  reason: string | null,
): { action: string; actor: string; tenant: string; target: string | null; reason: string | null; at: string } {
  return {
    action,
    actor: principal.id,
    tenant: principal.tenant,
    target,
    reason,
    at: new Date().toISOString(),
  };
}

/** The directory the operator data lives in, derived from the store path. */
export function dataDirectory(config: RailgunConfig): string {
  if (config.store.driver === "sqlite" && config.store.path) {
    return path.dirname(config.store.path);
  }
  return path.resolve(process.cwd(), "data");
}
