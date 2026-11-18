// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * The standalone health server.
 *
 * The container image runs this server so the Docker `HEALTHCHECK` has a
 * stable endpoint to probe. It is deliberately tiny: it serves `/health`
 * (liveness) and `/ready` (readiness) and nothing else, so a probe can never
 * leak a credential or a message body.
 *
 * The full HTTP API is served by `railgun serve --http`; this server exists so
 * that an operator can run the health surface on its own — in a sidecar, in a
 * Kubernetes probe, or in the container image — without opening the API.
 *
 * Contract: `docs/design/481de2b7-e002-4cdc-95e0-0adc9068e2c4.md` §5.2
 * (V-REL-5 … V-REL-8).
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

/** One readiness probe. */
export interface HealthProbe {
  /** The name reported in the readiness document. */
  readonly name: string;
  /** The probe itself. A throw marks the dependency as unavailable. */
  readonly check: () => Promise<{ status: string; detail: string }> | { status: string; detail: string };
}

/** The options of the health server. */
export interface HealthServerOptions {
  /** The host to bind. Defaults to `0.0.0.0`. */
  readonly host?: string;
  /** The port to bind. `0` picks an ephemeral port. */
  readonly port?: number;
  /** The readiness probes. */
  readonly probes?: readonly HealthProbe[];
}

/** The handle of a running health server. */
export interface HealthServerHandle {
  readonly address: AddressInfo | null;
  readonly port: number;
  close(): Promise<void>;
}

/** The started-at timestamp, used for the uptime figure. */
const startedAt = Date.now();

/**
 * Start the health server.
 *
 * The server binds one listener and serves exactly two routes. Every other
 * path answers `404` with a sanitized body.
 */
export async function startHealthServer(
  options: HealthServerOptions = {},
): Promise<HealthServerHandle> {
  const host = options.host ?? "0.0.0.0";
  const port = options.port ?? 2526;
  const probes = options.probes ?? [];

  const server: Server = createServer((request, response) => {
    const path = (request.url ?? "/").split("?")[0] ?? "/";

    if (path === "/health" || path === "/healthz") {
      const body = JSON.stringify({
        status: "ok",
        ok: true,
        version: "1.0.0",
        uptime_s: Math.max(0, Math.floor((Date.now() - startedAt) / 1000)),
      });
      response.statusCode = 200;
      response.setHeader("content-type", "application/json");
      response.end(body);
      return;
    }

    if (path === "/ready" || path === "/readyz") {
      void (async () => {
        const checks: Array<{ name: string; status: string; detail: string }> = [];
        for (const probe of probes) {
          try {
            const result = await probe.check();
            checks.push({ name: probe.name, status: result.status, detail: result.detail });
          } catch {
            checks.push({ name: probe.name, status: "error", detail: "unavailable" });
          }
        }
        const ok = !checks.some((check) => check.status === "error");
        response.statusCode = ok ? 200 : 503;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ ok, status: ok ? "ok" : "error", checks }));
      })();
      return;
    }

    response.statusCode = 404;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ error: { code: "NOT_FOUND", message: "Resource not found." } }));
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const address = server.address() as AddressInfo | null;
  return {
    address,
    port: address?.port ?? port,
    async close(): Promise<void> {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections?.();
      });
    },
  };
}
