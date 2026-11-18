#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors
//
// RailGun — the open Mailgun alternative.
// This file is part of RailGun and is licensed under the GNU General Public
// License, version 3 or later (see the LICENSE file at the package root).

/**
 * The standalone health-server entry point.
 *
 * The container image runs this process so the Docker `HEALTHCHECK` has a
 * stable endpoint to probe. It serves `/health` and `/ready` and nothing else.
 *
 * The bind address comes from the configuration (`server.http_bind`) or from
 * `RAILGUN_HEALTH_BIND`; the port may be overridden with
 * `RAILGUN_HEALTH_PORT`, which the container health check also reads.
 */

import { loadConfig } from "./config/load.js";
import { startHealthServer, type HealthProbe } from "./http/health-server.js";

const loaded = loadConfig({ env: process.env });

/** The probes the readiness endpoint evaluates. */
const probes: HealthProbe[] = [
  {
    name: "configuration",
    check: () => ({
      status: "ok",
      detail: loaded.configPath ? `loaded from ${loaded.configPath}` : "loaded from shipped defaults",
    }),
  },
  {
    name: "store",
    check: () => ({ status: "ok", detail: `${loaded.config.store.driver} store configured` }),
  },
  {
    name: "queue",
    check: () => ({
      status: "ok",
      detail: `concurrency=${loaded.config.queue.concurrency} max_attempts=${loaded.config.queue.max_attempts}`,
    }),
  },
];

/** The bind address, honouring the health-specific override. */
const bind = process.env.RAILGUN_HEALTH_BIND ?? loaded.config.server.http_bind;
const [host, portText] = bind.includes(":") ? bind.split(":") : [bind, "2526"];
const port = Number.parseInt(process.env.RAILGUN_HEALTH_PORT ?? portText ?? "2526", 10);

const handle = await startHealthServer({ host, port, probes });
process.stderr.write(`railgun health server listening on ${host}:${handle.port}\n`);

const shutdown = (): void => {
  void handle.close().then(() => process.exit(0));
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
