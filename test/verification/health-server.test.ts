// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The standalone health server.
 *
 * The container image runs this server so the Docker `HEALTHCHECK` has a
 * stable endpoint to probe. The tests assert the liveness/readiness contract
 * and that the surface never leaks anything.
 */
import { afterEach, describe, expect, it } from "vitest";

import { startHealthServer, type HealthProbe, type HealthServerHandle } from "../../src/http/health-server.js";

/** The servers started by a test, closed after the test. */
const handles: HealthServerHandle[] = [];

afterEach(async () => {
  while (handles.length > 0) {
    const handle = handles.pop();
    await handle?.close();
  }
});

/** Start a health server on an ephemeral loopback port. */
async function start(probes: readonly HealthProbe[] = []) {
  const handle = await startHealthServer({ host: "127.0.0.1", port: 0, probes });
  handles.push(handle);
  return handle;
}

describe("the health server", () => {
  it("serves an unauthenticated liveness document", async () => {
    const handle = await start();
    const response = await fetch(`http://127.0.0.1:${handle.port}/health`);

    expect(response.status).toBe(200);
    const body = (await response.json()) as { status: string; ok: boolean };
    expect(body.status).toBe("ok");
    expect(body.ok).toBe(true);
  });

  it("serves the /healthz alias", async () => {
    const handle = await start();
    const response = await fetch(`http://127.0.0.1:${handle.port}/healthz`);
    expect(response.status).toBe(200);
  });

  it("reports the readiness checks", async () => {
    const handle = await start([
      { name: "store", check: () => ({ status: "ok", detail: "ready" }) },
    ]);
    const response = await fetch(`http://127.0.0.1:${handle.port}/ready`);

    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; checks: unknown[] };
    expect(body.ok).toBe(true);
    expect(body.checks).toHaveLength(1);
  });

  it("fails readiness when a probe throws", async () => {
    const handle = await start([
      {
        name: "store",
        check: () => {
          throw new Error("store unavailable");
        },
      },
    ]);
    const response = await fetch(`http://127.0.0.1:${handle.port}/ready`);

    expect(response.status).toBe(503);
    const body = (await response.json()) as { ok: boolean };
    expect(body.ok).toBe(false);
  });

  it("answers 404 for every other path", async () => {
    const handle = await start();
    const response = await fetch(`http://127.0.0.1:${handle.port}/v1/messages`);

    expect(response.status).toBe(404);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("NOT_FOUND");
  });

  it("never exposes a stack trace or an internal path", async () => {
    const handle = await start([
      {
        name: "store",
        check: () => {
          throw new Error("/var/lib/railgun/store.db is unavailable");
        },
      },
    ]);
    const response = await fetch(`http://127.0.0.1:${handle.port}/ready`);
    const text = await response.text();

    expect(text).not.toContain("/var/lib/railgun");
    expect(text).not.toContain("at ");
  });
});
