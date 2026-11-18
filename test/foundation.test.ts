// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Foundation acceptance tests.
 *
 * These assert the properties that make RailGun a standalone package:
 * the manifest is workspace-free, the licence hygiene holds, the container
 * assets are safe, and the configuration subsystem fails closed.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Reads a file relative to the package root. */
function read(relative: string): string {
  return readFileSync(path.join(packageRoot, relative), "utf8");
}

/** The parsed package manifest. */
const manifest = JSON.parse(read("package.json")) as Record<string, unknown>;

/** Walks a directory tree, returning every file path relative to the root. */
function walk(relative: string): string[] {
  const absolute = path.join(packageRoot, relative);
  if (!existsSync(absolute)) return [];
  const found: string[] = [];
  for (const entry of readdirSync(absolute)) {
    const full = path.join(absolute, entry);
    if (statSync(full).isDirectory()) {
      found.push(...walk(path.relative(packageRoot, full)));
    } else {
      found.push(path.relative(packageRoot, full));
    }
  }
  return found;
}

describe("package manifest", () => {
  it("is an ESM package named railgun", () => {
    expect(manifest["name"]).toBe("railgun");
    expect(manifest["type"]).toBe("module");
  });

  it("exposes the railgun binary", () => {
    const bin = manifest["bin"] as Record<string, string>;
    expect(bin["railgun"]).toBeDefined();
    expect(bin["railgun"]).toMatch(/^\.\/dist\//);
  });

  it("declares the GPL-3.0-or-later licence", () => {
    expect(manifest["license"]).toBe("GPL-3.0-or-later");
  });

  it("requires Node.js 22 or newer", () => {
    const engines = manifest["engines"] as Record<string, string>;
    expect(engines["node"]).toBe(">=22.12.0");
  });

  it("contains no monorepo workspace assumptions", () => {
    expect(manifest["workspaces"]).toBeUndefined();
    const raw = read("package.json");
    expect(raw).not.toMatch(/workspace:\*/);
    expect(raw).not.toMatch(/catalog:/);
    expect(raw).not.toMatch(/"link:/);
    expect(raw).not.toMatch(/"file:\.\./);
  });

  it("publishes an allow-list that excludes sources and tests", () => {
    const files = manifest["files"] as string[];
    expect(files).toContain("dist");
    expect(files).toContain("LICENSE");
    expect(files).toContain("README.md");
    expect(files).not.toContain("src");
    expect(files).not.toContain("test");
    expect(files).not.toContain("tests");
  });

  it("declares its runtime dependencies", () => {
    const dependencies = manifest["dependencies"] as Record<string, string>;
    expect(Object.keys(dependencies)).toContain("yaml");
  });

  it("declares the TypeScript compiler as a dev dependency", () => {
    const devDependencies = manifest["devDependencies"] as Record<string, string>;
    expect(Object.keys(devDependencies)).toContain("typescript");
  });

  it("runs the build through a script that does not depend on the shell", () => {
    const scripts = manifest["scripts"] as Record<string, string>;
    expect(scripts["build"]).toContain("build:tsc");
    expect(scripts["build:tsc"]).toContain("tsc -p tsconfig.build.json");
    // The post-build step gives the compiled entry points a shebang and the
    // executable bit, so the `railgun` bin symlink works.
    expect(scripts["build"]).toContain("scripts/postbuild.mjs");
  });

  it("does not build during npm install", () => {
    const scripts = manifest["scripts"] as Record<string, string>;
    // A `prepare` hook would run the build on `npm install`, which must not
    // require the network or a workspace root.
    expect(scripts["prepare"]).toBeUndefined();
    expect(scripts["postinstall"]).toBeUndefined();
  });
});

describe("licence hygiene", () => {
  it("ships the GPL-3.0 licence text", () => {
    const license = read("LICENSE");
    expect(license).toContain("GNU GENERAL PUBLIC LICENSE");
    expect(license).toContain("Version 3");
  });

  it("puts an SPDX header on every source file", () => {
    const offenders: string[] = [];
    for (const directory of ["src", "test", "tests", "scripts"]) {
      for (const file of walk(directory)) {
        if (!/\.(ts|mts|cts|js|mjs|cjs|ya?ml|sh)$/.test(file)) continue;
        const head = readFileSync(path.join(packageRoot, file), "utf8").slice(0, 400);
        if (!head.includes("SPDX-License-Identifier: GPL-3.0-or-later")) {
          offenders.push(file);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("passes the standalone licence checker script", () => {
    execFileSync(process.execPath, [path.join(packageRoot, "scripts/check-licence-headers.mjs")], {
      cwd: packageRoot,
      stdio: "pipe",
    });
  });
});

describe("container assets", () => {
  const dockerfile = read("Dockerfile");

  it("is a multi-stage node:22-slim build", () => {
    expect(dockerfile).toMatch(/FROM node:22-slim AS builder/);
    expect(dockerfile).toMatch(/FROM node:22-slim AS runtime/);
  });

  it("runs as a non-root user", () => {
    expect(dockerfile).toMatch(/USER railgun/);
    expect(dockerfile).toMatch(/uid 10001/);
  });

  it("declares a HEALTHCHECK that does not require a shell", () => {
    expect(dockerfile).toMatch(/HEALTHCHECK/);
    expect(dockerfile).not.toMatch(/CMD-SHELL/);
  });

  it("declares no VOLUME instruction", () => {
    // An anonymous volume shadows the operator's bind mount, so the store
    // would silently start empty.
    expect(dockerfile).not.toMatch(/^VOLUME/m);
  });

  it("exposes the default HTTP bind", () => {
    expect(dockerfile).toMatch(/EXPOSE 2526/);
  });

  it("starts the railgun health server by default", () => {
    // The container runs the standalone health server so the Docker
    // HEALTHCHECK has a stable endpoint; the full HTTP API is started
    // separately with `railgun serve --http`.
    expect(dockerfile).toMatch(/CMD \["node", "dist\/health-main\.js"\]/);
  });
});

describe("compose deployment", () => {
  const compose = read("docker-compose.yml");

  it("starts with zero configuration", () => {
    expect(compose).toMatch(/RAILGUN_OUTBOUND_MODE/);
    expect(compose).not.toMatch(/PASSWORD:\s*["'][^"'$]/);
  });

  it("uses an operator bind mount rather than an anonymous volume", () => {
    expect(compose).toMatch(/volumes:/);
    expect(compose).toMatch(/railgun-data/);
  });
});

describe("ignore files", () => {
  it("keeps local state out of git", () => {
    const gitignore = read(".gitignore");
    for (const pattern of ["node_modules/", "dist/", ".env", "data/", "*.db", "*.ndjson"]) {
      expect(gitignore).toContain(pattern);
    }
  });

  it("keeps local state and secrets out of the build context", () => {
    const dockerignore = read(".dockerignore");
    for (const pattern of ["node_modules/", "dist/", ".env", "data/", "*.ndjson"]) {
      expect(dockerignore).toContain(pattern);
    }
  });
});

describe("documentation set", () => {
  it("ships the operator documentation", () => {
    for (const file of [
      "README.md",
      "CONTRIBUTING.md",
      "CODE_OF_CONDUCT.md",
      "SECURITY.md",
      "CHANGELOG.md",
      "NOTICE",
      "docs/ARCHITECTURE.md",
      "docs/CONFIGURATION.md",
    ]) {
      expect(existsSync(path.join(packageRoot, file)), file).toBe(true);
    }
  });

  it("does not claim the implementation is Rust", () => {
    const readme = read("README.md");
    expect(readme).not.toMatch(/\bRust\b/);
    expect(readme).not.toMatch(/Cargo\.toml/);
    expect(readme).toMatch(/npm install/);
  });

  it("describes direct-to-MX as the primary outbound mode", () => {
    const readme = read("README.md");
    expect(readme).toMatch(/direct/i);
    expect(readme).toMatch(/MX/);
  });
});

describe("no credential material", () => {
  it("contains no secret-looking assignment", () => {
    const offenders: string[] = [];
    const pattern =
      /(?:password|secret|token|api[_-]?key)\s*[:=]\s*["'][^"'$\s][^"']{7,}["']/i;
    for (const file of [...walk("src"), ...walk("config"), ...walk("docs")]) {
      if (!/\.(ts|mts|js|mjs|ya?ml|md)$/.test(file)) continue;
      const content = readFileSync(path.join(packageRoot, file), "utf8");
      if (pattern.test(content)) offenders.push(file);
    }
    expect(offenders).toEqual([]);
  });
});
