# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-18

The first release of RailGun as a self-hosted, agent-first email delivery
service. This release establishes the package foundation and the
configuration contract that the delivery engine is built on.

### Added

- **Standalone TypeScript package.** RailGun installs and builds with
  `npm install && npm run build` in a clean checkout, with no monorepo root,
  no workspace protocol and no pnpm. Node.js 22.12 or newer is required.
- **`railgun` command-line binary.** The package exposes a `railgun` binary
  through `npm`, with a stable exit-code contract.
- **Configuration subsystem.** Three-layer precedence — shipped defaults, an
  optional YAML file, and a `RAILGUN_*` environment overlay. An unknown YAML
  key is an error rather than a warning, so a typo never silently disables a
  control.
- **Fail-closed startup.** An invalid configuration stops the process before
  any listener binds. There is no silent fallback to a default.
- **Secret handling.** Secrets reach RailGun through an environment variable
  or a mounted file. A resolved configuration holds a reference and a
  presence flag, never the value. A credential that arrives quote-wrapped or
  whitespace-wrapped is rejected by name rather than used.
- **`railgun doctor`.** A configuration and runtime diagnostic that prints
  one line per check and never prints a secret. It supports `--json` and
  exits non-zero when a check fails.
- **Container assets.** A multi-stage, non-root `node:22-slim` image with a
  shell-free `HEALTHCHECK`, and a compose file that starts with zero
  configuration.
- **Documentation.** A README for the TypeScript/npm/direct-MX audience, a
  full configuration reference, a security policy, a contributor guide and a
  code of conduct.

### Changed

- Outbound delivery is **direct-to-MX by default**. An operator relay is an
  explicit fallback that must be configured, not the default path.

### Licence

GPL-3.0-or-later. Every source file carries an SPDX header; the full licence
text is in `LICENSE`.

[Unreleased]: https://github.com/pryzmatpl/railgun/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pryzmatpl/railgun/releases/tag/v0.1.0
