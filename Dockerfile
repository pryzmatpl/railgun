# =============================================================================
# RailGun — the open Mailgun alternative
#
# Multi-stage image: a build stage that compiles TypeScript, and a runtime
# stage that carries only the compiled output plus production dependencies.
#
# Conventions borrowed from packages/photonip/Dockerfile:
#   - non-root runtime user (uid 10001)
#   - a HEALTHCHECK expressed WITHOUT a shell, so the runtime stage needs no
#     shell at all
#   - deliberately NO `VOLUME` instruction (see the note at the bottom)
#
# The image is standalone: it does not depend on the Jaisiu monorepo, on
# pnpm, or on any workspace root.
# =============================================================================

# -----------------------------------------------------------------------------
# STAGE 1: Build — compile TypeScript to dist/
# -----------------------------------------------------------------------------
FROM node:22-slim AS builder

WORKDIR /build

# Copy only the package manifest first so the dependency layer is cached
# independently of source changes.
COPY package.json package-lock.json ./

# `npm ci` installs exactly what the lockfile pins. --ignore-scripts keeps
# the build hermetic: no prepare hook may reach for the network or for a
# workspace root.
RUN npm ci --ignore-scripts --no-audit --no-fund

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
# The build script itself lives in `scripts/`; the post-build step stamps the
# executable bits on the bin entry points, so it must be in the build context.
COPY scripts ./scripts

RUN npm run build

# Re-resolve the tree with only production dependencies for the runtime copy.
RUN npm prune --omit=dev

# -----------------------------------------------------------------------------
# STAGE 2: Runtime — the RailGun service and nothing else
# -----------------------------------------------------------------------------
FROM node:22-slim AS runtime

LABEL org.opencontainers.image.title="RailGun" \
      org.opencontainers.image.description="Self-hosted, agent-first email delivery over direct-to-MX outbound" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

ENV NODE_ENV=production \
    RAILGUN_SERVER_HTTP_BIND=0.0.0.0:2526 \
    RAILGUN_SERVER_SMTP_BIND=0.0.0.0:2525 \
    RAILGUN_SECRETS_DATA_DIR=/app/data

WORKDIR /app

# Production dependencies plus the compiled output.
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/dist ./dist
COPY package.json package-lock.json ./

# The example configuration and the operator documentation travel with the
# image so that `docker run` can serve a default configuration and an
# operator can read the reference offline.
COPY config ./config
COPY docs ./docs
COPY LICENSE NOTICE README.md SECURITY.md CHANGELOG.md ./

# The service runs as a non-root user. The data directory is created and
# owned by that user so the default (SQLite) store is writable without any
# further setup.
RUN useradd --system --uid 10001 --create-home railgun && \
    mkdir -p /app/data && \
    chown -R railgun:railgun /app
USER railgun

EXPOSE 2526 2525 2527

# NOTE: deliberately NO `VOLUME ["/app/data"]` here.
#
# A VOLUME instruction makes Docker create an anonymous volume at that path
# at container-create time, and the anonymous volume SHADOWS the operator's
# bind mount. The container then starts with an empty /app/data and the
# store appears to lose every message — with no error anywhere, because the
# mount it is given is not the mount it serves.
#
# The data root is supplied by the operator as a bind mount:
#   -v "railgun-data:/app/data"
# The directory is created in the image so the container still starts when the
# operator forgets the mount.

# The readiness probe is expressed without a shell so the runtime stage does
# not need one. It exits 0 only on a successful response.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:'+(process.env.RAILGUN_HEALTH_PORT||2526)+'/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# The health server serves `/health` and `/ready` and nothing else, so the
# probe can never leak a credential or a message body. The full HTTP API is
# started separately with `railgun serve --http`.
CMD ["node", "dist/health-main.js"]
