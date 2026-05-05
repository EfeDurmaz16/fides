# Stage 1: Install dependencies
FROM node:22-alpine AS deps
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/core/package.json ./packages/core/
COPY packages/evidence/package.json ./packages/evidence/
COPY packages/runtime/package.json ./packages/runtime/
COPY packages/shared/package.json ./packages/shared/
COPY packages/sdk/package.json ./packages/sdk/
COPY services/agentd/package.json ./services/agentd/
RUN pnpm install --frozen-lockfile

# Stage 2: Build
FROM node:22-alpine AS build
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages/core/node_modules ./packages/core/node_modules
COPY --from=deps /app/packages/evidence/node_modules ./packages/evidence/node_modules
COPY --from=deps /app/packages/runtime/node_modules ./packages/runtime/node_modules
COPY --from=deps /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=deps /app/packages/sdk/node_modules ./packages/sdk/node_modules
COPY --from=deps /app/services/agentd/node_modules ./services/agentd/node_modules
COPY packages/core/ ./packages/core/
COPY packages/evidence/ ./packages/evidence/
COPY packages/runtime/ ./packages/runtime/
COPY packages/shared/ ./packages/shared/
COPY packages/sdk/ ./packages/sdk/
COPY services/agentd/ ./services/agentd/
COPY tsconfig.base.json ./
RUN cd packages/shared && pnpm build
RUN cd packages/sdk && pnpm build
RUN cd packages/core && pnpm build
RUN cd packages/evidence && pnpm build
RUN cd packages/runtime && pnpm build
RUN cd services/agentd && pnpm build

# Stage 3: Runtime
FROM node:22-alpine AS runtime
RUN addgroup -g 1001 -S fides && adduser -S fides -u 1001
WORKDIR /app
COPY --from=build /app/packages/core/dist ./packages/core/dist
COPY --from=build /app/packages/core/package.json ./packages/core/
COPY --from=build /app/packages/evidence/dist ./packages/evidence/dist
COPY --from=build /app/packages/evidence/package.json ./packages/evidence/
COPY --from=build /app/packages/runtime/dist ./packages/runtime/dist
COPY --from=build /app/packages/runtime/package.json ./packages/runtime/
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/sdk/dist ./packages/sdk/dist
COPY --from=build /app/packages/sdk/package.json ./packages/sdk/
COPY --from=build /app/services/agentd/dist ./services/agentd/dist
COPY --from=build /app/services/agentd/package.json ./services/agentd/
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/services/agentd/node_modules ./services/agentd/node_modules

USER fides
EXPOSE 7345
ENV NODE_ENV=production
ENV AGENTD_PORT=7345

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:7345/health || exit 1

CMD ["node", "services/agentd/dist/index.js"]
