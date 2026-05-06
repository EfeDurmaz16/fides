# Stage 1: Install dependencies
FROM node:22-alpine AS deps
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/core/package.json ./packages/core/
COPY packages/shared/package.json ./packages/shared/
COPY services/platform-api/package.json ./services/platform-api/
RUN pnpm install --frozen-lockfile

# Stage 2: Build
FROM node:22-alpine AS build
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages/core/node_modules ./packages/core/node_modules
COPY --from=deps /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=deps /app/services/platform-api/node_modules ./services/platform-api/node_modules
COPY packages/core/ ./packages/core/
COPY packages/shared/ ./packages/shared/
COPY services/platform-api/ ./services/platform-api/
COPY tsconfig.base.json ./
RUN cd packages/shared && pnpm build
RUN cd packages/core && pnpm build
RUN cd services/platform-api && pnpm build

# Stage 3: Runtime
FROM node:22-alpine AS runtime
RUN addgroup -g 1001 -S fides && adduser -S fides -u 1001
WORKDIR /app
COPY --from=build /app/packages/core/dist ./packages/core/dist
COPY --from=build /app/packages/core/package.json ./packages/core/
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/services/platform-api/dist ./services/platform-api/dist
COPY --from=build /app/services/platform-api/package.json ./services/platform-api/
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages/core/node_modules ./packages/core/node_modules
COPY --from=deps /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=deps /app/services/platform-api/node_modules ./services/platform-api/node_modules

USER fides
EXPOSE 3600
ENV NODE_ENV=production
ENV PLATFORM_API_PORT=3600

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3600/health || exit 1

CMD ["node", "services/platform-api/dist/index.js"]
