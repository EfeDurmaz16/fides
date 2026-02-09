# Stage 1: Install dependencies
FROM node:22-alpine AS deps
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/sdk/package.json ./packages/sdk/
COPY services/discovery/package.json ./services/discovery/
RUN pnpm install --frozen-lockfile

# Stage 2: Build
FROM node:22-alpine AS build
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=deps /app/packages/sdk/node_modules ./packages/sdk/node_modules
COPY --from=deps /app/services/discovery/node_modules ./services/discovery/node_modules
COPY packages/shared/ ./packages/shared/
COPY packages/sdk/ ./packages/sdk/
COPY services/discovery/ ./services/discovery/
COPY tsconfig.base.json ./
RUN cd packages/shared && pnpm build
RUN cd packages/sdk && pnpm build
RUN cd services/discovery && pnpm build

# Stage 3: Runtime
FROM node:22-alpine AS runtime
RUN addgroup -g 1001 -S fides && adduser -S fides -u 1001
WORKDIR /app
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/sdk/dist ./packages/sdk/dist
COPY --from=build /app/packages/sdk/package.json ./packages/sdk/
COPY --from=build /app/services/discovery/dist ./services/discovery/dist
COPY --from=build /app/services/discovery/package.json ./services/discovery/
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/services/discovery/node_modules ./services/discovery/node_modules

USER fides
EXPOSE 3100
ENV NODE_ENV=production
ENV DISCOVERY_PORT=3100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3100/health || exit 1

CMD ["node", "services/discovery/dist/index.js"]
