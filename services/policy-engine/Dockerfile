# Stage 1: Install dependencies
FROM node:22-alpine AS deps
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/policy/package.json ./packages/policy/
COPY packages/shared/package.json ./packages/shared/
COPY services/policy-engine/package.json ./services/policy-engine/
RUN pnpm install --frozen-lockfile

# Stage 2: Build
FROM node:22-alpine AS build
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages/policy/node_modules ./packages/policy/node_modules
COPY --from=deps /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=deps /app/services/policy-engine/node_modules ./services/policy-engine/node_modules
COPY packages/policy/ ./packages/policy/
COPY packages/shared/ ./packages/shared/
COPY services/policy-engine/ ./services/policy-engine/
COPY tsconfig.base.json ./
RUN cd packages/shared && pnpm build
RUN cd packages/policy && pnpm build
RUN cd services/policy-engine && pnpm build

# Stage 3: Runtime
FROM node:22-alpine AS runtime
RUN addgroup -g 1001 -S fides && adduser -S fides -u 1001
WORKDIR /app
COPY --from=build /app/packages/policy/dist ./packages/policy/dist
COPY --from=build /app/packages/policy/package.json ./packages/policy/
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/services/policy-engine/dist ./services/policy-engine/dist
COPY --from=build /app/services/policy-engine/package.json ./services/policy-engine/
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages/policy/node_modules ./packages/policy/node_modules
COPY --from=deps /app/packages/shared/node_modules ./packages/shared/node_modules
COPY --from=deps /app/services/policy-engine/node_modules ./services/policy-engine/node_modules

USER fides
EXPOSE 3300
ENV NODE_ENV=production
ENV POLICY_ENGINE_PORT=3300

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3300/health || exit 1

CMD ["node", "services/policy-engine/dist/index.js"]
