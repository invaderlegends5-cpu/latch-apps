# ---------- Build Stage ----------
  FROM oven/bun:1.2 AS builder
  RUN apt-get update -y && apt-get install -y openssl
  
  WORKDIR /app
  COPY package.json bun.lockb ./
  RUN bun install --frozen-lockfile
  
  COPY . .
  RUN bunx prisma generate
  RUN bun run build
  
  # ---------- Runtime Stage ----------
  FROM oven/bun:1.2 AS runtime
  WORKDIR /app
  
  # Only need curl for healthcheck (pg_isready not used anymore)
  RUN apt-get update -y && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
  
  ENV NODE_ENV=production
  
  COPY --from=builder /app/node_modules ./node_modules
  COPY --from=builder /app/dist ./dist
  COPY --from=builder /app/prisma ./prisma
  COPY --from=builder /app/package.json ./package.json
  
  EXPOSE 3000
  
  HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -f http://localhost:3000/v1/health || exit 1
  
  # ✅ Simple start — DB wait handled in app code
  CMD ["bun", "run", "start:prod"]