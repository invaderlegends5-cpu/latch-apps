# ---------- Build Stage ----------
  FROM oven/bun:1.2 AS builder
  RUN apt-get update -y && apt-get install -y openssl
  
  WORKDIR /app
  COPY package.json bun.lock ./
  RUN bun install --frozen-lockfile
  
  COPY . .
  RUN bunx prisma generate
  RUN bun run build
  
  # ---------- Runtime Stage ----------
  FROM oven/bun:1.2 AS runtime
  WORKDIR /app
  
  # Install PostgreSQL client for health checks (minimal footprint)
  RUN apt-get update -y && apt-get install -y --no-install-recommends postgresql-client curl && rm -rf /var/lib/apt/lists/*
  
  ENV NODE_ENV=production
  
  COPY --from=builder /app/node_modules ./node_modules
  COPY --from=builder /app/dist ./dist
  COPY --from=builder /app/prisma ./prisma
  COPY --from=builder /app/package.json ./package.json
  COPY --from=builder /app/prisma/seed.ts ./prisma/seed.ts
  
  EXPOSE 3000
  
  # ---------- Healthcheck ----------
  HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -f http://localhost:3000/v1/health || exit 1
  
  # ---------- Startup Script ----------
  CMD bash -c '\
    echo "⏳ Waiting for database to be ready..." && \
    until pg_isready -h db -p 5432 -U latch > /dev/null 2>&1; do \
      sleep 1; \
    done; \
    echo "✅ Database is ready. Running Prisma migrations..." && \
    bunx prisma migrate deploy && \
    echo "🌱 Running mock seed script (if DB empty)..." && \
    bun prisma/seed.ts || true && \
    echo "🚀 Starting latch-auth service..." && \
    bun run start:prod \
  '
  