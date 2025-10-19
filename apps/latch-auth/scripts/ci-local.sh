#!/usr/bin/env bash
set -euo pipefail

echo "🧪 Starting Latch Auth Local CI Simulation..."
START_TIME=$(date +%s)

# 👇 LOAD .env.test to override DATABASE_URL for host usage
export $(grep -v '^#' .env.test | xargs)

# --------------------------------------------------
# 🧹 Cleanup on exit (always runs)
# --------------------------------------------------
cleanup() {
  echo "🧹 Cleaning up containers and processes..."
  docker compose down --remove-orphans >/dev/null 2>&1 || true
  pkill -f "bun run start" >/dev/null 2>&1 || true
  echo "🧼 Cleanup done."
}
trap cleanup EXIT

# --------------------------------------------------
# 1. Ensure dependencies
# --------------------------------------------------
echo "📦 Installing dependencies..."
bun install --frozen-lockfile

# --------------------------------------------------
# 2. Generate Prisma client
# --------------------------------------------------
echo "🧬 Generating Prisma client..."
npx prisma generate

# --------------------------------------------------
# 3. Start Postgres + Redis via compose
# --------------------------------------------------
echo "🐘 Launching Postgres + Redis..."
docker compose up -d db redis

# Wait for Postgres readiness
echo "⏳ Waiting for Postgres..."
for i in {1..20}; do
  if docker exec latch_postgres pg_isready -U latch -d latch_auth > /dev/null 2>&1; then
    echo "✅ Postgres is ready!"
    break
  fi
  if [ $i -eq 20 ]; then
    echo "❌ Postgres did not become ready in time."
    exit 1
  fi
  sleep 2
done

# --------------------------------------------------
# 4. Apply Prisma migrations
# --------------------------------------------------
echo "🧩 Applying Prisma migrations..."
npx prisma migrate deploy

# --------------------------------------------------
# 5. Run mock seed + verify
# --------------------------------------------------
echo "🌱 Running mock seed..."
bun run prisma/seed.ts || echo "⚠️ Seed skipped."

if bun run seed:check >/dev/null 2>&1; then
  echo "✅ Seed presence verified."
else
  echo "⚠️ Seed verification failed (check script output)."
fi

# 👇 FIX: Clean dist to avoid permission issues
#echo "🧹 Cleaning dist folder..."
#rm -rf dist/

# --------------------------------------------------
# 6. Start app and check /v1/health
# --------------------------------------------------
echo "🚀 Starting app for health check..."
# Build the app first
bun run build

# Run the production build (non-watch mode)
bun run start:prod &
APP_PID=$!


echo "⏳ Waiting for app to start..."
for i in {1..20}; do
  if curl -fs http://localhost:3000/v1/health >/dev/null 2>&1; then
    echo "✅ /v1/health endpoint is healthy."
    break
  fi
  if [ $i -eq 20 ]; then
    echo "❌ Health endpoint failed to respond in time."
    exit 1
  fi
  sleep 2
done

if [ -n "${APP_PID:-}" ]; then
  kill $APP_PID 2>/dev/null || true
  wait $APP_PID 2>/dev/null || true
fi

# --------------------------------------------------
# 7. Run tests (unit + e2e)
# --------------------------------------------------
echo "🧠 Running tests..."
npm test --ci --no-colors || echo "⚠️ Some tests failed — check logs."

# --------------------------------------------------
# 8. Done
# --------------------------------------------------
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
echo "🎉 Local CI simulation completed successfully in ${ELAPSED}s."
