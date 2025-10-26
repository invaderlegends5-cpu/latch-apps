#!/usr/bin/env bash
set -e

echo "🧩 Verifying CI readiness for latch-auth..."
ROOT_DIR="$(pwd)"
CI_DIR="$ROOT_DIR/latch-auth-ci-artifacts"

# Clean old artifacts
rm -rf "$CI_DIR" coverage || true
mkdir -p "$CI_DIR"

# 1️⃣ Run Jest locally (simulates CI unit test run)
echo "🚀 Running Jest..."
JEST_OUTPUT=$(mktemp)
npx jest --ci --no-colors --coverage | tee "$JEST_OUTPUT"

# 2️⃣ Check if JUnit XML exists
echo "🔍 Checking junit.xml..."
if [ -f "$CI_DIR/junit.xml" ]; then
  echo "✅ junit.xml found at $CI_DIR/junit.xml"
else
  echo "❌ junit.xml not found!"
  exit 1
fi

# 3️⃣ Check if coverage directory exists
  if [ -d "latch-auth-ci-artifacts/coverage" ] && [ -f "latch-auth-ci-artifacts/coverage/lcov-report/index.html" ]; then
  echo "✅ Coverage report found."
else
  echo "❌ Coverage report missing!"
  exit 1
fi

# 4️⃣ Simulate CI coverage extraction logic
if [ -f "latch-auth-ci-artifacts/coverage/lcov-report/index.html" ]; then
  RAW_PCT=$(grep -A1 'class="headerItem">Lines</' latch-auth-ci-artifacts/coverage/lcov-report/index.html | grep -o '[0-9.]*' | head -1)
  UNIT_COV=$(awk '/^All files[[:space:]]+\|/ {
  gsub(/\|/, " ");
  for(i=1; i<=NF; i++) if($i ~ /^[0-9]+\.[0-9]+$/) {
    printf "%.0f", $5;  # $5 is the % Lines column
    exit;
  }
}' "$JEST_OUTPUT")
UNIT_COV=${UNIT_COV:-0}
  if ! [[ "$UNIT_COV" =~ ^[0-9]+$ ]]; then
    UNIT_COV=0
  fi
else
  UNIT_COV=0
fi

echo "✅ Coverage detected: ${UNIT_COV}%"
echo "🎉 Local CI verification successful!"
