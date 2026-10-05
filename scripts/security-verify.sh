#!/usr/bin/env bash
# Repo-level security policy checks derived from AGENTS.md. Complements the scanners in
# .github/workflows/security.yml (gitleaks, pnpm/pip audit, trivy, CodeQL).
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
check() { # check <description> <command that prints offending lines on violation>
  local out; out="$(eval "$2" 2>/dev/null || true)"
  if [ -n "$out" ]; then echo "FAIL: $1"; echo "$out" | sed 's/^/    /'; fail=1; else echo "ok:   $1"; fi
}

SRC="apps packages"
# Virtualenvs and installed dependencies are not first-party source and must not
# trigger repo-level policy checks (e.g. python site-packages contain many
# `password = "..."` examples). Exclude them alongside node_modules.
DEP_EXCLUDES="--exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=site-packages --exclude-dir=.mypy_cache --exclude-dir=.pytest_cache --exclude-dir=.next"
check "no committed .env files (only .env.example)" \
  "git ls-files 2>/dev/null | grep -E '(^|/)\.env(\..+)?$' | grep -v '\.env\.example$'"
check "no auth tokens in browser storage" \
  "grep -rnE '(localStorage|sessionStorage)\.(setItem|getItem)\([^)]*(token|jwt|secret|password)' $SRC --include=*.ts --include=*.tsx --include=*.js $DEP_EXCLUDES"
check "no private keys in source" \
  "grep -rnE -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' . --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next --exclude-dir=.venv --exclude-dir=site-packages --exclude-dir=Netsight_Development_Package"
# Test files legitimately contain dummy credentials and placeholder tokens, and
# first-party tests live beside the code (src/lib/*.test.ts) as well as under
# tests/ directories. Exclude them by naming convention as well as by directory,
# so the check targets shipped code instead of failing closed on fixtures.
# gitleaks and trivy (security.yml) still scan the whole tree, including tests.
TEST_EXCLUDES="--exclude-dir=tests --exclude-dir=e2e --exclude=*.test.ts --exclude=*.test.tsx --exclude=*.spec.ts --exclude=test_*.py --exclude=*_test.py"
check "no hard-coded credential assignments in app code" \
  "grep -rniE '(password|passwd|secret|api_key|apikey|token)[\"'\'']?\s*[:=]\s*[\"'\''][^\"'\'']{8,}[\"'\'']' $SRC --include=*.ts --include=*.tsx --include=*.py $DEP_EXCLUDES $TEST_EXCLUDES"
check "no TLS verification disabled" \
  "grep -rnE 'rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED' $SRC --include=*.ts --include=*.tsx --include=*.js --include=*.py $DEP_EXCLUDES"

if [ "$fail" -ne 0 ]; then echo; echo "Security policy checks FAILED"; exit 1; fi
echo; echo "Security policy checks passed"
