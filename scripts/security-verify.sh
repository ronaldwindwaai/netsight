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
check "no committed .env files (only .env.example)" \
  "git ls-files 2>/dev/null | grep -E '(^|/)\.env(\..+)?$' | grep -v '\.env\.example$'"
check "no auth tokens in browser storage" \
  "grep -rnE '(localStorage|sessionStorage)\.(setItem|getItem)\([^)]*(token|jwt|secret|password)' $SRC --include=*.ts --include=*.tsx --include=*.js"
check "no private keys in source" \
  "grep -rnE -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' . --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next --exclude-dir=Netsight_Development_Package"
check "no hard-coded credential assignments in app code" \
  "grep -rniE '(password|passwd|secret|api_key|apikey|token)[\"'\'']?\s*[:=]\s*[\"'\''][^\"'\'']{8,}[\"'\'']' apps packages --include=*.ts --include=*.tsx --include=*.py --exclude-dir=node_modules --exclude-dir=tests --exclude-dir=.next"
check "no TLS verification disabled" \
  "grep -rnE 'rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED' $SRC --include=*.ts --include=*.tsx --include=*.js --include=*.py --exclude-dir=node_modules"

if [ "$fail" -ne 0 ]; then echo; echo "Security policy checks FAILED"; exit 1; fi
echo; echo "Security policy checks passed"
