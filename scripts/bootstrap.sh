#!/usr/bin/env bash
set -euo pipefail
echo "Netsight bootstrap"
echo "1) Review START-HERE.md and AGENTS.md"
echo "2) Copy .env.example to an untracked .env and fill DEV values only"
echo "3) docker compose -f infrastructure/compose/docker-compose.dev.yml up -d"
echo "4) pnpm install (this creates the lockfile; review and commit it)"
echo "5) create Python virtual environments using your preferred tool"
echo "Do not connect this bootstrap directly to production systems."
