#!/usr/bin/env bash
# Deploy Satark AI to Vercel (macOS / Linux / Git Bash).
#
#   Usage:  bash deploy/deploy.sh <XAI_API_KEY> [GROK_MODEL]
#   Needs:  Node.js 20+ and the Vercel CLI  (npm i -g vercel; vercel login)
set -euo pipefail

XAI_KEY="${1:?Usage: bash deploy/deploy.sh <XAI_API_KEY> [GROK_MODEL] - create a key at https://console.x.ai}"
MODEL="${2:-grok-4.20-0309-non-reasoning}"

cd "$(dirname "$0")/.."

echo "==> Running tests"
npm test

echo "==> Linking the folder to the Vercel project 'satark-ai'"
vercel link --yes --project satark-ai >/dev/null

echo "==> Storing the xAI key as an encrypted (sensitive) production environment variable"
vercel env rm XAI_API_KEY production --yes >/dev/null 2>&1 || true
printf '%s' "$XAI_KEY" | vercel env add XAI_API_KEY production --sensitive >/dev/null
vercel env rm GROK_MODEL production --yes >/dev/null 2>&1 || true
printf '%s' "$MODEL" | vercel env add GROK_MODEL production >/dev/null

echo "==> Deploying to production (region bom1 - Mumbai)"
URL="$(vercel deploy --prod --yes)"
echo ""
echo "============================================================"
echo " Satark AI is live: $URL"
echo " Health check:      $URL/api/health"
echo "============================================================"
