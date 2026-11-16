# Deploy Satark AI to Vercel (Windows PowerShell).
#
#   Usage:   .\deploy\deploy.ps1 -XaiKey <XAI_API_KEY>
#   Needs:   Node.js 20+ and the Vercel CLI  (npm i -g vercel; vercel login)
param(
  [Parameter(Mandatory = $true)][string]$XaiKey,
  [string]$Model = "grok-4.20-0309-non-reasoning"
)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "==> Running tests"
npm test
if ($LASTEXITCODE -ne 0) { throw "Tests failed - not deploying." }

Write-Host "==> Linking the folder to the Vercel project 'satark-ai'"
vercel link --yes --project satark-ai | Out-Null

Write-Host "==> Storing the xAI key as an encrypted (sensitive) production environment variable"
vercel env rm XAI_API_KEY production --yes 2>$null | Out-Null
$XaiKey | vercel env add XAI_API_KEY production --sensitive | Out-Null
vercel env rm GROK_MODEL production --yes 2>$null | Out-Null
$Model | vercel env add GROK_MODEL production | Out-Null

Write-Host "==> Deploying to production (region bom1 - Mumbai)"
$url = vercel deploy --prod --yes
Write-Host ""
Write-Host "============================================================"
Write-Host " Satark AI is live: $url"
Write-Host " Health check:      $url/api/health"
Write-Host "============================================================"
