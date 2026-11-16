# Deploy Satark AI to Google Cloud Run from Windows PowerShell.
# Requires the Google Cloud CLI: https://cloud.google.com/sdk/docs/install  (then run: gcloud auth login)
#
#   Usage:  .\deploy\deploy.ps1 -ProjectId satark-ai-demo -GeminiKey AIzaSy... [-Region asia-south1]
param(
  [Parameter(Mandatory = $true)][string]$ProjectId,
  [Parameter(Mandatory = $true)][string]$GeminiKey,
  [string]$Region = "asia-south1"
)
$ErrorActionPreference = "Stop"
$Service = "satark-ai"
$Secret = "gemini-api-key"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "==> Using project $ProjectId, region $Region"
gcloud config set project $ProjectId | Out-Null

Write-Host "==> Enabling required APIs"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com

Write-Host "==> Storing the Gemini API key in Secret Manager"
$tmp = New-TemporaryFile
[System.IO.File]::WriteAllText($tmp.FullName, $GeminiKey)
$exists = $true
try { gcloud secrets describe $Secret 2>$null | Out-Null; if ($LASTEXITCODE -ne 0) { $exists = $false } } catch { $exists = $false }
if ($exists) { gcloud secrets versions add $Secret --data-file="$($tmp.FullName)" }
else { gcloud secrets create $Secret --replication-policy=automatic --data-file="$($tmp.FullName)" }
Remove-Item $tmp.FullName -Force

$ProjectNumber = gcloud projects describe $ProjectId --format="value(projectNumber)"
$RuntimeSa = "$ProjectNumber-compute@developer.gserviceaccount.com"

Write-Host "==> Granting secret + build permissions"
gcloud secrets add-iam-policy-binding $Secret --member="serviceAccount:$RuntimeSa" --role=roles/secretmanager.secretAccessor | Out-Null
try { gcloud projects add-iam-policy-binding $ProjectId --member="serviceAccount:$RuntimeSa" --role=roles/run.builder 2>$null | Out-Null } catch {}

Write-Host "==> Building and deploying (takes 2-4 minutes)"
gcloud run deploy $Service `
  --source . `
  --region $Region `
  --allow-unauthenticated `
  --set-secrets "GEMINI_API_KEY=${Secret}:latest" `
  --set-env-vars "GEMINI_MODEL=gemini-3.8-flash,CLOUD_RUN_REGION=$Region" `
  --memory 512Mi --cpu 1 `
  --min-instances 0 --max-instances 3 `
  --concurrency 40 --timeout 60

$Url = gcloud run services describe $Service --region $Region --format="value(status.url)"
Write-Host ""
Write-Host "============================================================"
Write-Host " Satark AI is live: $Url"
Write-Host " Health check:      $Url/api/health"
Write-Host "============================================================"
