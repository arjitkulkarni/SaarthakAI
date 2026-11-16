#!/usr/bin/env bash
# Deploy Satark AI to Google Cloud Run.
# Easiest: run this inside Google Cloud Shell (https://shell.cloud.google.com) - gcloud is pre-installed.
#
#   Usage:  bash deploy/deploy.sh <GCP_PROJECT_ID> <GEMINI_API_KEY> [REGION]
#   Example: bash deploy/deploy.sh satark-ai-demo AIzaSy... asia-south1
set -euo pipefail

PROJECT_ID="${1:?Usage: bash deploy/deploy.sh <GCP_PROJECT_ID> <GEMINI_API_KEY> [REGION]}"
GEMINI_KEY="${2:?Gemini API key missing - create one at https://aistudio.google.com/apikey}"
REGION="${3:-asia-south1}"           # Mumbai
SERVICE="satark-ai"
SECRET="gemini-api-key"

cd "$(dirname "$0")/.."

echo "==> Using project $PROJECT_ID, region $REGION"
gcloud config set project "$PROJECT_ID" >/dev/null

echo "==> Enabling required APIs (Cloud Run, Cloud Build, Artifact Registry, Secret Manager)"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com secretmanager.googleapis.com

echo "==> Storing the Gemini API key in Secret Manager"
if gcloud secrets describe "$SECRET" >/dev/null 2>&1; then
  printf '%s' "$GEMINI_KEY" | gcloud secrets versions add "$SECRET" --data-file=-
else
  printf '%s' "$GEMINI_KEY" | gcloud secrets create "$SECRET" --replication-policy=automatic --data-file=-
fi

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
RUNTIME_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

echo "==> Granting the Cloud Run service account access to the secret"
gcloud secrets add-iam-policy-binding "$SECRET" \
  --member="serviceAccount:${RUNTIME_SA}" --role=roles/secretmanager.secretAccessor >/dev/null

echo "==> Granting build permissions (needed on newer projects for source deploys)"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${RUNTIME_SA}" --role=roles/run.builder >/dev/null 2>&1 || true

echo "==> Building and deploying (takes 2-4 minutes)"
gcloud run deploy "$SERVICE" \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --set-secrets "GEMINI_API_KEY=${SECRET}:latest" \
  --set-env-vars "GEMINI_MODEL=gemini-3.8-flash,CLOUD_RUN_REGION=${REGION}" \
  --memory 512Mi --cpu 1 \
  --min-instances 0 --max-instances 3 \
  --concurrency 40 --timeout 60

URL="$(gcloud run services describe "$SERVICE" --region "$REGION" --format='value(status.url)')"
echo ""
echo "============================================================"
echo " Satark AI is live: $URL"
echo " Health check:      $URL/api/health"
echo "============================================================"
