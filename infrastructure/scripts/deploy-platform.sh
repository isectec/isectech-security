#!/usr/bin/env bash

# iSECTECH – End-to-End Google Cloud Deployment Script
# Purpose: One-command deploy from zero (APIs, registry) to Cloud Run services
# Usage examples:
#   ./infrastructure/scripts/deploy-platform.sh \
#     --project-id=my-gcp-project --region=us-central1 --env=staging --all
#
#   ./infrastructure/scripts/deploy-platform.sh \
#     --project-id=my-gcp-project --region=us-central1 --env=production --build --push --deploy
#
# Requirements: gcloud, docker, Git (optional for commit hash), authenticated gcloud account

set -euo pipefail

#############################################
# Formatting & logging helpers
#############################################
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }

#############################################
# Defaults
#############################################
PROJECT_ID=""
REGION=""
ENVIRONMENT=""  # development|staging|production (auto-detected if empty)
ARTIFACT_REPO=""
DOCKER_PLATFORM="linux/amd64" # override if needed, e.g. linux/arm64 for Apple Silicon
ALLOW_UNAUTH="true"          # set to false to disable public access
VPC_CONNECTOR=""             # e.g. isectech-vpc-connector (optional)
CONCURRENCY="100"
MIN_INSTANCES="1"
MAX_INSTANCES="25"
TIMEOUT_SEC="300"
CPU="2"
MEMORY="2Gi"

# Auto-derived version tags
BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
BUILD_VERSION="$(date -u +'%Y%m%d-%H%M%S')-${GIT_COMMIT}"

#############################################
# Service catalog (service_id -> Dockerfile path)
#############################################
# macOS ships an older Bash without associative arrays; use colon-separated pairs
SERVICES_PAIRS=(
  "frontend:Dockerfile.frontend.production"
  "api-gateway:backend/services/api-gateway/Dockerfile"
  "auth-service:backend/services/auth-service/Dockerfile"
  "asset-discovery:backend/services/asset-discovery/Dockerfile"
  "event-processor:backend/services/event-processor/Dockerfile"
  "threat-detection:backend/services/threat-detection/Dockerfile"
  "behavioral-analysis:ai-services/services/behavioral-analysis/Dockerfile"
  "decision-engine:ai-services/services/decision-engine/Dockerfile"
  "nlp-assistant:ai-services/services/nlp-assistant/Dockerfile"
)

#############################################
# Argument parsing
#############################################
SHOW_HELP="false"
DO_INIT="false"      # enable APIs + create artifact registry
DO_BUILD="false"
DO_PUSH="false"
DO_DEPLOY="false"
DO_ALL="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-id) PROJECT_ID="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --env|--environment) ENVIRONMENT="$2"; shift 2 ;;
    --artifact-repo) ARTIFACT_REPO="$2"; shift 2 ;;
    --platform) DOCKER_PLATFORM="$2"; shift 2 ;;
    --no-public) ALLOW_UNAUTH="false"; shift 1 ;;
    --vpc-connector) VPC_CONNECTOR="$2"; shift 2 ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --min-instances) MIN_INSTANCES="$2"; shift 2 ;;
    --max-instances) MAX_INSTANCES="$2"; shift 2 ;;
    --cpu) CPU="$2"; shift 2 ;;
    --memory) MEMORY="$2"; shift 2 ;;
    --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
    --init) DO_INIT="true"; shift 1 ;;
    --build) DO_BUILD="true"; shift 1 ;;
    --push) DO_PUSH="true"; shift 1 ;;
    --deploy) DO_DEPLOY="true"; shift 1 ;;
    --all) DO_ALL="true"; shift 1 ;;
    -h|--help) SHOW_HELP="true"; shift 1 ;;
    *) log_error "Unknown option: $1"; SHOW_HELP="true"; shift 1 ;;
  esac
done

if [[ "$SHOW_HELP" == "true" ]]; then
  cat <<EOF
One-command deploy to Google Cloud Run

Common:
  --project-id <id>           GCP project id (auto-detected if omitted)
  --region <r>                Region (auto-detected if omitted)
  --env <e>                   Environment: development|staging|production (auto-detected by git branch if omitted)
  --artifact-repo <name>      Artifact Registry repo (defaults to "<project-id>-docker-repo")
  --platform <p>              Docker build platform (default: ${DOCKER_PLATFORM})
  --no-public                 Do NOT allow unauthenticated access
  --vpc-connector <name>      Use a Serverless VPC connector (optional)
  --concurrency <n>           Cloud Run concurrency (default: ${CONCURRENCY})
  --min-instances <n>         Min instances (default: ${MIN_INSTANCES})
  --max-instances <n>         Max instances (default: ${MAX_INSTANCES})
  --cpu <n>                   vCPU (default: ${CPU})
  --memory <size>             Memory (default: ${MEMORY})
  --timeout <sec>             Request timeout seconds (default: ${TIMEOUT_SEC})

Actions:
  --init                      Enable APIs and create Artifact Registry
  --build                     Build Docker images for all services
  --push                      Push images to Artifact Registry
  --deploy                    Deploy all services to Cloud Run
  --all                       Run: --init, --build, --push, --deploy

Examples:
  $0 --project-id my-proj --region us-central1 --env staging --all
  $0 --project-id my-proj --region europe-west1 --env production --build --push --deploy --no-public
EOF
  exit 0
fi

if [[ "$DO_ALL" == "true" ]]; then
  DO_INIT="true"; DO_BUILD="true"; DO_PUSH="true"; DO_DEPLOY="true"
fi

# If no action flags passed, default to end-to-end
if [[ "$DO_INIT$DO_BUILD$DO_PUSH$DO_DEPLOY$DO_ALL" == "falsefalsefalsefalsefalse" ]]; then
  DO_INIT="true"; DO_BUILD="true"; DO_PUSH="true"; DO_DEPLOY="true"
fi

#############################################
# Preconditions
#############################################
require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log_error "Missing required command: $1"; exit 1
  fi
}

require_cmd gcloud
require_cmd docker

log_info "Using project=${PROJECT_ID}, region=${REGION}, env=${ENVIRONMENT}"

#############################################
# Auto-detection from repository
#############################################
most_common() {
  awk 'NF{count[$0]++} END{mc="";m=0; for(k in count){ if(count[k]>m){m=count[k]; mc=k} } if(mc!="") print mc; }'
}

detect_project_id() {
  # Try README declaration
  local candidates
  candidates=$(grep -RhoE "isectech-[a-z0-9-]+" infrastructure 2>/dev/null | grep -E "isectech-.*project|isectech-.*platform|isectech-.*security" || true)
  # Add keys JSON project_ids
  candidates+=$'\n'$(grep -RhoE '"project_id"\s*:\s*"[^"]+"' infrastructure/keys 2>/dev/null | sed -E 's/.*:"([^"]+)"/\1/' || true)
  # Add explicit gcloud set project lines
  candidates+=$'\n'$(grep -RhoE 'gcloud\s+config\s+set\s+project\s+[^\s]+' infrastructure 2>/dev/null | awk '{print $NF}' || true)
  # Add env files
  candidates+=$'\n'$(grep -RhoE '^PROJECT_ID=.+$' infrastructure/secrets 2>/dev/null | sed -E 's/.*=([^\r\n]+)/\1/' || true)
  echo "$candidates" | sed '/^$/d' | most_common
}

detect_region() {
  local regions
  regions=$(grep -RhoE '[a-z0-9-]+-docker\.pkg\.dev' . 2>/dev/null | sed 's/-docker.pkg.dev//' || true)
  # Fall back to regions declared in env or docs
  regions+=$'\n'$(grep -Rho "\b(us|europe|asia)[a-z0-9-]*1\b" -h infrastructure -R 2>/dev/null | grep -Eo '(us|europe|asia)[a-z0-9-]*1' || true)
  if [[ -n "$regions" ]]; then echo "$regions" | most_common; else echo "us-central1"; fi
}

detect_artifact_repo() {
  # Prefer <project-id>-docker-repo pattern if present in CI
  local repo
  if grep -Rho "_ARTIFACT_REGISTRY:.*\\\\?\${_PROJECT_ID}-docker-repo" infrastructure/ci-cd >/dev/null 2>&1; then
    echo "${PROJECT_ID}-docker-repo"; return
  fi
  # Fallback to explicit mentions
  repo=$(grep -RhoE '/([^/]+)/[^:]+:latest' . 2>/dev/null | sed -E 's#^.*/([a-zA-Z0-9._-]+)/[^:]+:latest#\1#' | most_common || true)
  if [[ -n "$repo" ]]; then echo "$repo"; else echo "${PROJECT_ID}-docker-repo"; fi
}

detect_environment() {
  # Derive from git branch
  local branch
  branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  if [[ "$branch" == "main" || "$branch" == "master" ]]; then echo "production"; return; fi
  if [[ "$branch" == "staging" ]]; then echo "staging"; return; fi
  echo "development"
}

detect_vpc_connector() {
  local conn
  conn=$(grep -RhoE 'vpc-connector\s+"?[a-zA-Z0-9-]+"?' . 2>/dev/null | awk '{print $2}' | tr -d '"' | most_common || true)
  if [[ -n "$conn" ]]; then echo "$conn"; fi
}

# Populate values if missing
if [[ -z "$PROJECT_ID" ]]; then PROJECT_ID="$(detect_project_id || true)"; fi
if [[ -z "$REGION" ]]; then REGION="$(detect_region || true)"; fi
if [[ -z "$ENVIRONMENT" ]]; then ENVIRONMENT="$(detect_environment)"; fi
if [[ -z "$ARTIFACT_REPO" && -n "$PROJECT_ID" ]]; then ARTIFACT_REPO="$(detect_artifact_repo)"; fi
if [[ -z "$VPC_CONNECTOR" ]]; then VPC_CONNECTOR="$(detect_vpc_connector || true)"; fi

if [[ -z "$PROJECT_ID" ]]; then log_error "Could not auto-detect PROJECT_ID"; exit 1; fi
if [[ -z "$REGION" ]]; then REGION="us-central1"; fi
if [[ -z "$ARTIFACT_REPO" ]]; then ARTIFACT_REPO="${PROJECT_ID}-docker-repo"; fi

log_info "Auto-detected project=${PROJECT_ID}, region=${REGION}, env=${ENVIRONMENT}, repo=${ARTIFACT_REPO}, vpc=${VPC_CONNECTOR:-none}"
gcloud config set project "$PROJECT_ID" >/dev/null

#############################################
# Enable required APIs
#############################################
enable_required_apis() {
  log_info "Enabling required Google Cloud APIs (idempotent)..."
  local apis=(
    run.googleapis.com
    artifactregistry.googleapis.com
    cloudbuild.googleapis.com
    iam.googleapis.com
    vpcaccess.googleapis.com
    logging.googleapis.com
    monitoring.googleapis.com
    secretmanager.googleapis.com
  )
  for api in "${apis[@]}"; do
    log_info "  Enabling $api"
    gcloud services enable "$api" --project "$PROJECT_ID" >/dev/null || true
  done
  log_success "APIs ensured"
}

#############################################
# Artifact Registry setup
#############################################
ensure_artifact_registry() {
  log_info "Ensuring Artifact Registry repo '${ARTIFACT_REPO}' exists in ${REGION}..."
  if ! gcloud artifacts repositories describe "$ARTIFACT_REPO" \
       --location "$REGION" >/dev/null 2>&1; then
    gcloud artifacts repositories create "$ARTIFACT_REPO" \
      --repository-format=docker \
      --location="$REGION" \
      --description="iSECTECH platform containers" >/dev/null
    log_success "Created Artifact Registry: ${ARTIFACT_REPO} (${REGION})"
  else
    log_info "Artifact Registry already exists"
  fi

  log_info "Configuring Docker to authenticate with Artifact Registry..."
  gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet
  log_success "Docker authentication configured"
}

#############################################
# Build & push
#############################################
image_name_for() {
  local service="$1"
  echo "${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REPO}/${service}:${BUILD_VERSION}"
}

latest_tag_for() {
  local service="$1"
  echo "${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REPO}/${service}:${ENVIRONMENT}-latest"
}

build_images() {
  log_info "Building images for services..."
  local pair service dockerfile
  for pair in "${SERVICES_PAIRS[@]}"; do
    service="${pair%%:*}"
    dockerfile="${pair#*:}"
    if [[ ! -f "$dockerfile" ]]; then
      log_warn "Skipping ${service}: Dockerfile not found at ${dockerfile}"
      continue
    fi

    local image="$(image_name_for "$service")"
    local latest="$(latest_tag_for "$service")"
    log_info "Building ${service} -> ${image} (platform: ${DOCKER_PLATFORM})"

    # Ensure buildx builder exists
    docker buildx create --use --name isectech-builder >/dev/null 2>&1 || true
    docker buildx inspect isectech-builder >/dev/null 2>&1 || docker buildx use isectech-builder

    docker buildx build \
      --platform "${DOCKER_PLATFORM}" \
      --file "$dockerfile" \
      --build-arg BUILD_DATE="${BUILD_DATE}" \
      --build-arg BUILD_VERSION="${BUILD_VERSION}" \
      --build-arg GIT_COMMIT="${GIT_COMMIT}" \
      --tag "$image" \
      --tag "$latest" \
      --provenance=false \
      --sbom=false \
      --load \
      .

    log_success "Built ${service}"
  done
}

push_images() {
  log_info "Pushing images to Artifact Registry..."
  local pair service image latest
  for pair in "${SERVICES_PAIRS[@]}"; do
    service="${pair%%:*}"
    image="$(image_name_for "$service")"
    latest="$(latest_tag_for "$service")"
    if docker image inspect "$image" >/dev/null 2>&1; then
      log_info "Pushing ${image}"
      docker push "$image" >/dev/null
      docker push "$latest" >/dev/null
      log_success "Pushed ${service}"
    else
      log_warn "Image not found locally, skipped push: ${image}"
    fi
  done
}

#############################################
# Deploy to Cloud Run
#############################################
deploy_services() {
  log_info "Deploying services to Cloud Run (env=${ENVIRONMENT})..."

  local allow_flag="--allow-unauthenticated"
  if [[ "$ALLOW_UNAUTH" != "true" ]]; then
    allow_flag="--no-allow-unauthenticated"
  fi

  local pair service image svc_name
  for pair in "${SERVICES_PAIRS[@]}"; do
    service="${pair%%:*}"
    image="$(image_name_for "$service")"
    svc_name="isectech-${service}-${ENVIRONMENT}"

    if ! gcloud artifacts docker images describe "$image" >/dev/null 2>&1; then
      log_warn "Image not in Artifact Registry yet, attempting to deploy with local tag: ${image}"
    fi

    local vpc_flags=()
    if [[ -n "$VPC_CONNECTOR" ]]; then
      vpc_flags=("--vpc-connector" "$VPC_CONNECTOR" "--vpc-egress" "private-ranges-only")
    fi

    log_info "Deploying ${service} as ${svc_name}..."
    gcloud run deploy "$svc_name" \
      --image "$image" \
      --region "$REGION" \
      --platform managed \
      $allow_flag \
      --memory "$MEMORY" \
      --cpu "$CPU" \
      --concurrency "$CONCURRENCY" \
      --min-instances "$MIN_INSTANCES" \
      --max-instances "$MAX_INSTANCES" \
      --timeout "$TIMEOUT_SEC" \
      --port 8080 \
      --set-env-vars "ENVIRONMENT=${ENVIRONMENT},BUILD_VERSION=${BUILD_VERSION},GIT_COMMIT=${GIT_COMMIT}" \
      --labels "environment=${ENVIRONMENT},service=${service},version=${BUILD_VERSION}" \
      --tag "version-${BUILD_VERSION}" \
      "${vpc_flags[@]}" \
      --quiet

    local url
    url=$(gcloud run services describe "$svc_name" --region "$REGION" --format 'value(status.url)')
    log_success "Deployed ${svc_name} -> ${url}"
  done

  log_success "All services deployed"
}

#############################################
# Orchestration
#############################################
if [[ "$DO_INIT" == "true" ]]; then
  enable_required_apis
  ensure_artifact_registry
fi

if [[ "$DO_BUILD" == "true" ]]; then
  build_images
fi

if [[ "$DO_PUSH" == "true" ]]; then
  push_images
fi

if [[ "$DO_DEPLOY" == "true" ]]; then
  deploy_services
fi

log_success "Done. BuildVersion=${BUILD_VERSION} Env=${ENVIRONMENT} Region=${REGION} Project=${PROJECT_ID}"