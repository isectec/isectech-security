#!/bin/bash

# iSECTECH Dockerfile Validation Script
# Tests Dockerfile syntax and build compatibility before Cloud Build deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOCKERFILE_PATH="Dockerfile.frontend.production"
DOCKERFILE_BUILDKIT_PATH="Dockerfile.frontend.production.buildkit"
IMAGE_NAME="isectech-frontend-test"
PROJECT_ROOT=$(dirname "$(dirname "$(realpath "$0")")")

echo -e "${BLUE}=== iSECTECH Dockerfile Validation Script ===${NC}"
echo -e "Project Root: ${PROJECT_ROOT}"
echo -e "Testing: ${DOCKERFILE_PATH}"
echo ""

cd "$PROJECT_ROOT"

# Test 1: Check if Dockerfile exists
echo -e "${BLUE}Test 1: Dockerfile Existence${NC}"
if [[ ! -f "$DOCKERFILE_PATH" ]]; then
    echo -e "${RED}❌ FAIL: $DOCKERFILE_PATH not found${NC}"
    exit 1
fi
echo -e "${GREEN}✅ PASS: $DOCKERFILE_PATH exists${NC}"
echo ""

# Test 2: Check for BuildKit syntax that would fail in Cloud Build
echo -e "${BLUE}Test 2: BuildKit Compatibility${NC}"
BUILDKIT_SYNTAX=$(grep -n "RUN --mount" "$DOCKERFILE_PATH" || true)
if [[ -n "$BUILDKIT_SYNTAX" ]]; then
    echo -e "${RED}❌ FAIL: Found BuildKit syntax that will fail in Cloud Build:${NC}"
    echo "$BUILDKIT_SYNTAX"
    echo -e "${YELLOW}Consider using $DOCKERFILE_BUILDKIT_PATH with BuildKit-enabled Cloud Build${NC}"
    exit 1
fi
echo -e "${GREEN}✅ PASS: No BuildKit-specific syntax found${NC}"
echo ""

# Test 3: Check for common Dockerfile issues
echo -e "${BLUE}Test 3: Common Dockerfile Issues${NC}"

# Check for ECHO instruction (common parser error)
ECHO_ISSUES=$(grep -n "^ECHO\|^echo\|^\s*ECHO" "$DOCKERFILE_PATH" || true)
if [[ -n "$ECHO_ISSUES" ]]; then
    echo -e "${RED}❌ FAIL: Found invalid ECHO instructions:${NC}"
    echo "$ECHO_ISSUES"
    exit 1
fi

# Check for proper USER instruction format
USER_INSTRUCTION=$(grep -n "^USER" "$DOCKERFILE_PATH" || true)
if [[ -n "$USER_INSTRUCTION" ]]; then
    echo -e "${GREEN}✅ PASS: USER instruction found (security best practice)${NC}"
else
    echo -e "${YELLOW}⚠️  WARNING: No USER instruction found (running as root)${NC}"
fi

# Check for EXPOSE instruction
EXPOSE_INSTRUCTION=$(grep -n "^EXPOSE" "$DOCKERFILE_PATH" || true)
if [[ -n "$EXPOSE_INSTRUCTION" ]]; then
    echo -e "${GREEN}✅ PASS: EXPOSE instruction found${NC}"
else
    echo -e "${YELLOW}⚠️  WARNING: No EXPOSE instruction found${NC}"
fi

echo ""

# Test 4: Dockerfile syntax validation (if Docker is available)
echo -e "${BLUE}Test 4: Docker Syntax Validation${NC}"
if command -v docker &> /dev/null; then
    echo "Testing Dockerfile syntax with Docker..."
    
    # Test basic parsing without actually building
    if docker build -f "$DOCKERFILE_PATH" --target base . >/dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS: Basic Dockerfile syntax is valid${NC}"
    else
        echo -e "${RED}❌ FAIL: Dockerfile syntax errors detected${NC}"
        echo "Running detailed syntax check:"
        docker build -f "$DOCKERFILE_PATH" --target base . || true
        exit 1
    fi
else
    echo -e "${YELLOW}⚠️  SKIP: Docker not available, cannot validate syntax${NC}"
fi
echo ""

# Test 5: Check required files for build
echo -e "${BLUE}Test 5: Required Build Files${NC}"
REQUIRED_FILES=("package.json" "next.config.production.ts")
for file in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo -e "${GREEN}✅ PASS: $file exists${NC}"
    else
        echo -e "${RED}❌ FAIL: Required file missing: $file${NC}"
        exit 1
    fi
done
echo ""

# Test 6: Check Cloud Build configuration
echo -e "${BLUE}Test 6: Cloud Build Configuration${NC}"
CLOUDBUILD_FILE="cloudbuild.yaml"
if [[ -f "$CLOUDBUILD_FILE" ]]; then
    echo -e "${GREEN}✅ PASS: $CLOUDBUILD_FILE exists${NC}"
    
    # Check for proper dockerfile reference
    if grep -q "Dockerfile.frontend.production" "$CLOUDBUILD_FILE"; then
        echo -e "${GREEN}✅ PASS: Cloud Build references correct Dockerfile${NC}"
    else
        echo -e "${YELLOW}⚠️  WARNING: Cloud Build may not reference the correct Dockerfile${NC}"
    fi
    
    # Check for substitutionOption (not substitution_option)
    if grep -q "substitutionOption" "$CLOUDBUILD_FILE"; then
        echo -e "${GREEN}✅ PASS: Correct substitutionOption syntax${NC}"
    elif grep -q "substitution_option" "$CLOUDBUILD_FILE"; then
        echo -e "${RED}❌ FAIL: Invalid substitution_option syntax (should be substitutionOption)${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠️  WARNING: No $CLOUDBUILD_FILE found${NC}"
fi
echo ""

# Test 7: BuildKit Dockerfile availability
echo -e "${BLUE}Test 7: BuildKit Dockerfile Option${NC}"
if [[ -f "$DOCKERFILE_BUILDKIT_PATH" ]]; then
    echo -e "${GREEN}✅ PASS: BuildKit-enhanced Dockerfile available${NC}"
    echo -e "${BLUE}   Use 'cloudbuild.buildkit.yaml' for enhanced performance${NC}"
else
    echo -e "${YELLOW}⚠️  INFO: No BuildKit-enhanced Dockerfile found${NC}"
fi
echo ""

# Summary
echo -e "${GREEN}=== VALIDATION SUMMARY ===${NC}"
echo -e "${GREEN}✅ Dockerfile is compatible with Google Cloud Build${NC}"
echo -e "${GREEN}✅ No BuildKit dependencies that would cause failures${NC}"
echo -e "${GREEN}✅ Ready for deployment with 'gcloud builds submit'${NC}"
echo ""

echo -e "${BLUE}Deployment Command:${NC}"
echo -e "  ${YELLOW}gcloud builds submit --config=cloudbuild.yaml .${NC}"
echo ""

echo -e "${BLUE}For enhanced performance (if BuildKit is supported):${NC}"
echo -e "  ${YELLOW}gcloud builds submit --config=cloudbuild.buildkit.yaml .${NC}"
echo ""

echo -e "${GREEN}🎉 Validation completed successfully!${NC}"