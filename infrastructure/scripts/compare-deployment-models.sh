#!/bin/bash
# iSECTECH Deployment Model Comparison and Selection Tool
# Interactive tool to analyze and select optimal deployment model
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Deployment Model Comparison

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}/../.."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}$1${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════${NC}"
}

print_comparison_table() {
    cat << 'EOF'
┌─────────────────────┬─────────────────┬─────────────────┬─────────────────────┐
│      Criteria       │  Active-Active  │ Active-Passive  │ Active-Active-Reg   │
├─────────────────────┼─────────────────┼─────────────────┼─────────────────────┤
│ Monthly Cost        │ $17,150 (1.0x)  │ $7,425 (0.43x) │ $12,540 (0.73x)    │
│ Global Latency      │ <50ms           │ <200ms          │ <80ms               │
│ Availability        │ 99.99%          │ 99.9%           │ 99.95%              │
│ RTO (Recovery)      │ <5 minutes      │ 15-30 minutes   │ 5-15 minutes        │
│ RPO (Data Loss)     │ <1 minute       │ <15 minutes     │ <5 minutes          │
│ Complexity          │ High            │ Low             │ Medium              │
│ Compliance Risk     │ Medium          │ Low             │ Low                 │
│ Operational Effort  │ High            │ Low             │ Medium              │
└─────────────────────┴─────────────────┴─────────────────┴─────────────────────┘
EOF
}

# ═══════════════════════════════════════════════════════════════════════════════
# ASSESSMENT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

assess_business_requirements() {
    log_header "BUSINESS REQUIREMENTS ASSESSMENT"
    
    echo "Please answer the following questions to assess your deployment needs:"
    echo ""
    
    # Budget assessment
    echo -e "${CYAN}1. What is your monthly infrastructure budget range?${NC}"
    echo "   a) <$10,000 (Cost-conscious)"
    echo "   b) $10,000-$15,000 (Moderate)"
    echo "   c) >$15,000 (Premium)"
    read -p "Enter choice (a/b/c): " budget_choice
    
    # Performance requirements
    echo ""
    echo -e "${CYAN}2. What are your global latency requirements?${NC}"
    echo "   a) <50ms globally (Premium performance)"
    echo "   b) <100ms regionally, <200ms globally (Good performance)"
    echo "   c) <200ms acceptable (Basic performance)"
    read -p "Enter choice (a/b/c): " latency_choice
    
    # Availability requirements
    echo ""
    echo -e "${CYAN}3. What is your availability requirement?${NC}"
    echo "   a) 99.99% (Maximum uptime)"
    echo "   b) 99.95% (High availability)"
    echo "   c) 99.9% (Standard availability)"
    read -p "Enter choice (a/b/c): " availability_choice
    
    # User distribution
    echo ""
    echo -e "${CYAN}4. How is your user base distributed?${NC}"
    echo "   a) Globally distributed evenly"
    echo "   b) Regional concentrations (US, EU, APAC)"
    echo "   c) Primarily in one region"
    read -p "Enter choice (a/b/c): " distribution_choice
    
    # Compliance requirements
    echo ""
    echo -e "${CYAN}5. What are your data compliance requirements?${NC}"
    echo "   a) Strict data residency (GDPR, CCPA, APPI)"
    echo "   b) Regional compliance preferred"
    echo "   c) Flexible data location"
    read -p "Enter choice (a/b/c): " compliance_choice
    
    # Growth projection
    echo ""
    echo -e "${CYAN}6. What is your expected growth over 2 years?${NC}"
    echo "   a) 10x+ growth expected"
    echo "   b) 3-5x growth expected"
    echo "   c) Steady growth <2x"
    read -p "Enter choice (a/b/c): " growth_choice
    
    # Store responses
    BUDGET_CHOICE=$budget_choice
    LATENCY_CHOICE=$latency_choice
    AVAILABILITY_CHOICE=$availability_choice
    DISTRIBUTION_CHOICE=$distribution_choice
    COMPLIANCE_CHOICE=$compliance_choice
    GROWTH_CHOICE=$growth_choice
}

calculate_score() {
    local model=$1
    local score=0
    
    case $model in
        "active-active")
            # Budget scoring
            case $BUDGET_CHOICE in
                "a") score=$((score - 2)) ;;  # Expensive for low budget
                "b") score=$((score + 0)) ;;  # Neutral for medium budget
                "c") score=$((score + 2)) ;;  # Good for high budget
            esac
            
            # Latency scoring
            case $LATENCY_CHOICE in
                "a") score=$((score + 3)) ;;  # Perfect for premium performance
                "b") score=$((score + 2)) ;;  # Good for good performance
                "c") score=$((score + 1)) ;;  # Overkill for basic
            esac
            
            # Availability scoring
            case $AVAILABILITY_CHOICE in
                "a") score=$((score + 3)) ;;  # Perfect for maximum uptime
                "b") score=$((score + 2)) ;;  # Good for high availability
                "c") score=$((score + 1)) ;;  # Overkill for standard
            esac
            
            # Distribution scoring
            case $DISTRIBUTION_CHOICE in
                "a") score=$((score + 3)) ;;  # Perfect for global distribution
                "b") score=$((score + 2)) ;;  # Good for regional
                "c") score=$((score + 0)) ;;  # Overkill for single region
            esac
            
            # Compliance scoring
            case $COMPLIANCE_CHOICE in
                "a") score=$((score - 1)) ;;  # Complex for strict compliance
                "b") score=$((score + 0)) ;;  # Neutral
                "c") score=$((score + 1)) ;;  # Good for flexible
            esac
            
            # Growth scoring
            case $GROWTH_CHOICE in
                "a") score=$((score + 3)) ;;  # Perfect for high growth
                "b") score=$((score + 2)) ;;  # Good for medium growth
                "c") score=$((score + 1)) ;;  # Good for steady growth
            esac
            ;;
            
        "active-passive")
            # Budget scoring
            case $BUDGET_CHOICE in
                "a") score=$((score + 3)) ;;  # Perfect for low budget
                "b") score=$((score + 2)) ;;  # Good for medium budget
                "c") score=$((score + 0)) ;;  # Acceptable for high budget
            esac
            
            # Latency scoring
            case $LATENCY_CHOICE in
                "a") score=$((score - 2)) ;;  # Poor for premium performance
                "b") score=$((score + 0)) ;;  # Acceptable for good performance
                "c") score=$((score + 2)) ;;  # Good for basic performance
            esac
            
            # Availability scoring
            case $AVAILABILITY_CHOICE in
                "a") score=$((score - 1)) ;;  # Lower than required
                "b") score=$((score + 0)) ;;  # Below target
                "c") score=$((score + 2)) ;;  # Meets standard requirement
            esac
            
            # Distribution scoring
            case $DISTRIBUTION_CHOICE in
                "a") score=$((score - 2)) ;;  # Poor for global distribution
                "b") score=$((score + 0)) ;;  # Acceptable for regional
                "c") score=$((score + 3)) ;;  # Perfect for single region
            esac
            
            # Compliance scoring
            case $COMPLIANCE_CHOICE in
                "a") score=$((score + 3)) ;;  # Perfect for strict compliance
                "b") score=$((score + 2)) ;;  # Good for regional compliance
                "c") score=$((score + 1)) ;;  # Good for flexible
            esac
            
            # Growth scoring
            case $GROWTH_CHOICE in
                "a") score=$((score - 1)) ;;  # May not scale well
                "b") score=$((score + 1)) ;;  # Acceptable for medium growth
                "c") score=$((score + 2)) ;;  # Good for steady growth
            esac
            ;;
            
        "active-active-regional")
            # Budget scoring
            case $BUDGET_CHOICE in
                "a") score=$((score + 0)) ;;  # Moderate for low budget
                "b") score=$((score + 3)) ;;  # Perfect for medium budget
                "c") score=$((score + 2)) ;;  # Good for high budget
            esac
            
            # Latency scoring
            case $LATENCY_CHOICE in
                "a") score=$((score + 2)) ;;  # Good for premium performance
                "b") score=$((score + 3)) ;;  # Perfect for good performance
                "c") score=$((score + 2)) ;;  # Good for basic performance
            esac
            
            # Availability scoring
            case $AVAILABILITY_CHOICE in
                "a") score=$((score + 2)) ;;  # Good for maximum uptime
                "b") score=$((score + 3)) ;;  # Perfect for high availability
                "c") score=$((score + 2)) ;;  # Good for standard
            esac
            
            # Distribution scoring
            case $DISTRIBUTION_CHOICE in
                "a") score=$((score + 2)) ;;  # Good for global distribution
                "b") score=$((score + 3)) ;;  # Perfect for regional
                "c") score=$((score + 1)) ;;  # Acceptable for single region
            esac
            
            # Compliance scoring
            case $COMPLIANCE_CHOICE in
                "a") score=$((score + 3)) ;;  # Perfect for strict compliance
                "b") score=$((score + 3)) ;;  # Perfect for regional compliance
                "c") score=$((score + 2)) ;;  # Good for flexible
            esac
            
            # Growth scoring
            case $GROWTH_CHOICE in
                "a") score=$((score + 2)) ;;  # Good for high growth
                "b") score=$((score + 3)) ;;  # Perfect for medium growth
                "c") score=$((score + 2)) ;;  # Good for steady growth
            esac
            ;;
    esac
    
    echo $score
}

generate_recommendation() {
    log_header "DEPLOYMENT MODEL RECOMMENDATION"
    
    local aa_score=$(calculate_score "active-active")
    local ap_score=$(calculate_score "active-passive")
    local aar_score=$(calculate_score "active-active-regional")
    
    echo "Based on your requirements assessment:"
    echo ""
    echo -e "${CYAN}Deployment Model Scores:${NC}"
    echo "  Active-Active:          $aa_score points"
    echo "  Active-Passive:         $ap_score points"
    echo "  Active-Active Regional: $aar_score points"
    echo ""
    
    # Determine recommendation
    local max_score=-10
    local recommended_model=""
    
    if [ $aa_score -gt $max_score ]; then
        max_score=$aa_score
        recommended_model="active-active"
    fi
    
    if [ $ap_score -gt $max_score ]; then
        max_score=$ap_score
        recommended_model="active-passive"
    fi
    
    if [ $aar_score -gt $max_score ]; then
        max_score=$aar_score
        recommended_model="active-active-regional"
    fi
    
    case $recommended_model in
        "active-active")
            log_success "RECOMMENDED: Active-Active Deployment Model"
            echo ""
            echo -e "${GREEN}Why this model fits your needs:${NC}"
            echo "  ✓ Provides maximum global performance and availability"
            echo "  ✓ Handles high traffic and global user distribution"
            echo "  ✓ Supports aggressive growth projections"
            echo "  ✓ Premium infrastructure investment justified"
            echo ""
            echo -e "${YELLOW}Consider these challenges:${NC}"
            echo "  ⚠ Higher operational complexity"
            echo "  ⚠ Increased infrastructure costs"
            echo "  ⚠ Complex compliance management"
            ;;
            
        "active-passive")
            log_success "RECOMMENDED: Active-Passive Deployment Model"
            echo ""
            echo -e "${GREEN}Why this model fits your needs:${NC}"
            echo "  ✓ Most cost-effective solution"
            echo "  ✓ Simplifies operations and compliance"
            echo "  ✓ Suitable for regional user concentration"
            echo "  ✓ Easy to implement and maintain"
            echo ""
            echo -e "${YELLOW}Consider these limitations:${NC}"
            echo "  ⚠ Higher latency for distant users"
            echo "  ⚠ Longer recovery times during failures"
            echo "  ⚠ May not scale well for global expansion"
            ;;
            
        "active-active-regional")
            log_success "RECOMMENDED: Active-Active Regional (Hybrid) Model"
            echo ""
            echo -e "${GREEN}Why this model fits your needs:${NC}"
            echo "  ✓ Optimal balance of performance and cost"
            echo "  ✓ Excellent compliance and data residency support"
            echo "  ✓ Scales well with regional growth patterns"
            echo "  ✓ Provides regional redundancy with global backup"
            echo ""
            echo -e "${YELLOW}Consider these aspects:${NC}"
            echo "  ⚠ Moderate operational complexity"
            echo "  ⚠ Mixed synchronization patterns"
            echo "  ⚠ Requires regional expertise"
            ;;
    esac
    
    RECOMMENDED_MODEL=$recommended_model
}

show_cost_analysis() {
    log_header "COST ANALYSIS"
    
    echo -e "${CYAN}Monthly Infrastructure Costs:${NC}"
    echo ""
    printf "%-25s %-15s %-15s %-20s\n" "Component" "Active-Active" "Active-Passive" "Regional Hybrid"
    printf "%-25s %-15s %-15s %-20s\n" "─────────" "─────────────" "──────────────" "───────────────"
    printf "%-25s %-15s %-15s %-20s\n" "Compute (GKE)" "\$8,500" "\$3,500" "\$6,000"
    printf "%-25s %-15s %-15s %-20s\n" "Database (Cloud SQL)" "\$3,600" "\$1,800" "\$2,800"
    printf "%-25s %-15s %-15s %-20s\n" "Load Balancing" "\$800" "\$300" "\$600"
    printf "%-25s %-15s %-15s %-20s\n" "Storage" "\$1,200" "\$600" "\$900"
    printf "%-25s %-15s %-15s %-20s\n" "Network/CDN" "\$2,200" "\$800" "\$1,600"
    printf "%-25s %-15s %-15s %-20s\n" "Monitoring" "\$400" "\$200" "\$300"
    printf "%-25s %-15s %-15s %-20s\n" "Other Services" "\$450" "\$225" "\$340"
    echo "─────────────────────────────────────────────────────────────────────────"
    printf "%-25s %-15s %-15s %-20s\n" "TOTAL MONTHLY" "\$17,150" "\$7,425" "\$12,540"
    printf "%-25s %-15s %-15s %-20s\n" "ANNUAL COST" "\$205,800" "\$89,100" "\$150,480"
    echo ""
    
    echo -e "${CYAN}3-Year TCO Projection:${NC}"
    echo ""
    printf "%-20s %-15s %-15s %-20s\n" "Year" "Active-Active" "Active-Passive" "Regional Hybrid"
    printf "%-20s %-15s %-15s %-20s\n" "────" "─────────────" "──────────────" "───────────────"
    printf "%-20s %-15s %-15s %-20s\n" "Year 1" "\$205,800" "\$89,100" "\$150,480"
    printf "%-20s %-15s %-15s %-20s\n" "Year 2" "\$226,380" "\$98,010" "\$165,528"
    printf "%-20s %-15s %-15s %-20s\n" "Year 3" "\$249,018" "\$107,811" "\$182,081"
    echo "─────────────────────────────────────────────────────────────────────────"
    printf "%-20s %-15s %-15s %-20s\n" "3-Year Total" "\$681,198" "\$294,921" "\$498,089"
}

show_performance_comparison() {
    log_header "PERFORMANCE COMPARISON"
    
    echo -e "${CYAN}Global Latency (95th percentile):${NC}"
    echo ""
    printf "%-20s %-15s %-15s %-20s\n" "User Location" "Active-Active" "Active-Passive" "Regional Hybrid"
    printf "%-20s %-15s %-15s %-20s\n" "─────────────" "─────────────" "──────────────" "───────────────"
    printf "%-20s %-15s %-15s %-20s\n" "US East Coast" "45ms" "50ms" "45ms"
    printf "%-20s %-15s %-15s %-20s\n" "US West Coast" "25ms" "25ms" "25ms"
    printf "%-20s %-15s %-15s %-20s\n" "London, UK" "35ms" "180ms" "35ms"
    printf "%-20s %-15s %-15s %-20s\n" "Frankfurt, DE" "25ms" "190ms" "25ms"
    printf "%-20s %-15s %-15s %-20s\n" "Tokyo, JP" "40ms" "220ms" "40ms"
    printf "%-20s %-15s %-15s %-20s\n" "Sydney, AU" "80ms" "280ms" "80ms"
    echo ""
    
    echo -e "${CYAN}Availability and Recovery:${NC}"
    echo ""
    printf "%-20s %-15s %-15s %-20s\n" "Metric" "Active-Active" "Active-Passive" "Regional Hybrid"
    printf "%-20s %-15s %-15s %-20s\n" "──────" "─────────────" "──────────────" "───────────────"
    printf "%-20s %-15s %-15s %-20s\n" "Availability" "99.99%" "99.9%" "99.95%"
    printf "%-20s %-15s %-15s %-20s\n" "RTO (Recovery)" "<5 minutes" "15-30 minutes" "5-15 minutes"
    printf "%-20s %-15s %-15s %-20s\n" "RPO (Data Loss)" "<1 minute" "<15 minutes" "<5 minutes"
    printf "%-20s %-15s %-15s %-20s\n" "Global RPS" "150,000" "50,000" "120,000"
}

update_terraform_config() {
    local selected_model=$1
    local tfvars_file="${SCRIPT_DIR}/../terraform/multi-region.tfvars"
    
    log_info "Updating Terraform configuration with selected model: $selected_model"
    
    # Create backup
    cp "$tfvars_file" "${tfvars_file}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Update deployment model
    sed -i.tmp "s/^deployment_model.*=.*/deployment_model        = \"$selected_model\"/" "$tfvars_file"
    rm "${tfvars_file}.tmp"
    
    # Update traffic distribution based on model
    case $selected_model in
        "active-active")
            log_info "Configuring for full active-active deployment"
            ;;
        "active-passive")
            log_info "Configuring for active-passive deployment"
            # Update traffic distribution to route 100% to primary
            sed -i.tmp '/traffic_distribution = {/,/}/ s/"us-central1"[[:space:]]*=[[:space:]]*[0-9]*/"us-central1"     = 100/' "$tfvars_file"
            sed -i.tmp '/traffic_distribution = {/,/}/ s/"europe-west4"[[:space:]]*=[[:space:]]*[0-9]*/"europe-west4"    = 0/' "$tfvars_file"
            sed -i.tmp '/traffic_distribution = {/,/}/ s/"asia-northeast1"[[:space:]]*=[[:space:]]*[0-9]*/"asia-northeast1" = 0/' "$tfvars_file"
            rm "${tfvars_file}.tmp"
            ;;
        "active-active-regional")
            log_info "Configuring for regional hybrid deployment"
            # Keep existing balanced distribution for primary regions
            ;;
    esac
    
    log_success "Terraform configuration updated successfully"
    log_info "Backup saved as: ${tfvars_file}.backup.*"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

interactive_assessment() {
    log_header "ISECTECH DEPLOYMENT MODEL SELECTION TOOL"
    
    echo -e "${CYAN}This tool will help you select the optimal deployment model for your multi-region architecture.${NC}"
    echo ""
    
    # Run assessment
    assess_business_requirements
    echo ""
    
    # Show comparison table
    log_header "DEPLOYMENT MODEL COMPARISON"
    print_comparison_table
    echo ""
    
    # Generate recommendation
    generate_recommendation
    echo ""
    
    # Show detailed analysis
    show_cost_analysis
    echo ""
    show_performance_comparison
    echo ""
    
    # Confirm selection
    echo -e "${CYAN}Do you want to proceed with the recommended model: $RECOMMENDED_MODEL? (y/N)${NC}"
    read -p "Enter choice: " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        update_terraform_config "$RECOMMENDED_MODEL"
        echo ""
        log_success "Configuration updated! You can now deploy with:"
        echo "  cd infrastructure/scripts"
        echo "  ./deploy-multi-region.sh"
    else
        echo ""
        echo -e "${CYAN}Would you like to select a different model? (y/N)${NC}"
        read -p "Enter choice: " manual_select
        
        if [[ $manual_select =~ ^[Yy]$ ]]; then
            echo ""
            echo "Available models:"
            echo "  1) active-active"
            echo "  2) active-passive" 
            echo "  3) active-active-regional"
            read -p "Select model (1/2/3): " model_choice
            
            case $model_choice in
                1) update_terraform_config "active-active" ;;
                2) update_terraform_config "active-passive" ;;
                3) update_terraform_config "active-active-regional" ;;
                *) log_error "Invalid choice. Configuration not updated." ;;
            esac
        else
            log_info "Configuration not updated. You can run this tool again later."
        fi
    fi
}

show_help() {
    cat << EOF
iSECTECH Deployment Model Comparison Tool

Usage: $0 [COMMAND]

Commands:
  interactive    Run interactive assessment and configuration (default)
  compare        Show detailed comparison table
  cost           Show cost analysis
  performance    Show performance comparison  
  help           Show this help message

Examples:
  $0                    # Run interactive assessment
  $0 interactive        # Same as above
  $0 compare           # Show comparison table only
  $0 cost              # Show cost analysis only

This tool helps select the optimal deployment model for your multi-region
iSECTECH deployment based on business requirements, performance needs,
compliance requirements, and budget constraints.

EOF
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCRIPT EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

case "${1:-interactive}" in
    "interactive")
        interactive_assessment
        ;;
    "compare")
        log_header "DEPLOYMENT MODEL COMPARISON"
        print_comparison_table
        ;;
    "cost")
        show_cost_analysis
        ;;
    "performance")
        show_performance_comparison
        ;;
    "help"|"--help"|"-h")
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac