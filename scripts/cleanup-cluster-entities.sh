#!/bin/bash

# HAProxy OpenManager - Cluster Entity Cleanup Script
# Version: 1.0.0
# Description: Comprehensive cleanup of all frontends and backends for a specific cluster

set -e

# Configuration
BASE_URL="https://haproxy-openmanager.example.com"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "\n${BLUE}===========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===========================================${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Function to authenticate
authenticate() {
    echo "🔐 Authenticating..."
    TOKEN=$(curl -k -s -X POST "${BASE_URL}/api/auth/login" \
      -H "Content-Type: application/json" \
      -d '{"username": "admin", "password": "admin123"}' | jq -r '.access_token')

    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
        print_error "Authentication failed!"
        exit 1
    fi
    print_success "Authenticated as admin"
    echo ""
}

# Function to get cluster by name or ID
get_cluster_info() {
    local cluster_input="$1"
    
    print_info "Fetching cluster information..."
    CLUSTERS_RESPONSE=$(curl -k -s -X GET "${BASE_URL}/api/clusters" \
        -H "Authorization: Bearer ${TOKEN}")
    
    if echo "$CLUSTERS_RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
        print_error "Failed to fetch clusters:"
        echo "$CLUSTERS_RESPONSE" | jq '.error'
        exit 1
    fi
    
    # Try to find cluster by ID first (if numeric), then by name
    if [[ "$cluster_input" =~ ^[0-9]+$ ]]; then
        # Input is numeric - search by ID
        CLUSTER_INFO=$(echo "$CLUSTERS_RESPONSE" | jq -r ".clusters[] | select(.id == $cluster_input)")
    else
        # Input is text - search by name (case insensitive)
        CLUSTER_INFO=$(echo "$CLUSTERS_RESPONSE" | jq -r ".clusters[] | select(.name | ascii_downcase == \"$(echo "$cluster_input" | tr '[:upper:]' '[:lower:]')\")")
    fi
    
    if [ -z "$CLUSTER_INFO" ] || [ "$CLUSTER_INFO" = "null" ]; then
        print_error "Cluster not found: '$cluster_input'"
        echo ""
        print_info "Available clusters:"
        echo "$CLUSTERS_RESPONSE" | jq -r '.clusters[] | "  - \(.name) (ID: \(.id))"'
        exit 1
    fi
    
    CLUSTER_ID=$(echo "$CLUSTER_INFO" | jq -r '.id')
    CLUSTER_NAME=$(echo "$CLUSTER_INFO" | jq -r '.name')
    
    print_success "Found cluster: $CLUSTER_NAME (ID: $CLUSTER_ID)"
    echo ""
}

# Function to clean backends
cleanup_backends() {
    print_info "Fetching backends for cluster $CLUSTER_NAME..."
    BACKENDS=$(curl -k -s -X GET "${BASE_URL}/api/backends?cluster_id=${CLUSTER_ID}" \
        -H "Authorization: Bearer ${TOKEN}")

    if echo "$BACKENDS" | jq -e '.error' > /dev/null 2>&1; then
        print_error "Failed to fetch backends:"
        echo "$BACKENDS" | jq '.error'
        return 1
    fi

    BACKEND_IDS=$(echo "$BACKENDS" | python3 -c "import sys, json; data = json.load(sys.stdin); print(' '.join([str(b['id']) for b in data.get('backends', [])]))")

    backend_count=$(echo $BACKEND_IDS | wc -w | tr -d ' ')
    print_info "Found ${backend_count} backends"

    if [ "$backend_count" = "0" ]; then
        print_warning "No backends found for cluster $CLUSTER_NAME"
        return 0
    fi

    echo ""
    deleted_backends=0
    for id in $BACKEND_IDS; do
        name=$(echo "$BACKENDS" | python3 -c "import sys, json; data = json.load(sys.stdin); print([b['name'] for b in data.get('backends', []) if b['id'] == $id][0])")
        echo "Deleting backend: $name (ID: $id)"
        
        response=$(curl -k -s -X DELETE "${BASE_URL}/api/backends/${id}" \
            -H "Authorization: Bearer ${TOKEN}")
        
        if echo "$response" | grep -q "deleted\|updated"; then
            echo "  ✅ Success"
            ((deleted_backends++))
        else
            echo "  ❌ Failed: $response"
        fi
    done

    echo ""
    print_success "Deleted ${deleted_backends} backends"
    
    # Apply backend deletions
    if [ $deleted_backends -gt 0 ]; then
        echo ""
        print_info "Applying backend deletions to agents..."
        apply_response=$(curl -k -s -X POST "${BASE_URL}/api/clusters/${CLUSTER_ID}/apply-changes" \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json" \
            -d '{}' | jq -r '.message')
        print_success "Apply result: $apply_response"
        print_info "Waiting 5 seconds for agent synchronization..."
        sleep 5
    fi
    
    return $deleted_backends
}

# Function to clean frontends
cleanup_frontends() {
    print_info "Fetching frontends for cluster $CLUSTER_NAME..."
    FRONTENDS=$(curl -k -s -X GET "${BASE_URL}/api/frontends?cluster_id=${CLUSTER_ID}" \
        -H "Authorization: Bearer ${TOKEN}")

    if echo "$FRONTENDS" | jq -e '.error' > /dev/null 2>&1; then
        print_error "Failed to fetch frontends:"
        echo "$FRONTENDS" | jq '.error'
        return 1
    fi

    FRONTEND_IDS=$(echo "$FRONTENDS" | python3 -c "import sys, json; data = json.load(sys.stdin); print(' '.join([str(f['id']) for f in data.get('frontends', [])]))")

    frontend_count=$(echo $FRONTEND_IDS | wc -w | tr -d ' ')
    print_info "Found ${frontend_count} frontends"

    if [ "$frontend_count" = "0" ]; then
        print_warning "No frontends found for cluster $CLUSTER_NAME"
        return 0
    fi

    echo ""
    deleted_frontends=0
    for id in $FRONTEND_IDS; do
        name=$(echo "$FRONTENDS" | python3 -c "import sys, json; data = json.load(sys.stdin); print([f['name'] for f in data.get('frontends', []) if f['id'] == $id][0])")
        echo "Deleting frontend: $name (ID: $id)"
        
        response=$(curl -k -s -X DELETE "${BASE_URL}/api/frontends/${id}" \
            -H "Authorization: Bearer ${TOKEN}")
        
        if echo "$response" | grep -q "deleted\|updated"; then
            echo "  ✅ Success"
            ((deleted_frontends++))
        else
            echo "  ❌ Failed: $response"
        fi
    done

    echo ""
    print_success "Deleted ${deleted_frontends} frontends"
    
    # Apply frontend deletions
    if [ $deleted_frontends -gt 0 ]; then
        echo ""
        print_info "Applying frontend deletions to agents..."
        apply_response=$(curl -k -s -X POST "${BASE_URL}/api/clusters/${CLUSTER_ID}/apply-changes" \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json" \
            -d '{}' | jq -r '.message')
        print_success "Apply result: $apply_response"
    fi
    
    return $deleted_frontends
}

# Main function
main() {
    print_header "HAProxy OpenManager - Cluster Entity Cleanup"
    echo ""
    
    # Get cluster information from user
    if [ $# -eq 0 ]; then
        echo -n "Enter cluster name or ID: "
        read -r CLUSTER_INPUT
    else
        CLUSTER_INPUT="$1"
    fi
    
    if [ -z "$CLUSTER_INPUT" ]; then
        print_error "Cluster name or ID is required"
        echo ""
        echo "Usage: $0 [cluster_name_or_id]"
        echo "   or: $0"
        echo "       (will prompt for cluster)"
        exit 1
    fi
    
    # Authenticate
    authenticate
    
    # Get cluster information
    get_cluster_info "$CLUSTER_INPUT"
    
    # Confirmation prompt
    print_warning "WARNING: This will DELETE ALL frontends and backends from cluster: $CLUSTER_NAME"
    print_warning "This action cannot be undone!"
    echo ""
    echo -n "Are you sure you want to continue? (yes/no): "
    read -r CONFIRM
    
    if [ "$CONFIRM" != "yes" ]; then
        print_warning "Cleanup cancelled by user"
        exit 0
    fi
    
    echo ""
    print_header "Starting Cleanup for Cluster: $CLUSTER_NAME"
    
    # Clean backends
    cleanup_backends
    BACKENDS_DELETED=$?
    
    # Clean frontends  
    cleanup_frontends
    FRONTENDS_DELETED=$?
    
    # Final summary
    print_header "Cleanup Summary"
    echo -e "${CYAN}Cluster:${NC} $CLUSTER_NAME (ID: $CLUSTER_ID)"
    echo -e "${GREEN}Backends deleted:${NC} $BACKENDS_DELETED"
    echo -e "${GREEN}Frontends deleted:${NC} $FRONTENDS_DELETED"
    echo -e "${GREEN}Total entities deleted:${NC} $((BACKENDS_DELETED + FRONTENDS_DELETED))"
    echo ""
    print_success "🎉 Cluster cleanup completed successfully!"
    echo ""
    print_info "Note: Cluster '$CLUSTER_NAME' can now be safely deleted if needed"
}

# Run main function with all arguments
main "$@"
