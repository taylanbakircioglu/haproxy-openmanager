#!/bin/bash

# HAProxy OpenManager - Soft-Deleted Entity Cleanup Script
# Version: 1.0.0
# Description: Clean up soft-deleted entities from database permanently

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
    LOGIN_RESPONSE=$(curl -k -s -X POST "$BASE_URL/api/auth/login" \
      -H "Content-Type: application/json" \
      -d '{"username": "admin", "password": "admin123"}')

    TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')

    if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
        print_error "Authentication failed!"
        echo "$LOGIN_RESPONSE" | jq '.'
        exit 1
    fi

    USERNAME=$(echo "$LOGIN_RESPONSE" | jq -r '.user.username')
    ROLE=$(echo "$LOGIN_RESPONSE" | jq -r '.user.role')
    ROLES=$(echo "$LOGIN_RESPONSE" | jq -r '.roles[].name' | tr '\n' ', ')

    print_success "Authenticated as $USERNAME"
    print_info "Role: $ROLE"
    print_info "Roles: $ROLES"
    echo ""
}

# Function to check database status
check_database_status() {
    print_info "Checking database status..."
    STATUS=$(curl -k -s -X GET "$BASE_URL/api/maintenance/database-status" \
      -H "Authorization: Bearer $TOKEN")

    if echo "$STATUS" | jq -e '.error' > /dev/null 2>&1; then
        print_error "Error getting database status:"
        echo "$STATUS" | jq '.error'
        exit 1
    fi

    echo "Current Database Status:"
    echo "$STATUS" | jq '.'
    echo ""
    
    # Extract total soft-deleted entities
    TOTAL_SOFT_DELETED=$(echo "$STATUS" | jq -r '.database_health.total_soft_deleted_entities // 0')
    CLEANUP_RECOMMENDED=$(echo "$STATUS" | jq -r '.database_health.cleanup_recommended // false')
    
    print_info "Soft-deleted entities: $TOTAL_SOFT_DELETED"
    
    if [ "$CLEANUP_RECOMMENDED" = "true" ]; then
        print_warning "Database cleanup is recommended"
    else
        print_success "Database is in good health"
    fi
    
    return $TOTAL_SOFT_DELETED
}

# Function to perform dry run
perform_dry_run() {
    print_info "Performing dry run to see what would be deleted..."
    DRY_RUN=$(curl -k -s -X POST "$BASE_URL/api/maintenance/cleanup-soft-deleted?dry_run=true" \
      -H "Authorization: Bearer $TOKEN")

    if echo "$DRY_RUN" | jq -e '.error' > /dev/null 2>&1; then
        print_error "Error during dry run:"
        echo "$DRY_RUN" | jq '.error'
        exit 1
    fi

    echo "Dry Run Results:"
    echo "$DRY_RUN" | jq '.'
    echo ""

    # Calculate total entities to delete
    TOTAL_TO_DELETE=$(echo "$DRY_RUN" | jq '[.entities_to_delete | to_entries[] | .value] | add')
    
    if [ -z "$TOTAL_TO_DELETE" ] || [ "$TOTAL_TO_DELETE" = "null" ] || [ "$TOTAL_TO_DELETE" = "0" ]; then
        TOTAL_TO_DELETE=0
    fi
    
    print_warning "Total entities to be PERMANENTLY deleted: $TOTAL_TO_DELETE"
    
    if [ "$TOTAL_TO_DELETE" = "0" ]; then
        print_success "No soft-deleted entities found. Database is clean!"
        exit 0
    fi
    
    # Show details if available
    DETAILS=$(echo "$DRY_RUN" | jq '.entities_to_delete // {}')
    if [ "$DETAILS" != "null" ] && [ "$DETAILS" != "{}" ]; then
        echo ""
        print_info "Details of entities to be deleted:"
        echo "$DRY_RUN" | jq '.entities_to_delete'
    fi
    
    return $TOTAL_TO_DELETE
}

# Function to perform actual cleanup
perform_cleanup() {
    print_info "Performing PERMANENT cleanup of soft-deleted entities..."
    CLEANUP=$(curl -k -s -X POST "$BASE_URL/api/maintenance/cleanup-soft-deleted?dry_run=false" \
      -H "Authorization: Bearer $TOKEN")

    if echo "$CLEANUP" | jq -e '.error' > /dev/null 2>&1; then
        print_error "Error during cleanup:"
        echo "$CLEANUP" | jq '.error'
        return 1
    fi

    echo "Cleanup Results:"
    echo "$CLEANUP" | jq '.'
    echo ""
    
    # Extract deleted counts
    DELETED_TOTAL=$(echo "$CLEANUP" | jq '[.entities_deleted | to_entries[] | .value] | add // 0')
    print_success "Total entities permanently deleted: $DELETED_TOTAL"
    
    return 0
}

# Function to verify cleanup
verify_cleanup() {
    print_info "Verifying cleanup completion..."
    FINAL_STATUS=$(curl -k -s -X GET "$BASE_URL/api/maintenance/database-status" \
      -H "Authorization: Bearer $TOKEN")

    echo "Final Database Status:"
    echo "$FINAL_STATUS" | jq '.'
    echo ""
    
    REMAINING_SOFT_DELETED=$(echo "$FINAL_STATUS" | jq -r '.database_health.total_soft_deleted_entities // 0')
    
    if [ "$REMAINING_SOFT_DELETED" = "0" ]; then
        print_success "Database is completely clean - no soft-deleted entities remain"
    else
        print_warning "$REMAINING_SOFT_DELETED soft-deleted entities still remain"
    fi
}

# Main function
main() {
    print_header "HAProxy OpenManager - Database Soft-Delete Cleanup"
    print_warning "This tool permanently deletes all soft-deleted entities from the database"
    print_warning "This action cannot be undone!"
    echo ""
    
    # Authenticate
    authenticate
    
    # Check database status
    check_database_status
    SOFT_DELETED_COUNT=$?
    
    if [ "$SOFT_DELETED_COUNT" = "0" ]; then
        print_success "Database is already clean - no soft-deleted entities found"
        exit 0
    fi
    
    # Perform dry run
    perform_dry_run
    ENTITIES_TO_DELETE=$?
    
    # Final confirmation
    echo ""
    print_warning "⚠️  FINAL WARNING ⚠️"
    print_warning "This will PERMANENTLY delete $ENTITIES_TO_DELETE entities from the database"
    print_warning "This action cannot be undone and the entities cannot be recovered"
    echo ""
    echo -n "Type 'CONFIRM' to proceed with permanent deletion: "
    read -r FINAL_CONFIRM
    
    if [ "$FINAL_CONFIRM" != "CONFIRM" ]; then
        print_warning "Cleanup cancelled by user"
        exit 0
    fi
    
    print_header "Performing Permanent Database Cleanup"
    
    # Perform actual cleanup
    perform_cleanup
    
    # Verify cleanup
    verify_cleanup
    
    print_header "Cleanup Complete"
    print_success "🎉 Database soft-delete cleanup completed successfully!"
    print_info "Database is now optimized and clean"
}

# Show usage if help requested
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "HAProxy OpenManager - Database Soft-Delete Cleanup"
    echo ""
    echo "This script permanently removes all soft-deleted entities from the database"
    echo "to optimize performance and clean up unused data."
    echo ""
    echo "Usage: $0"
    echo ""
    echo "The script will:"
    echo "  1. Check current database status"
    echo "  2. Show what would be deleted (dry run)"
    echo "  3. Ask for confirmation"
    echo "  4. Permanently delete soft-deleted entities"
    echo "  5. Verify cleanup completion"
    echo ""
    echo "⚠️  WARNING: This action cannot be undone!"
    exit 0
fi

# Run main function
main "$@"
