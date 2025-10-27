#!/bin/bash

# HAProxy Open UI - Kubernetes/OpenShift Cleanup Script
# Version: 3.0 (Remote HAProxy connections only)

# Exit on any error
set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="internal-haproxy-open-manager"
KUBECTL="${KUBECTL:-oc}"

# Print functions
print_step() {
    echo -e "\n${BLUE}===========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===========================================${NC}"
}

print_status() {
    echo -e "${CYAN}[INFO]${NC} $1"
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

# Function to delete resource safely
delete_resource() {
    local resource_type="$1"
    local resource_name="$2"
    local namespace_flag="$3"
    
    if [[ "$namespace_flag" == "cluster" ]]; then
        if $KUBECTL get $resource_type $resource_name >/dev/null 2>&1; then
            if $KUBECTL delete $resource_type $resource_name --timeout=60s 2>/dev/null; then
                print_success "$resource_type/$resource_name deleted"
            else
                print_warning "Failed to delete $resource_type/$resource_name"
            fi
        else
            print_status "$resource_type/$resource_name not found, skipping..."
        fi
    else
        if $KUBECTL get $resource_type $resource_name -n $NAMESPACE >/dev/null 2>&1; then
            if $KUBECTL delete $resource_type $resource_name -n $NAMESPACE --timeout=60s 2>/dev/null; then
                print_success "$resource_type/$resource_name deleted"
            else
                print_warning "Failed to delete $resource_type/$resource_name"
            fi
        else
            print_status "$resource_type/$resource_name not found, skipping..."
        fi
    fi
}

# Function to check if we're on OpenShift
is_openshift() {
    $KUBECTL api-versions | grep -q "route.openshift.io" 2>/dev/null || \
    $KUBECTL get crd routes.route.openshift.io >/dev/null 2>&1
}

# Function to detect kubectl/oc
detect_kubectl() {
    if command -v oc >/dev/null 2>&1 && is_openshift; then
        echo "oc"
    elif command -v kubectl >/dev/null 2>&1; then
        echo "kubectl"
    else
        echo "ERROR: Neither 'oc' nor 'kubectl' found in PATH" >&2
        exit 1
    fi
}

# Main cleanup function
main() {
    # Detect kubectl/oc
    KUBECTL=$(detect_kubectl)
    print_status "Using command: $KUBECTL"
    
    # Check if namespace exists
    if ! $KUBECTL get namespace internal-haproxy-open-manager >/dev/null 2>&1; then
        print_warning "Namespace 'internal-haproxy-open-manager' not found. Nothing to clean up."
        exit 0
    fi

    # Security check - ensure we're only working with internal-haproxy-open-manager namespace
    NAMESPACE="internal-haproxy-open-manager"
    
    print_step "Starting HAProxy Open UI cleanup (Remote connections only)..."
    
    # Get script directory for relative paths
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    # Step 1: Delete Routes/Ingress
    print_step "1/11 - Removing routes/ingress..."
    if is_openshift; then
        if [[ -f "11-routes.yaml" ]]; then
            $KUBECTL delete -f 11-routes.yaml --ignore-not-found=true --timeout=60s || true
            print_success "Routes removed"
        fi
    else
        if [[ -f "12-ingress.yaml" ]]; then
            $KUBECTL delete -f 12-ingress.yaml --ignore-not-found=true --timeout=60s || true
            print_success "Ingress removed"
        fi
    fi

    # Step 2: Delete Nginx
    print_step "2/11 - Removing Nginx..."
    delete_resource "deployment" "nginx" "namespaced"
    delete_resource "service" "nginx" "namespaced"
    delete_resource "configmap" "nginx-nonroot-config" "namespaced"

    # Step 3: Delete Frontend
    print_step "3/11 - Removing Frontend..."
    delete_resource "deployment" "frontend" "namespaced"
    delete_resource "service" "frontend" "namespaced"

    # Step 4: Delete Backend
    print_step "4/11 - Removing Backend..."
    delete_resource "deployment" "backend" "namespaced"
    delete_resource "service" "backend" "namespaced"

    # Step 5: Delete Redis
    print_step "5/11 - Removing Redis..."
    delete_resource "deployment" "redis" "namespaced"
    delete_resource "service" "redis" "namespaced"

    # Step 6: Gracefully stop PostgreSQL
    print_step "6/11 - Stopping PostgreSQL gracefully..."
    if $KUBECTL get deployment postgres -n internal-haproxy-open-manager >/dev/null 2>&1; then
        print_status "Scaling PostgreSQL to 0 replicas..."
        $KUBECTL scale deployment postgres --replicas=0 -n internal-haproxy-open-manager >/dev/null 2>&1 || true
        sleep 5
        
        print_status "Deleting PostgreSQL deployment..."
        delete_resource "deployment" "postgres" "namespaced"
        delete_resource "service" "postgres" "namespaced"
    else
        print_status "PostgreSQL deployment not found, skipping..."
    fi

    # Step 7: Delete Storage
    print_step "7/11 - Removing storage..."
    delete_resource "pvc" "postgres-pvc" "namespaced"
    delete_resource "pvc" "redis-pvc" "namespaced"

    # Step 8: Delete ConfigMaps and Secrets
    print_step "8/11 - Removing configuration and secrets..."
    delete_resource "configmap" "backend-config" "namespaced"
    delete_resource "configmap" "frontend-config" "namespaced"

    delete_resource "secret" "postgres-secret" "namespaced"
    delete_resource "secret" "backend-secret" "namespaced"

    # Step 9: Delete RBAC
    print_step "9/11 - Removing RBAC..."
    delete_resource "clusterrolebinding" "internal-haproxy-open-manager-binding" "cluster"
    delete_resource "clusterrole" "internal-haproxy-open-manager-role" "cluster"

    # Step 10: Delete Service Accounts
    print_step "10/11 - Removing service accounts..."
    delete_resource "serviceaccount" "internal-haproxy-open-manager-backend" "namespaced"
    delete_resource "serviceaccount" "internal-haproxy-open-manager-frontend" "namespaced"
    delete_resource "serviceaccount" "internal-haproxy-open-manager-postgres" "namespaced"
    delete_resource "serviceaccount" "internal-haproxy-open-manager-redis" "namespaced"
    delete_resource "serviceaccount" "internal-haproxy-open-manager-nginx" "namespaced"

    # Step 11: Final cleanup
    print_step "11/11 - Final cleanup..."
    
    # Clean up any remaining pods
    print_status "Cleaning up remaining pods..."
    $KUBECTL delete pods --all -n $NAMESPACE --ignore-not-found=true --timeout=60s 2>/dev/null || true
    
    # Wait a moment for pods to terminate
    sleep 3
    
    # Check for any remaining resources
    print_status "Checking for remaining resources..."
    remaining_pods=$($KUBECTL get pods -n $NAMESPACE --no-headers 2>/dev/null | wc -l || echo "0")
    remaining_deployments=$($KUBECTL get deployments -n $NAMESPACE --no-headers 2>/dev/null | wc -l || echo "0")
    remaining_services=$($KUBECTL get services -n $NAMESPACE --no-headers 2>/dev/null | wc -l || echo "0")
    
    if [[ "$remaining_pods" -gt 0 ]] || [[ "$remaining_deployments" -gt 0 ]] || [[ "$remaining_services" -gt 0 ]]; then
        print_warning "Some resources may still be terminating:"
        [[ "$remaining_pods" -gt 0 ]] && echo "  - Pods: $remaining_pods"
        [[ "$remaining_deployments" -gt 0 ]] && echo "  - Deployments: $remaining_deployments"
        [[ "$remaining_services" -gt 0 ]] && echo "  - Services: $remaining_services"
    else
        print_success "All resources cleaned up successfully"
    fi

    # Show final status
    print_step "Cleanup Summary"
    echo -e "${GREEN}✅ HAProxy Open UI cleanup completed${NC}"
    echo -e "${CYAN}📝 Note: Namespace '$NAMESPACE' was preserved${NC}"
    echo -e "${CYAN}📝 Note: PersistentVolumes may need manual cleanup if using dynamic provisioning${NC}"
    
    print_success "🎉 HAProxy Open UI cleanup completed successfully!"
}

# Run main function
main "$@" 