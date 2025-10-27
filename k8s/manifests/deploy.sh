#!/bin/bash

# HAProxy Open UI - Kubernetes/OpenShift Deployment Script
# Version: 3.0
# Description: Deploy HAProxy Open UI components to Kubernetes/OpenShift (Remote HAProxy connections only)

# Exit on any error
set -e

# Color definitions for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="internal-haproxy-open-manager"
KUBECTL="${KUBECTL:-oc}"

# Utility functions
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

# Function to wait for resource to be ready
wait_for_ready() {
    local resource_type="$1"
    local name="$2"
    local timeout="${3:-300}"
    
    print_status "Waiting for $resource_type/$name to be ready (timeout: ${timeout}s)..."
    
    case "$resource_type" in
        "Deployment")
            if $KUBECTL wait --for=condition=available deployment/$name -n internal-haproxy-open-manager --timeout=${timeout}s >/dev/null 2>&1; then
                print_success "$resource_type/$name is ready"
                return 0
            fi
            ;;
        *)
            sleep 2
            if $KUBECTL get $resource_type/$name -n internal-haproxy-open-manager >/dev/null 2>&1; then
                print_success "$resource_type/$name is ready"
                return 0
            fi
            ;;
    esac
    
    print_error "$resource_type/$name failed to become ready within ${timeout}s"
    return 1
}

# Function to check if we're on OpenShift
is_openshift() {
    $KUBECTL api-versions | grep -q "route.openshift.io" 2>/dev/null || \
    $KUBECTL get crd routes.route.openshift.io >/dev/null 2>&1
}

# Function to get kubectl/oc command
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

# Main deployment function
main() {
    # Detect kubectl/oc
    KUBECTL=$(detect_kubectl)
    print_status "Using command: $KUBECTL"
    
    # Platform detection
    if is_openshift; then
        print_status "Detected OpenShift platform"
        PLATFORM="openshift"
    else
        print_status "Detected Kubernetes platform"  
        PLATFORM="kubernetes"
    fi

    print_step "Starting HAProxy Open UI deployment (Remote connections only)..."
    
    # Get current directory for relative paths
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    # Step 1: Create namespace
    print_step "1/12 - Creating namespace..."
    $KUBECTL apply -f 00-namespace.yaml
    wait_for_ready "Namespace" "$NAMESPACE"

    # Step 2: Create service accounts
    print_step "2/12 - Creating service accounts..."
    $KUBECTL apply -f 01-service-accounts.yaml
    wait_for_ready "ServiceAccount" "internal-haproxy-open-manager-backend"

    # Step 3: Create RBAC
    print_step "3/12 - Setting up RBAC..."
    $KUBECTL apply -f 02-rbac.yaml
    wait_for_ready "ClusterRole" "internal-haproxy-open-manager-role"

    # Step 4: Create secrets
    print_step "4/12 - Creating secrets..."
    $KUBECTL apply -f 03-secrets.yaml

    # Step 5: Create storage
    print_step "5/12 - Creating storage..."
    $KUBECTL apply -f 04-storage.yaml
    wait_for_ready "PersistentVolumeClaim" "postgres-pvc"

    # Step 6: Create configmaps
    print_step "6/12 - Creating configuration..."
    $KUBECTL apply -f 03-configmaps.yaml

    # Step 7: Deploy PostgreSQL
    print_step "7/12 - Deploying PostgreSQL..."
    $KUBECTL apply -f 05-postgres.yaml
    wait_for_ready "Deployment" "postgres"

    # Step 8: Deploy Redis
    print_step "8/12 - Deploying Redis..."
    $KUBECTL apply -f 06-redis.yaml
    wait_for_ready "Deployment" "redis"

    # Step 9: Deploy Backend
    print_step "9/12 - Deploying Backend API..."
    $KUBECTL apply -f 08-backend.yaml
    wait_for_ready "Deployment" "backend"

    # Step 10: Deploy Frontend
    print_step "10/12 - Deploying Frontend..."
    $KUBECTL apply -f 09-frontend.yaml
    wait_for_ready "Deployment" "frontend"

    # Step 11: Deploy Nginx
    print_step "11/12 - Deploying Nginx proxy..."
    $KUBECTL apply -f 10-nginx.yaml
    wait_for_ready "Deployment" "nginx"

    # Step 12: Create routes/ingress
    print_step "12/12 - Creating routes/ingress..."
    if [[ "$PLATFORM" == "openshift" ]]; then
        $KUBECTL apply -f 11-routes.yaml
    else
        $KUBECTL apply -f 12-ingress.yaml
    fi

    # Check deployment status
    print_step "Checking deployment status..."
    deployments=("postgres" "redis" "backend" "frontend" "nginx")
    
    for deployment in "${deployments[@]}"; do
        if $KUBECTL get deployment $deployment -n internal-haproxy-open-manager >/dev/null 2>&1; then
            ready_replicas=$($KUBECTL get deployment $deployment -n internal-haproxy-open-manager -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
            desired_replicas=$($KUBECTL get deployment $deployment -n internal-haproxy-open-manager -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
            
            if [[ "$ready_replicas" == "$desired_replicas" ]]; then
                print_success "$deployment: $ready_replicas/$desired_replicas replicas ready"
            else
                print_warning "$deployment: $ready_replicas/$desired_replicas replicas ready (may still be starting)"
            fi
        else
            print_error "$deployment: Not found"
        fi
    done

    # Show access information
    print_step "Access Information"
    
    if [[ "$PLATFORM" == "openshift" ]]; then
        frontend_route=$($KUBECTL get route frontend -n internal-haproxy-open-manager -o jsonpath='{.spec.host}' 2>/dev/null || echo "not-found")
        backend_route=$($KUBECTL get route backend -n internal-haproxy-open-manager -o jsonpath='{.spec.host}' 2>/dev/null || echo "not-found")
        
        if [[ "$frontend_route" != "not-found" ]]; then
            echo -e "${GREEN}🌐 Frontend URL: ${NC}https://$frontend_route"
        fi
        if [[ "$backend_route" != "not-found" ]]; then
            echo -e "${GREEN}🔧 Backend API: ${NC}https://$backend_route"
        fi
    else
        echo -e "${CYAN}Port-forward commands (for local access):${NC}"
        echo -e "${CYAN}Frontend:${NC} kubectl port-forward -n internal-haproxy-open-manager service/nginx 8080:80"
        echo -e "${CYAN}Backend:${NC} kubectl port-forward -n internal-haproxy-open-manager service/backend 8000:8000"
    fi

    echo -e "\n${CYAN}Useful commands:${NC}"
    echo -e "${CYAN}Check pods:${NC} $KUBECTL get pods -n internal-haproxy-open-manager"
    echo -e "${CYAN}Check logs:${NC} $KUBECTL logs -f deployment/<deployment-name> -n internal-haproxy-open-manager"
    echo -e "${CYAN}Check services:${NC} $KUBECTL get services -n internal-haproxy-open-manager"

    echo -e "\n${GREEN}📝 Note: This deployment supports remote HAProxy connections only.${NC}"
    echo -e "${GREEN}   Use SSH or Agent connection types to manage remote HAProxy instances.${NC}"
    
    print_success "🎉 HAProxy Open UI deployment completed successfully!"
}

# Run main function
main "$@" 