#!/bin/bash

# HAProxy OpenManager - Docker Image Build Script for OpenShift
# This script builds and pushes production-ready Docker images

set -e

echo "🐳 Building HAProxy OpenManager Docker Images for OpenShift"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
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

# Configuration
# Set REGISTRY environment variable or use default
# Example: export REGISTRY="taylanbakircioglu"
REGISTRY="${REGISTRY:-taylanbakircioglu}"
BACKEND_IMAGE="${REGISTRY}/haproxy-openmanager-backend"
FRONTEND_IMAGE="${REGISTRY}/haproxy-openmanager-frontend"
VERSION="${VERSION:-latest}"

print_status "Registry: $REGISTRY"
print_status "Backend Image: $BACKEND_IMAGE:$VERSION"
print_status "Frontend Image: $FRONTEND_IMAGE:$VERSION"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed or not in PATH"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    print_error "Docker daemon is not running"
    exit 1
fi

# Check if we're logged into the registry
print_status "Checking registry login..."
if ! docker system info | grep -q "Registry Mirrors"; then
    print_warning "You may need to login to the registry:"
    echo "docker login $REGISTRY"
fi

# Build Backend Image
print_status "Building Backend Image..."
cd backend
docker build -t $BACKEND_IMAGE:$VERSION \
    --platform linux/amd64 \
    --no-cache .
cd ..
print_success "Backend image built: $BACKEND_IMAGE:$VERSION"

# Build Frontend Image
print_status "Building Frontend Image..."
cd frontend
docker build -t $FRONTEND_IMAGE:$VERSION \
    --platform linux/amd64 \
    --no-cache .
cd ..
print_success "Frontend image built: $FRONTEND_IMAGE:$VERSION"

# Push Images
read -p "Push images to registry? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Pushing Backend Image..."
    docker push $BACKEND_IMAGE:$VERSION
    print_success "Backend image pushed"

    print_status "Pushing Frontend Image..."
    docker push $FRONTEND_IMAGE:$VERSION
    print_success "Frontend image pushed"
    
    print_success "All images pushed successfully!"
else
    print_status "Images built but not pushed"
fi

# Update Kubernetes manifests
print_status "Updating Kubernetes manifests with new image versions..."

# Update backend deployment
sed -i.bak "s|image: taylanbakircioglu/haproxy-openmanager-backend:latest|image: $BACKEND_IMAGE:$VERSION|g" k8s/manifests/08-backend.yaml

# Update frontend deployment  
sed -i.bak "s|image: taylanbakircioglu/haproxy-openmanager-frontend:latest|image: $FRONTEND_IMAGE:$VERSION|g" k8s/manifests/09-frontend.yaml

print_success "Kubernetes manifests updated"

# Show image sizes
echo
print_status "Image Information:"
docker images | grep -E "(haproxy-openmanager|REPOSITORY)"

echo
print_status "Next steps:"
echo "1. Deploy to OpenShift:"
echo "   ./k8s/manifests/deploy.sh"
echo
echo "2. Or apply specific components:"
echo "   oc apply -f k8s/manifests/08-backend.yaml"
echo "   oc apply -f k8s/manifests/09-frontend.yaml"
echo
echo "3. Check deployment status:"
echo "   oc get pods -n haproxy-openmanager"
echo "   oc logs -f deployment/backend -n haproxy-openmanager"
echo "   oc logs -f deployment/frontend -n haproxy-openmanager"

print_success "Docker image build completed!" 