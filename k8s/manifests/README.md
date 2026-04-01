# HAProxy Open UI - Kubernetes/OpenShift Deployment

This directory contains all the necessary Kubernetes/OpenShift manifests to deploy the HAProxy Open UI application.

## Security Context

### OpenShift Security Context Constraints (SCC)

The HAProxy instance requires `anyuid` SCC permissions to:
- Install SSH server components (openssh-server, dropbear)
- Bind to required ports (8080, 8081, 8404, 2222)
- Manage user accounts and file permissions

The deployment script automatically grants this permission, but if needed manually:

```bash
# Grant anyuid SCC to HAProxy service account
oc adm policy add-scc-to-user anyuid system:serviceaccount:haproxy-openmanager:haproxy-openmanager-haproxy

# Verify SCC assignment
oc describe scc anyuid | grep Users
```

**Note:** The `anyuid` SCC allows the container to run as any user ID, which is necessary for HAProxy's SSH server functionality and port binding in OpenShift environments.

## 📁 File Structure

```
k8s/manifests/
├── 00-namespace.yaml          # Namespace creation
├── 01-service-accounts.yaml   # Service accounts for all components
├── 02-rbac.yaml              # RBAC policies (if needed)
├── 02-secrets.yaml           # Secrets (if needed)
├── 03-configmaps.yaml        # Configuration maps and database init
├── 04-storage.yaml           # Persistent Volume Claims (PVCs)
├── 05-postgres.yaml          # PostgreSQL database
├── 06-redis.yaml             # Redis cache
├── 07-backend.yaml           # FastAPI backend
├── 07-haproxy.yaml           # HAProxy instance with SSH access
├── 08-frontend.yaml          # React frontend
├── 09-nginx.yaml             # Nginx reverse proxy
├── 10-routes.yaml            # OpenShift Routes
├── 11-ingress.yaml           # Kubernetes Ingress (if needed)
├── 12-hpa.yaml               # Horizontal Pod Autoscaler (if needed)
├── deploy.sh                 # Automated deployment script
├── cleanup.sh                # Automated cleanup script
└── README.md                 # This file
```

## 🚀 Quick Deployment

### Prerequisites

- Access to a Kubernetes or OpenShift cluster
- `kubectl` or `oc` CLI installed and configured
- Appropriate permissions to create resources in the cluster

### Option 1: Automated Deployment (Recommended)

```bash
# Make scripts executable (if not already)
chmod +x deploy.sh cleanup.sh

# Deploy everything
./deploy.sh
```

The deployment script will:
- Deploy components in the correct dependency order
- Wait for each component to be ready before proceeding
- Perform health checks
- Provide access information and useful commands

### Option 2: Manual Deployment

```bash
# Deploy in order (dependencies first)
kubectl apply -f 00-namespace.yaml
kubectl apply -f 01-service-accounts.yaml
kubectl apply -f 02-secrets.yaml           # Optional
kubectl apply -f 03-configmaps.yaml
kubectl apply -f 04-storage.yaml           # PVCs - MUST be before databases!
kubectl apply -f 05-postgres.yaml
kubectl apply -f 06-redis.yaml
kubectl apply -f 07-haproxy.yaml
kubectl apply -f 07-backend.yaml
kubectl apply -f 08-frontend.yaml
kubectl apply -f 09-nginx.yaml

# For OpenShift (external access)
oc apply -f 10-routes.yaml

# For Kubernetes (external access)
kubectl apply -f 11-ingress.yaml
```

## 🧹 Cleanup

### Option 1: Automated Cleanup (Recommended)

```bash
./cleanup.sh
```

The cleanup script will:
- Remove components in reverse dependency order
- Wait for resources to be properly deleted
- Preserve the namespace (unless manually deleted)
- Provide verification commands

### Option 2: Manual Cleanup

```bash
# Delete in reverse order (applications first, dependencies last)
kubectl delete -f 10-routes.yaml     # or 11-ingress.yaml
kubectl delete -f 09-nginx.yaml
kubectl delete -f 08-frontend.yaml
kubectl delete -f 07-backend.yaml
kubectl delete -f 07-haproxy.yaml
kubectl delete -f 06-redis.yaml
kubectl delete -f 05-postgres.yaml
kubectl delete -f 04-storage.yaml    # PVCs last among storage
kubectl delete -f 03-configmaps.yaml
kubectl delete -f 02-secrets.yaml    # Optional
kubectl delete -f 01-service-accounts.yaml

# Optional: Delete namespace
kubectl delete -f 00-namespace.yaml
```

## 📊 Monitoring Deployment

### Check Pod Status
```bash
kubectl get pods -n haproxy-openmanager -w
```

### Check All Resources
```bash
kubectl get all -n haproxy-openmanager
```

### View Logs
```bash
# Backend logs
kubectl logs -f deployment/backend -n haproxy-openmanager

# Frontend logs
kubectl logs -f deployment/frontend -n haproxy-openmanager

# PostgreSQL logs
kubectl logs -f deployment/postgres -n haproxy-openmanager

# HAProxy logs
kubectl logs -f deployment/haproxy-instance -n haproxy-openmanager
```

## 🌐 Accessing the Application

### OpenShift (with Routes)
After deployment, the script will show the route URLs:
```bash
# Frontend URL (main application)
https://haproxy-openmanager.example.com

# Backend API URL
https://haproxy-openmanager.example.com/api
```

### Kubernetes (with Port Forward)
If no Ingress is configured:
```bash
# Frontend access
kubectl port-forward -n haproxy-openmanager service/nginx 8080:80
# Then access: http://localhost:8080

# Backend API access
kubectl port-forward -n haproxy-openmanager service/backend 8000:8000
# Then access: http://localhost:8000
```

## 🔧 Configuration

### Default Credentials
- **Admin User**: `admin` / `admin123`
- **HAProxy SSH**: `haproxy` / `admin123`
- **Database**: `haproxy_user` / `haproxy_pass`

### Key Components

1. **PostgreSQL**: Database for application data and configuration
2. **Redis**: Cache for sessions and performance data
3. **HAProxy Instance**: Remote HAProxy with SSH access for configuration management
4. **Backend API**: FastAPI application serving the REST API
5. **Frontend**: React application providing the web interface
6. **Nginx**: Reverse proxy routing traffic to frontend and backend

## 🐛 Troubleshooting

### Common Issues

1. **Pods in Pending State**
   ```bash
   kubectl describe pod <pod-name> -n haproxy-openmanager
   ```
   Check for resource constraints or PVC issues.

2. **Backend Health Check Failures**
   ```bash
   kubectl logs deployment/backend -n haproxy-openmanager
   ```
   Usually database or Redis connection issues.

3. **Database Connection Issues**
   ```bash
   kubectl exec -it deployment/postgres -n haproxy-openmanager -- psql -U haproxy_user -d haproxy_openmanager
   ```

4. **Frontend Not Loading**
   ```bash
   kubectl logs deployment/nginx -n haproxy-openmanager
   kubectl logs deployment/frontend -n haproxy-openmanager
   ```

### Resource Requirements

Minimum resource requirements:
- **CPU**: 2 cores total
- **Memory**: 4GB total
- **Storage**: 10GB for PostgreSQL data

## 📝 Customization

### Environment Variables
Edit `03-configmaps.yaml` to modify:
- Database connection settings
- Redis configuration
- API endpoints
- Frontend configuration

### Resource Limits
Edit individual component YAML files to adjust:
- CPU/Memory requests and limits
- Replica counts
- Storage sizes

### Networking
- Modify `13-routes.yaml` for OpenShift route configuration
- Modify `12-ingress.yaml` for Kubernetes ingress configuration
- Edit `10-nginx.yaml` for reverse proxy settings

## 🔒 Security Considerations

1. **Change Default Passwords**: Update default passwords in ConfigMaps and Secrets
2. **Enable HTTPS**: Configure proper TLS certificates
3. **Network Policies**: Implement network policies for additional security
4. **RBAC**: Review and adjust service account permissions
5. **Image Security**: Use specific image tags, not `latest`



### 🆕 New Features Included in Initial Schema

- **Pool Management**: HAProxy Cluster Pool organization
- **Agent Management**: Cross-platform HAProxy agent system  
- **Enhanced User Activity**: Detailed audit logging
- **Multi-environment Support**: Production, Staging, Test, Development
- **ACME Auto SSL**: Automated certificate management via Let's Encrypt / ACME protocol (v1.1.0+)

All database tables and initial data are created automatically via the backend migration system on startup. ACME-related tables (`letsencrypt_accounts`, `letsencrypt_orders`, `acme_challenges`) and columns (`source`, `auto_renew`, `acme_enabled`) are created automatically on both fresh and existing databases.

### ACME / Let's Encrypt Notes for Kubernetes

For ACME HTTP-01 challenges to work in Kubernetes:
1. The Nginx reverse proxy includes a location block for `/.well-known/acme-challenge/` that proxies requests to the backend
2. HAProxy clusters must have `acme_enabled=true` for challenge routing
3. The domain being validated must resolve to the HAProxy server(s) in the cluster
4. Port 80 must be accessible from the internet for the ACME CA to validate challenges

## 📚 Additional Resources

- [HAProxy Documentation](https://docs.haproxy.org/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [OpenShift Documentation](https://docs.openshift.com/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://reactjs.org/docs/) 