# HAProxy Open Manager - Testing & Docker Integration

## 🧪 Test-Integrated Docker Build

Unit tests are now integrated into the Docker build process, ensuring code quality at deployment time.

### 🔧 How It Works

**Backend Dockerfile:**
1. Installs test dependencies
2. Runs `pytest` during build
3. **Build fails if tests fail** ❌
4. Removes test dependencies for smaller image
5. Continues with production build

**Frontend Dockerfile:**
1. Installs test dependencies
2. Runs `npm test` with coverage during build  
3. **Build fails if tests fail** ❌
4. Continues with production build

### 🚀 Usage

**Production Build (with tests):**
```bash
# Build both services with integrated tests
docker-compose up --build

# Or build individually
docker build -t haproxy-backend ./backend
docker build -t haproxy-frontend ./frontend
```

**Test-Only Build:**
```bash
# Run comprehensive test suite with reports
docker-compose -f docker-compose.test.yml up --build

# Run backend tests only
docker build -f backend/Dockerfile.test -t haproxy-backend-test ./backend
docker run --rm haproxy-backend-test

# Run frontend tests only  
docker build -f frontend/Dockerfile.test -t haproxy-frontend-test ./frontend
docker run --rm haproxy-frontend-test
```

**Automated Build Script:**
```bash
# Interactive build with test reports
./scripts/test-build.sh
```

### 📊 Test Coverage

**Backend Tests (pytest):**
- ✅ Soft delete & unique constraints
- ✅ Apply process entity management
- ✅ Entity sync calculations
- ✅ HAProxy config generation
- ✅ Authentication & authorization
- **Target: 70% coverage**

**Frontend Tests (Jest):**
- ✅ EntitySyncStatus component
- ✅ ApplyManagement workflow
- ✅ SSLManagement functionality
- **Target: 70% coverage**

### 🎯 Build Behavior

**✅ Tests Pass:**
```
🧪 Running unit tests...
✅ All tests passed (42/42)
📊 Coverage: 78%
🔨 Continuing with production build...
✅ Build successful
```

**❌ Tests Fail:**
```
🧪 Running unit tests...
❌ UNIT TESTS FAILED - Build aborted
Error: Test suite failed
Build failed with exit code 1
```

### 🔄 CI/CD Integration

**Azure DevOps Pipeline:**
```yaml
- task: Docker@2
  displayName: 'Build Backend with Tests'
  inputs:
    command: 'build'
    dockerfile: 'backend/Dockerfile'
    tags: 'haproxy-backend:$(Build.BuildId)'
  # Build automatically fails if tests fail
```

### 🛠️ Development Workflow

**Skip Tests During Development:**
```bash
# Set environment variable to skip tests
export SKIP_TESTS=true
docker-compose up --build
```

**Run Tests Separately:**
```bash
# Backend
cd backend && pytest tests/ -v --cov=backend

# Frontend  
cd frontend && npm test -- --coverage --watchAll=false
```

### 📋 Test Reports

**Backend Coverage:** `./backend/htmlcov/index.html`
**Frontend Coverage:** `./frontend/coverage/lcov-report/index.html`

```bash
# Generate and view reports
docker-compose -f docker-compose.test.yml up --build
open backend/htmlcov/index.html
open frontend/coverage/lcov-report/index.html
```

### 🚨 Troubleshooting

**Build Fails Due to Tests:**
1. Check test output in build logs
2. Fix failing tests locally
3. Commit and rebuild

**Memory Issues During Build:**
```bash
# Increase Docker memory limit
docker system prune -f
docker build --memory=4g ./backend
```

**Skip Tests Temporarily:**
```dockerfile
# Comment out test line in Dockerfile
# RUN python -m pytest tests/ -v --tb=short --disable-warnings || \
#     (echo "❌ UNIT TESTS FAILED - Build aborted" && exit 1)
```

### 🎯 Benefits

- ✅ **Quality Gate:** Broken code cannot be deployed
- ✅ **Early Detection:** Issues caught at build time
- ✅ **CI/CD Integration:** Automatic test validation
- ✅ **Coverage Reports:** Built-in test coverage
- ✅ **Production Safety:** Only tested code reaches production

This ensures that every deployed image has passed comprehensive unit tests, preventing regression bugs from reaching production.
