# HAProxy Management UI - Unit Tests

## Overview

Comprehensive unit test suite for the HAProxy Management UI backend, covering critical business logic and ensuring reliability.

## Test Structure

### Backend Tests (`backend/tests/`)

- **`test_soft_delete.py`** - Soft delete functionality and unique constraints
- **`test_apply_process.py`** - Critical apply process that manages entity states  
- **`test_entity_sync.py`** - Entity-specific agent sync calculations
- **`test_haproxy_config.py`** - HAProxy configuration generation
- **`test_auth.py`** - Authentication and authorization

### Frontend Tests (`frontend/src/components/__tests__/`)

- **`EntitySyncStatus.test.js`** - Agent sync status component
- **`ApplyManagement.test.js`** - Apply management workflow
- **`SSLManagement.test.js`** - SSL certificate management

## Running Tests

### Backend Tests

```bash
# Install test dependencies
pip install -r backend/requirements-test.txt

# Run all tests
pytest

# Run specific test file
pytest backend/tests/test_apply_process.py

# Run with coverage
pytest --cov=backend --cov-report=html

# Run specific test
pytest backend/tests/test_soft_delete.py::TestSoftDeleteUniqueConstraints::test_backend_soft_delete_allows_name_reuse
```

### Frontend Tests

```bash
# Run all frontend tests
npm test

# Run with coverage
npm run test:coverage

# Run in CI mode
npm run test:ci
```

## Test Coverage Goals

- **Backend**: 70% minimum coverage
- **Frontend**: 70% minimum coverage
- **Critical paths**: 90%+ coverage (apply process, soft delete, entity sync)

## Critical Test Areas

### 🔴 HIGH PRIORITY

1. **Apply Process** - Prevents entity disappearance bugs
2. **Soft Delete Logic** - Ensures proper unique constraint handling
3. **Entity Sync Calculations** - Agent sync status accuracy
4. **Authentication/Authorization** - Security validation

### 🟡 MEDIUM PRIORITY

1. **HAProxy Config Generation** - Configuration correctness
2. **SSL Management** - Certificate lifecycle
3. **Form Validations** - Input validation

### 🟢 LOW PRIORITY

1. **UI Components** - Visual behavior
2. **Utility Functions** - Helper functions

## Mock Strategy

### Backend Mocking
- **Database connections**: `AsyncMock` for database operations
- **External APIs**: Mock HTTP calls
- **File operations**: Mock file system access

### Frontend Mocking
- **API calls**: Mock axios requests
- **Ant Design components**: Mock component behavior
- **Context providers**: Mock React contexts

## Test Data

All tests use consistent mock data from `conftest.py`:
- Sample clusters, backends, frontends
- Mock users and authentication
- Config versions and SSL certificates

## Debugging Tests

```bash
# Run with verbose output
pytest -v -s

# Run specific failing test
pytest backend/tests/test_apply_process.py::TestApplyProcess::test_apply_process_preserves_active_entities -v -s

# Drop into debugger on failure
pytest --pdb
```

## Integration with CI/CD

Tests are designed to run in Azure DevOps pipeline:

```yaml
# Example pipeline step
- script: |
    pip install -r backend/requirements-test.txt
    pytest --cov=backend --cov-report=xml
  displayName: 'Run Backend Tests'

- script: |
    npm ci
    npm run test:ci
  displayName: 'Run Frontend Tests'
```

## Adding New Tests

1. **Follow naming convention**: `test_*.py` for backend, `*.test.js` for frontend
2. **Use appropriate fixtures**: Leverage existing mock data
3. **Test edge cases**: Include error scenarios and boundary conditions
4. **Update coverage**: Ensure new code maintains coverage thresholds

## Common Issues

### Backend
- **Async tests**: Use `@pytest.mark.asyncio` decorator
- **Database mocking**: Ensure proper mock setup for database operations
- **Import paths**: Use relative imports for testable modules

### Frontend
- **Component rendering**: Wait for async operations with `waitFor`
- **Event simulation**: Use `fireEvent` for user interactions
- **Mock cleanup**: Clear mocks between tests with `jest.clearAllMocks()`

## Test Philosophy

These tests focus on:
- **Business logic correctness** over implementation details
- **Critical path coverage** over 100% coverage
- **Regression prevention** based on actual bugs encountered
- **Maintainability** with clear, readable test cases

The test suite is designed to catch the types of bugs we've actually encountered in production, particularly around the apply process and soft delete behavior.

---
*Test deployment trigger - $(date)*
