"""
Test configuration and fixtures for HAProxy Management UI
"""
import pytest
import asyncio
import asyncpg
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock
from typing import AsyncGenerator, Dict, Any
import os
import tempfile
import json

# Import the main app
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import app

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def client():
    """FastAPI test client"""
    return TestClient(app)

@pytest.fixture
def mock_db_connection():
    """Mock database connection for testing"""
    mock_conn = AsyncMock()
    
    # Mock common database operations
    mock_conn.fetchrow = AsyncMock()
    mock_conn.fetchval = AsyncMock()
    mock_conn.fetch = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.transaction = AsyncMock()
    
    return mock_conn

@pytest.fixture
def sample_cluster_data():
    """Sample cluster data for testing"""
    return {
        "id": 1,
        "name": "test-cluster",
        "pool_id": 1,
        "stats_socket_path": "/run/haproxy/admin.sock",
        "haproxy_user": "haproxy",
        "haproxy_group": "haproxy"
    }

@pytest.fixture
def sample_backend_data():
    """Sample backend data for testing"""
    return {
        "id": 1,
        "name": "test-backend",
        "balance_method": "roundrobin",
        "mode": "http",
        "cluster_id": 1,
        "is_active": True,
        "last_config_status": "APPLIED"
    }

@pytest.fixture
def sample_frontend_data():
    """Sample frontend data for testing"""
    return {
        "id": 1,
        "name": "test-frontend",
        "bind_address": "0.0.0.0",
        "bind_port": 80,
        "default_backend": "test-backend",
        "mode": "http",
        "cluster_id": 1,
        "is_active": True,
        "last_config_status": "APPLIED",
        "ssl_enabled": False
    }

@pytest.fixture
def sample_ssl_data():
    """Sample SSL certificate data for testing"""
    return {
        "id": 1,
        "name": "test-ssl",
        "primary_domain": "example.com",
        "certificate_content": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
        "private_key_content": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
        "cluster_id": 1,
        "is_active": True,
        "last_config_status": "APPLIED"
    }

@pytest.fixture
def sample_server_data():
    """Sample server data for testing"""
    return {
        "id": 1,
        "server_name": "test-server",
        "backend_name": "test-backend",
        "server_address": "192.168.1.10",
        "server_port": 80,
        "weight": 100,
        "cluster_id": 1,
        "is_active": True,
        "last_config_status": "APPLIED"
    }

@pytest.fixture
def sample_config_version_data():
    """Sample config version data for testing"""
    return {
        "id": 1,
        "cluster_id": 1,
        "version_name": "test-version-123456",
        "config_content": "# HAProxy Configuration\nglobal\n    daemon\n",
        "checksum": "abc123",
        "status": "PENDING",
        "is_active": False,
        "created_by": 1
    }

@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    return {
        "id": 1,
        "username": "testuser",
        "email": "test@example.com",
        "is_admin": True,
        "is_active": True,
        "role": "admin"
    }

@pytest.fixture
def auth_headers():
    """Mock authorization headers"""
    return {"authorization": "Bearer test-token"}

@pytest.fixture
def mock_get_current_user():
    """Mock get_current_user_from_token function"""
    return {
        "id": 1,
        "username": "testuser",
        "email": "test@example.com",
        "is_admin": True
    }

class MockDatabase:
    """Mock database class for comprehensive testing"""
    
    def __init__(self):
        self.data = {
            "backends": {},
            "frontends": {},
            "ssl_certificates": {},
            "backend_servers": {},
            "config_versions": {},
            "clusters": {},
            "users": {}
        }
        self.next_id = 1
    
    def add_record(self, table: str, record: Dict[str, Any]) -> int:
        """Add a record to mock database"""
        record_id = self.next_id
        record["id"] = record_id
        self.data[table][record_id] = record.copy()
        self.next_id += 1
        return record_id
    
    def get_record(self, table: str, record_id: int) -> Dict[str, Any]:
        """Get a record from mock database"""
        return self.data[table].get(record_id)
    
    def update_record(self, table: str, record_id: int, updates: Dict[str, Any]):
        """Update a record in mock database"""
        if record_id in self.data[table]:
            self.data[table][record_id].update(updates)
    
    def delete_record(self, table: str, record_id: int):
        """Delete a record from mock database"""
        if record_id in self.data[table]:
            del self.data[table][record_id]
    
    def find_records(self, table: str, **filters) -> list:
        """Find records matching filters"""
        results = []
        for record in self.data[table].values():
            match = True
            for key, value in filters.items():
                if record.get(key) != value:
                    match = False
                    break
            if match:
                results.append(record)
        return results

@pytest.fixture
def mock_database():
    """Mock database fixture"""
    return MockDatabase()
