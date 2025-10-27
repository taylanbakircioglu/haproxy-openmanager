"""
Simple smoke tests to verify basic functionality
"""
import pytest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestBasicFunctionality:
    """Basic smoke tests"""
    
    def test_imports_work(self):
        """Test that all main modules can be imported"""
        try:
            import routers.cluster
            import routers.backend
            import routers.frontend
            import routers.ssl
            import services.haproxy_config
            import utils.activity_log
            assert True
        except ImportError as e:
            pytest.fail(f"Import failed: {e}")
    
    def test_extract_entities_function(self):
        """Test the entity extraction function"""
        from routers.cluster import _extract_entities_from_config
        
        config = """
        frontend web-frontend
            bind *:80
            default_backend web-servers
            
        backend web-servers
            balance roundrobin
            server web1 192.168.1.10:80 check
        """
        
        result = _extract_entities_from_config(config)
        
        assert 'web-frontend' in result['frontends']
        assert 'web-servers' in result['backends']
        assert len(result['frontends']) == 1
        assert len(result['backends']) == 1
    
    def test_extract_entities_empty_config(self):
        """Test entity extraction with empty config"""
        from routers.cluster import _extract_entities_from_config
        
        result = _extract_entities_from_config("")
        
        assert len(result['frontends']) == 0
        assert len(result['backends']) == 0
        assert len(result['waf_rules']) == 0
    
    def test_extract_entities_multiple_frontends(self):
        """Test entity extraction with multiple frontends and backends"""
        from routers.cluster import _extract_entities_from_config
        
        config = """
        global
            daemon
            
        frontend web-frontend
            bind *:80
            
        frontend api-frontend
            bind *:8080
            
        backend web-servers
            balance roundrobin
            
        backend api-servers
            balance leastconn
        """
        
        result = _extract_entities_from_config(config)
        
        assert 'web-frontend' in result['frontends']
        assert 'api-frontend' in result['frontends']
        assert 'web-servers' in result['backends']
        assert 'api-servers' in result['backends']
        assert len(result['frontends']) == 2
        assert len(result['backends']) == 2

class TestUtilityFunctions:
    """Test utility functions"""
    
    def test_config_templates_import(self):
        """Test config templates can be imported"""
        try:
            import utils.config_templates
            assert True
        except ImportError as e:
            pytest.fail(f"Config templates import failed: {e}")
    
    def test_haproxy_validator_import(self):
        """Test HAProxy validator can be imported"""
        try:
            import utils.haproxy_validator
            assert True
        except ImportError as e:
            pytest.fail(f"HAProxy validator import failed: {e}")
    
    def test_activity_log_import(self):
        """Test activity log can be imported"""
        try:
            import utils.activity_log
            assert True
        except ImportError as e:
            pytest.fail(f"Activity log import failed: {e}")

class TestModelImports:
    """Test model imports"""
    
    def test_backend_models_import(self):
        """Test backend models can be imported"""
        try:
            from models.backend import BackendConfig, ServerConfig
            assert True
        except ImportError as e:
            pytest.fail(f"Backend models import failed: {e}")
    
    def test_frontend_models_import(self):
        """Test frontend models can be imported"""
        try:
            from models import FrontendConfig
            assert True
        except ImportError as e:
            pytest.fail(f"Frontend models import failed: {e}")
    
    def test_ssl_models_import(self):
        """Test SSL models can be imported"""
        try:
            from models.ssl import SSLCertificateCreate
            assert True
        except ImportError as e:
            pytest.fail(f"SSL models import failed: {e}")

class TestDatabaseConnection:
    """Test database connection utilities"""
    
    def test_database_connection_import(self):
        """Test database connection can be imported"""
        try:
            from database.connection import get_database_connection, close_database_connection
            assert True
        except ImportError as e:
            pytest.fail(f"Database connection import failed: {e}")

class TestMainApp:
    """Test main application"""
    
    def test_main_app_import(self):
        """Test main app can be imported"""
        try:
            import main
            assert hasattr(main, 'app')
        except ImportError as e:
            pytest.fail(f"Main app import failed: {e}")
    
    def test_fastapi_app_creation(self):
        """Test FastAPI app can be created"""
        try:
            from fastapi.testclient import TestClient
            import main
            
            client = TestClient(main.app)
            assert client is not None
        except Exception as e:
            pytest.fail(f"FastAPI app creation failed: {e}")
