import os
from typing import Optional

# Database connection settings
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://haproxy_user:haproxy_password@postgres:5432/haproxy_openmanager")

# Redis connection
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# CORS settings
CORS_ORIGINS = ["http://localhost:3000"]

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
JWT_SECRET_KEY = SECRET_KEY  # Alias for JWT middleware
ALGORITHM = "HS256"
JWT_ALGORITHM = ALGORITHM  # Alias for JWT middleware
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Logging level
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Public URL configuration (for agent installation scripts)
PUBLIC_URL = os.getenv("PUBLIC_URL", "http://localhost:8000")
MANAGEMENT_BASE_URL = os.getenv("MANAGEMENT_BASE_URL", PUBLIC_URL)  # Backward compatibility

# Agent settings
AGENT_HEARTBEAT_TIMEOUT_SECONDS = 15
AGENT_CONFIG_SYNC_INTERVAL_SECONDS = 30

# Entity snapshot feature flag (for gradual rollout)
# IMPORTANT: Keep this FALSE in production until Phase 7 deployment
ENTITY_SNAPSHOT_ENABLED = os.getenv("ENTITY_SNAPSHOT_ENABLED", "false").lower() == "true" 