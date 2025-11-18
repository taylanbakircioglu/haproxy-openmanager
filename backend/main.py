from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import redis
import asyncio
from datetime import datetime, timedelta

# Version: 2025-10-20 - Agent script fixes deployed
# - Removed 'local' keyword from DAEMON mode (bash syntax fix)
# - Listen blocks preservation in DAEMON mode
# - Applied config version tracking improvements

# Import configurations and database

from config import CORS_ORIGINS, REDIS_URL, LOG_LEVEL
from database.connection import redis_client, get_database_connection, close_database_connection, init_database_pool, close_database_pool
from database.migrations import run_all_migrations

# Import routers
from routers import frontend_router, backend_router, cluster_router, dashboard_router, agent_router, waf_router, ssl_router, auth_router, user_router
from routers.health import router as health_router
from routers.config import router as config_router
from routers.security import router as security_router
from routers.configuration import router as configuration_router
from routers.maintenance import router as maintenance_router
from routers.dashboard_stats import router as dashboard_stats_router

# Production logging configuration
from utils.logging_config import setup_production_logging
from middleware.error_handler import (
    RequestLoggingMiddleware, PerformanceMonitoringMiddleware, 
    GlobalExceptionHandler, get_error_statistics
)
from middleware.activity_logger import log_activity_middleware
from middleware.json_sanitizer import JSONSanitizerMiddleware

# Setup structured logging
logger = setup_production_logging(LOG_LEVEL)

# Initialize FastAPI app with detailed API documentation
app = FastAPI(
    title="HAProxy Open Manager API", 
    version="1.0.5",
    description="""
# HAProxy Open Manager - Enterprise Multi-Cluster Management API

🚀 **Production-ready HAProxy management system** with agent-pull architecture for managing multiple HAProxy clusters remotely.

## Architecture Overview

This system uses an **agent-pull architecture**:
- Changes are NOT pushed from backend to agents
- Agent services periodically poll the backend for tasks
- Agents execute tasks on their local HAProxy servers
- Agents report status and sync configuration back to backend

## Getting Started

### Authentication
All API endpoints (except `/api/auth/login` and agent endpoints) require JWT authentication:

```bash
# 1. Login to get access token
curl -X POST "{BASE_URL}/api/auth/login" \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin", "password": "admin123"}'

# Response: {"access_token": "eyJ...", "token_type": "bearer"}

# 2. Use token in subsequent requests
curl -X GET "{BASE_URL}/api/clusters" \\
  -H "Authorization: Bearer eyJ..."
```

**Note:** Replace `{BASE_URL}` with your actual deployment URL (e.g., `https://haproxy-manager.company.com`)

## Workflow

### Initial Setup (From Scratch)

1. **Create Agent Pool**
   - Pools group agents logically
   - POST `/api/clusters/pools` - Create a new pool

2. **Create HAProxy Cluster**
   - Select the pool created above
   - POST `/api/clusters` - Create cluster associated with pool

3. **Generate Agent Installation Script**
   - Select pool when creating agent
   - POST `/api/agents` - Generate platform-specific installation script
   - Agent automatically gets associated with cluster via pool

4. **Install Agent on Remote HAProxy Server**
   - Download and run the generated script on target server
   - Agent service starts and begins polling backend
   - Agent logs written to `/var/log/haproxy-agent/agent.log`

5. **Configure HAProxy via UI**
   - Define backends, frontends, WAF rules, SSL certificates
   - Changes are stored in backend database
   - Agents periodically pull changes and apply to local haproxy.cfg
   - HAProxy service is automatically reloaded

### Multi-Cluster Management

Most operations are **cluster-scoped**:
- Select cluster in UI (top bar cluster selector)
- All operations apply to selected cluster only
- Exception: SSL Management can work across all clusters

### Agent Version Management

- Agent versions stored in backend database
- Agents check for updates on each poll cycle
- If new version available, agent downloads and self-updates
- Update agent scripts via UI: `Agent Management > Update Script`

## Key Features

- ✅ Multi-cluster management
- ✅ Agent-pull architecture (no push from backend)
- ✅ Backend & Frontend management
- ✅ WAF rule management
- ✅ SSL certificate management
- ✅ Bulk configuration import
- ✅ Real-time agent health monitoring
- ✅ Configuration version history
- ✅ Role-based access control (RBAC)
- ✅ Audit logging

## Deployment

- Platform: OpenShift
- CI/CD: Azure DevOps Pipeline
- Architecture: Agent-Pull based distributed management
""",
    contact={
        "name": "HAProxy Open Manager Team",
        "email": "support@example.com",
    },
    license_info={
        "name": "Enterprise License",
    },
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    openapi_tags=[
        {
            "name": "Authentication",
            "description": "User authentication and JWT token management. All protected endpoints require a valid JWT token obtained from `/api/auth/login`."
        },
        {
            "name": "Users",
            "description": "User management operations including CRUD operations, role assignments, and user activity tracking."
        },
        {
            "name": "clusters",
            "description": "HAProxy cluster management. Clusters represent groups of HAProxy instances that share configuration. Each cluster is associated with an agent pool."
        },
        {
            "name": "pools",
            "description": "Agent pool management. Pools are logical groups that connect agents to clusters. Create pools first, then create clusters referencing them."
        },
        {
            "name": "agents",
            "description": "Agent management and monitoring. Agents run on HAProxy servers and pull configuration from backend. Includes installation script generation, version management, and health monitoring."
        },
        {
            "name": "frontends",
            "description": "HAProxy frontend management. Frontends define how HAProxy receives incoming traffic (bind addresses, ports, SSL/TLS configuration)."
        },
        {
            "name": "backends",
            "description": "HAProxy backend and server management. Backends define pools of servers that handle requests, including load balancing algorithms and health checks."
        },
        {
            "name": "waf",
            "description": "Web Application Firewall (WAF) rule management. Define security rules to protect web applications from common attacks."
        },
        {
            "name": "ssl",
            "description": "SSL/TLS certificate management. Upload, manage, and deploy SSL certificates across clusters. Supports per-cluster and all-cluster deployment."
        },
        {
            "name": "configuration",
            "description": "Configuration management including bulk import, version history, and configuration preview. Import existing HAProxy configs or view generated configurations."
        },
        {
            "name": "dashboard",
            "description": "Real-time statistics and monitoring dashboard. View cluster health, agent status, traffic metrics, and system overview."
        },
        {
            "name": "security",
            "description": "Security and audit features including activity logs, access control, and system security settings."
        },
        {
            "name": "maintenance",
            "description": "System maintenance operations including database cleanup, soft-delete recovery, and system health checks."
        },
        {
            "name": "health",
            "description": "Health check endpoints for monitoring system status, database connectivity, and Redis status."
        }
    ]
)

# Background task for agent status monitoring
async def monitor_agent_status():
    """Background task to monitor agent status and mark offline agents"""
    while True:
        try:
            conn = await get_database_connection()
            
            # Mark agents as offline if they haven't sent heartbeat in last 120 seconds (2 minutes)
            threshold_time = datetime.utcnow() - timedelta(seconds=120)
            
            result = await conn.execute("""
                UPDATE agents 
                SET status = 'offline', updated_at = CURRENT_TIMESTAMP
                WHERE status = 'online' 
                AND (last_seen IS NULL OR last_seen < $1)
            """, threshold_time)
            
            await close_database_connection(conn)
            
            # Log if any agents were marked offline
            if result and hasattr(result, 'split') and len(result.split()) > 1:
                count = result.split()[1]
                if int(count) > 0:
                    logger.info(f"Marked {count} agents as offline due to missing heartbeats")
            
        except Exception as e:
            logger.error(f"Error in agent status monitoring: {e}")
        
        # Wait 30 seconds before next check
        await asyncio.sleep(30)

# Background task for agent upgrade timeout cleanup
async def cleanup_stuck_agent_upgrades():
    """Background task to reset agents stuck in 'upgrading' status
    
    Agents stuck in 'upgrading' for more than 5 minutes are automatically reset.
    This prevents UI issues where delete button is hidden due to stuck upgrade status.
    """
    while True:
        try:
            conn = await get_database_connection()
            
            # MIGRATION SAFETY: Check if upgrade_status column exists before using it
            # This prevents errors during initial deployment before migration runs
            upgrade_column_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'agents' AND column_name = 'upgrade_status'
                )
            """)
            
            if not upgrade_column_exists:
                await close_database_connection(conn)
                logger.debug("Agent upgrade columns not yet created - skipping cleanup (migration pending)")
                await asyncio.sleep(120)
                continue
            
            # Reset stuck upgrades older than 5 minutes
            # upgraded_at tracks the last upgrade status change
            threshold_time = datetime.utcnow() - timedelta(minutes=5)
            
            result = await conn.execute("""
                UPDATE agents 
                SET upgrade_status = NULL, 
                    upgrade_target_version = NULL,
                    status = 'online',
                    updated_at = CURRENT_TIMESTAMP
                WHERE upgrade_status = 'upgrading' 
                AND (upgraded_at IS NULL OR upgraded_at < $1)
            """, threshold_time)
            
            await close_database_connection(conn)
            
            # Log if any stuck upgrades were reset
            if result and hasattr(result, 'split') and len(result.split()) > 1:
                count = result.split()[1]
                if int(count) > 0:
                    logger.warning(f"Reset {count} stuck agent upgrade(s) - timeout after 5 minutes")
            
        except Exception as e:
            logger.error(f"Error in agent upgrade cleanup: {e}")
        
        # Wait 120 seconds (2 minutes) before next check
        await asyncio.sleep(120)

# Production middleware stack (order matters!)
app.add_middleware(PerformanceMonitoringMiddleware, slow_request_threshold_ms=1000)
app.add_middleware(RequestLoggingMiddleware, exclude_paths=["/api/health/", "/docs", "/redoc"])

# JSON Sanitizer - MUST be early to fix malformed JSON before FastAPI parses it
app.add_middleware(JSONSanitizerMiddleware)

# Activity logging middleware - must be before CORS
app.middleware("http")(log_activity_middleware)

# CORS middleware  
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handlers
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return await GlobalExceptionHandler.handle_http_exception(request, exc)

@app.exception_handler(StarletteHTTPException)
async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException):
    return await GlobalExceptionHandler.handle_http_exception(request, HTTPException(status_code=exc.status_code, detail=str(exc.detail)))

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return await GlobalExceptionHandler.handle_validation_error(request, exc)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return await GlobalExceptionHandler.handle_generic_exception(request, exc)

# Include routers
app.include_router(health_router)  # Health checks first for monitoring
app.include_router(config_router)  # Configuration management
app.include_router(maintenance_router, prefix="/api", tags=["maintenance"])  # Database cleanup & maintenance
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(frontend_router)
app.include_router(backend_router)
app.include_router(cluster_router)
app.include_router(dashboard_router)
app.include_router(dashboard_stats_router)  # HAProxy stats dashboard
app.include_router(agent_router)
app.include_router(waf_router)
app.include_router(ssl_router)
app.include_router(security_router)
app.include_router(configuration_router)

@app.on_event("startup")
async def startup_event():
    """Initialize the application on startup"""
    logger.info("HAProxy OpenManager API starting up...")
    
    try:
        # Initialize database connection pool FIRST (before any DB operations)
        logger.info("Initializing database connection pool...")
        await init_database_pool()
        logger.info("✅ Database connection pool initialized successfully")
        
        # Run database migrations
        logger.info("Forcing re-check of database schema...")
        await run_all_migrations()
        logger.info("Database migrations completed successfully")
        
        # Initialize agent scripts in database ONLY if empty (first deployment)
        # User edits are preserved, only Reset to Default overwrites from files
        try:
            import os
            
            conn = await get_database_connection()
            
            # Check if agent_script_templates table has any active scripts
            script_count = await conn.fetchval("""
                SELECT COUNT(*) FROM agent_script_templates WHERE is_active = true
            """)
            
            if script_count == 0:
                logger.info("🆕 INITIAL SETUP: No agent scripts in database, loading from files...")
                
                script_files = {
                    'linux': 'linux_install.sh',
                    'macos': 'macos_install.sh'
                }
                
                for platform_key, filename in script_files.items():
                    script_path = os.path.join(os.path.dirname(__file__), 'utils', 'agent_scripts', filename)
                    
                    if os.path.exists(script_path):
                        with open(script_path, 'r') as f:
                            file_content = f.read()
                        
                        # Create initial version 1.0.0
                        await conn.execute("""
                            INSERT INTO agent_script_templates (platform, version, script_content, is_active)
                            VALUES ($1, '1.0.0', $2, true)
                            ON CONFLICT (platform, version) DO NOTHING
                        """, platform_key, file_content)
                        
                        # Also create version entry
                        await conn.execute("""
                            INSERT INTO agent_versions (platform, version, is_active)
                            VALUES ($1, '1.0.0', true)
                            ON CONFLICT (platform, version) DO NOTHING
                        """, platform_key)
                        
                        logger.info(f"✅ INITIAL SETUP: {platform_key} script loaded (version 1.0.0)")
                
                logger.info("✅ INITIAL SETUP: Agent scripts initialized from files")
            else:
                logger.info(f"ℹ️  Agent scripts already exist in database ({script_count} active), preserving user edits")
            
            await close_database_connection(conn)
            
        except Exception as init_error:
            logger.warning(f"Agent script initialization check failed (non-critical): {init_error}")
        
        # Test Redis connection (graceful if unavailable)
        try:
            redis_client.ping()
            logger.info("Redis connection established")
        except Exception as redis_error:
            logger.warning(f"Redis is unavailable, continuing in degraded mode: {redis_error}")
        
        # Start background agent status monitoring task
        asyncio.create_task(monitor_agent_status())
        logger.info("Agent status monitoring task started")
        
        # Start background agent upgrade cleanup task
        asyncio.create_task(cleanup_stuck_agent_upgrades())
        logger.info("Agent upgrade timeout cleanup task started (5 minute timeout)")
        
        # Create test activity log entry to verify system is working
        try:
            from utils.activity_log import log_user_activity
            await log_user_activity(
                user_id=1,  # Admin user
                action='system_startup',
                resource_type='system',
                resource_id='main',
                details={'event': 'HAProxy OpenManager system started', 'version': '1.0.1'},
                ip_address='127.0.0.1',
                user_agent='HAProxy-OpenManager-System'
            )
            logger.info("✅ Test activity log created successfully")
        except Exception as log_error:
            logger.error(f"❌ Failed to create test activity log: {log_error}")
        
        logger.info("HAProxy OpenManager API startup completed successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("HAProxy OpenManager API shutting down...")
    
    # Close database connection pool gracefully
    try:
        logger.info("Closing database connection pool...")
        await close_database_pool()
        logger.info("✅ Database connection pool closed successfully")
    except Exception as e:
        logger.error(f"❌ Error closing database connection pool: {e}")

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "HAProxy Management UI API", "version": "1.0.1"}

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check Redis connection
        try:
            redis_client.ping()
            redis_status = "connected"
        except Exception:
            redis_status = "disconnected"
        
        # Check database connection (basic check)
        conn = await get_database_connection()
        await close_database_connection(conn)
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "services": {
                "redis": redis_status,
                "database": "connected"
            }
        }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        ) 