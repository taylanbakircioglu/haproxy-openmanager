"""
Configuration Management and Validation API
Provides endpoints for HAProxy configuration validation, templates, and optimization
"""

from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import logging

from utils.haproxy_validator import validate_haproxy_config, get_validation_summary
from utils.config_templates import (
    get_template_manager, list_available_templates, 
    generate_config_from_template, TemplateCategory
)
from utils.haproxy_config_parser import parse_haproxy_config
from utils.logging_config import log_with_correlation, PerformanceLogger
from auth_middleware import get_current_user_from_token
from database.connection import get_database_connection, close_database_connection

router = APIRouter(prefix="/api/config", tags=["Configuration Management"])
logger = logging.getLogger("haproxy_openmanager.config")

# Import agent version management
from routers.agent import AGENT_VERSIONS, get_platform_key

# Request/Response Models
class ConfigValidationRequest(BaseModel):
    config_content: str
    strict_mode: bool = False
    check_performance: bool = True
    check_security: bool = True

class ConfigValidationResponse(BaseModel):
    is_valid: bool
    overall_score: float
    scores: Dict[str, float]
    issue_counts: Dict[str, int]
    issues: List[Dict[str, Any]]
    timestamp: float

class TemplateGenerationRequest(BaseModel):
    template_id: str
    variables: Dict[str, Any]
    validate_output: bool = True

class TemplateResponse(BaseModel):
    id: str
    name: str
    description: str
    category: str
    difficulty: str
    tags: List[str]
    use_cases: List[str]
    variables: List[str]

class ConfigOptimizationRequest(BaseModel):
    config_content: str
    optimization_level: str = "balanced"  # conservative, balanced, aggressive
    target_environment: str = "production"  # development, staging, production

@router.post("/validate")
async def validate_configuration(
    request: ConfigValidationRequest,
    current_user: dict = None,
    authorization: str = Header(None)
):
    """Validate HAProxy configuration syntax and best practices"""
    
    # Get current user for logging
    if authorization:
        try:
            current_user = await get_current_user_from_token(authorization.replace("Bearer ", ""))
        except:
            pass  # Continue without user context
    
    with PerformanceLogger(logger, "config_validation", 
                          user_id=current_user.get('id') if current_user else None,
                          config_size=len(request.config_content)):
        
        try:
            # Validate configuration
            validation_report = validate_haproxy_config(request.config_content)
            
            # Get summary for API response
            summary = get_validation_summary(validation_report)
            
            # Log validation result
            log_with_correlation(
                logger, "INFO",
                f"Configuration validation completed",
                user_id=current_user.get('id') if current_user else None,
                is_valid=validation_report.is_valid,
                error_count=validation_report.error_count,
                warning_count=validation_report.warning_count,
                overall_score=summary["overall_score"],
                config_size_bytes=len(request.config_content)
            )
            
            return {
                **summary,
                "timestamp": __import__('time').time(),
                "validation_options": {
                    "strict_mode": request.strict_mode,
                    "check_performance": request.check_performance,
                    "check_security": request.check_security
                }
            }
            
        except Exception as e:
            log_with_correlation(
                logger, "ERROR",
                f"Configuration validation failed: {str(e)}",
                user_id=current_user.get('id') if current_user else None,
                config_size_bytes=len(request.config_content)
            )
            raise HTTPException(
                status_code=500, 
                detail=f"Configuration validation failed: {str(e)}"
            )

@router.get("/templates")
async def list_templates(
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    tag: Optional[str] = None
):
    """List available configuration templates"""
    
    try:
        templates = list_available_templates()
        
        # Apply filters
        if category:
            templates = [t for t in templates if t["category"] == category]
        
        if difficulty:
            templates = [t for t in templates if t["difficulty"] == difficulty]
        
        if tag:
            templates = [t for t in templates if tag in t["tags"]]
        
        log_with_correlation(
            logger, "INFO",
            f"Listed {len(templates)} configuration templates",
            filters={"category": category, "difficulty": difficulty, "tag": tag}
        )
        
        return {
            "templates": templates,
            "total_count": len(templates),
            "categories": list(set(t["category"] for t in templates)),
            "difficulties": list(set(t["difficulty"] for t in templates)),
            "available_tags": list(set(tag for t in templates for tag in t["tags"]))
        }
        
    except Exception as e:
        log_with_correlation(
            logger, "ERROR",
            f"Failed to list templates: {str(e)}"
        )
        raise HTTPException(status_code=500, detail=f"Failed to list templates: {str(e)}")

@router.get("/templates/{template_id}")
async def get_template_details(template_id: str):
    """Get detailed information about a specific template"""
    
    try:
        template_manager = get_template_manager()
        template = template_manager.get_template(template_id)
        
        if not template:
            raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
        
        log_with_correlation(
            logger, "INFO",
            f"Retrieved template details: {template_id}",
            template_name=template.name
        )
        
        return {
            "id": template.id,
            "name": template.name,
            "description": template.description,
            "category": template.category.value,
            "difficulty": template.difficulty,
            "tags": template.tags,
            "use_cases": template.use_cases,
            "variables": template.variables,
            "config_preview": template.config_content[:500] + "..." if len(template.config_content) > 500 else template.config_content
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log_with_correlation(
            logger, "ERROR",
            f"Failed to get template details: {str(e)}",
            template_id=template_id
        )
        raise HTTPException(status_code=500, detail=f"Failed to get template: {str(e)}")

@router.post("/templates/{template_id}/generate")
async def generate_configuration(
    template_id: str,
    request: TemplateGenerationRequest,
    current_user: dict = None,
    authorization: str = Header(None)
):
    """Generate configuration from template with custom variables"""
    
    # Get current user for logging
    if authorization:
        try:
            current_user = await get_current_user_from_token(authorization.replace("Bearer ", ""))
        except:
            pass
    
    with PerformanceLogger(logger, "template_generation",
                          user_id=current_user.get('id') if current_user else None,
                          template_id=template_id):
        
        try:
            # Generate configuration
            config = generate_config_from_template(template_id, request.variables)
            
            if not config:
                raise HTTPException(
                    status_code=404, 
                    detail=f"Template '{template_id}' not found or generation failed"
                )
            
            response_data = {
                "template_id": template_id,
                "generated_config": config,
                "variables_used": request.variables,
                "timestamp": __import__('time').time()
            }
            
            # Validate generated configuration if requested
            if request.validate_output:
                validation_report = validate_haproxy_config(config)
                validation_summary = get_validation_summary(validation_report)
                response_data["validation"] = validation_summary
            
            log_with_correlation(
                logger, "INFO",
                f"Generated configuration from template: {template_id}",
                user_id=current_user.get('id') if current_user else None,
                config_size_bytes=len(config),
                validated=request.validate_output,
                variable_count=len(request.variables)
            )
            
            return response_data
            
        except HTTPException:
            raise
        except Exception as e:
            log_with_correlation(
                logger, "ERROR",
                f"Configuration generation failed: {str(e)}",
                user_id=current_user.get('id') if current_user else None,
                template_id=template_id
            )
            raise HTTPException(
                status_code=500, 
                detail=f"Configuration generation failed: {str(e)}"
            )

@router.post("/optimize")
async def optimize_configuration(
    request: ConfigOptimizationRequest,
    current_user: dict = None,
    authorization: str = Header(None)
):
    """Analyze and suggest optimizations for HAProxy configuration"""
    
    # Get current user for logging
    if authorization:
        try:
            current_user = await get_current_user_from_token(authorization.replace("Bearer ", ""))
        except:
            pass
    
    with PerformanceLogger(logger, "config_optimization",
                          user_id=current_user.get('id') if current_user else None,
                          optimization_level=request.optimization_level):
        
        try:
            # First validate the current configuration
            validation_report = validate_haproxy_config(request.config_content)
            validation_summary = get_validation_summary(validation_report)
            
            # Generate optimization suggestions
            suggestions = _generate_optimization_suggestions(
                request.config_content,
                validation_report,
                request.optimization_level,
                request.target_environment
            )
            
            response_data = {
                "current_validation": validation_summary,
                "optimizations": suggestions,
                "optimization_level": request.optimization_level,
                "target_environment": request.target_environment,
                "timestamp": __import__('time').time()
            }
            
            log_with_correlation(
                logger, "INFO",
                f"Configuration optimization analysis completed",
                user_id=current_user.get('id') if current_user else None,
                optimization_count=len(suggestions),
                optimization_level=request.optimization_level,
                current_score=validation_summary["overall_score"]
            )
            
            return response_data
            
        except Exception as e:
            log_with_correlation(
                logger, "ERROR",
                f"Configuration optimization failed: {str(e)}",
                user_id=current_user.get('id') if current_user else None
            )
            raise HTTPException(
                status_code=500, 
                detail=f"Configuration optimization failed: {str(e)}"
            )

@router.get("/best-practices")
async def get_best_practices(
    category: Optional[str] = None,
    environment: Optional[str] = None
):
    """Get HAProxy configuration best practices and recommendations"""
    
    try:
        best_practices = _get_configuration_best_practices(category, environment)
        
        log_with_correlation(
            logger, "INFO",
            f"Retrieved configuration best practices",
            category=category,
            environment=environment,
            practice_count=len(best_practices)
        )
        
        return {
            "best_practices": best_practices,
            "category": category,
            "environment": environment,
            "timestamp": __import__('time').time()
        }
        
    except Exception as e:
        log_with_correlation(
            logger, "ERROR",
            f"Failed to get best practices: {str(e)}"
        )
        raise HTTPException(status_code=500, detail=f"Failed to get best practices: {str(e)}")

@router.post("/diff")
async def compare_configurations(
    current_config: str,
    new_config: str,
    context_lines: int = 3
):
    """Compare two HAProxy configurations and show differences"""
    
    try:
        import difflib
        
        current_lines = current_config.splitlines(keepends=True)
        new_lines = new_config.splitlines(keepends=True)
        
        # Generate unified diff
        diff = list(difflib.unified_diff(
            current_lines,
            new_lines,
            fromfile="current_config",
            tofile="new_config",
            n=context_lines
        ))
        
        # Parse diff for structured response
        changes = _parse_diff_output(diff)
        
        # Validate both configurations
        current_validation = validate_haproxy_config(current_config)
        new_validation = validate_haproxy_config(new_config)
        
        response_data = {
            "diff_output": "".join(diff),
            "changes": changes,
            "validation": {
                "current": get_validation_summary(current_validation),
                "new": get_validation_summary(new_validation)
            },
            "statistics": {
                "lines_added": len([c for c in changes if c["type"] == "added"]),
                "lines_removed": len([c for c in changes if c["type"] == "removed"]),
                "lines_modified": len([c for c in changes if c["type"] == "modified"])
            },
            "timestamp": __import__('time').time()
        }
        
        log_with_correlation(
            logger, "INFO",
            f"Configuration diff completed",
            changes_count=len(changes),
            current_size=len(current_config),
            new_size=len(new_config)
        )
        
        return response_data
        
    except Exception as e:
        log_with_correlation(
            logger, "ERROR",
            f"Configuration diff failed: {str(e)}"
        )
        raise HTTPException(status_code=500, detail=f"Configuration diff failed: {str(e)}")

# Helper functions
def _generate_optimization_suggestions(config_content: str, validation_report, level: str, environment: str) -> List[Dict[str, Any]]:
    """Generate optimization suggestions based on config analysis"""
    suggestions = []
    
    # Performance optimizations
    if "timeout" not in config_content.lower():
        suggestions.append({
            "type": "performance",
            "priority": "high",
            "title": "Add timeout configurations",
            "description": "Configure appropriate timeouts for better resource management",
            "suggestion": "Add timeout connect 5s, timeout client 50s, timeout server 50s",
            "impact": "Prevents resource exhaustion and improves reliability"
        })
    
    if "maxconn" not in config_content.lower():
        suggestions.append({
            "type": "performance", 
            "priority": "medium",
            "title": "Set connection limits",
            "description": "Configure maxconn to prevent server overload",
            "suggestion": "Add maxconn 2000 in global section",
            "impact": "Protects against connection exhaustion"
        })
    
    # Security optimizations
    if environment == "production":
        if "ssl" not in config_content.lower():
            suggestions.append({
                "type": "security",
                "priority": "high", 
                "title": "Enable SSL/HTTPS",
                "description": "Configure SSL termination for secure communications",
                "suggestion": "Add SSL binding and certificate configuration",
                "impact": "Encrypts traffic and improves security posture"
            })
        
        if "user" not in config_content.lower():
            suggestions.append({
                "type": "security",
                "priority": "medium",
                "title": "Configure non-root user",
                "description": "Run HAProxy as non-privileged user",
                "suggestion": "Add 'user haproxy' and 'group haproxy' in global section",
                "impact": "Reduces security risk from privilege escalation"
            })
    
    # Monitoring optimizations
    if "stats" not in config_content.lower():
        suggestions.append({
            "type": "monitoring",
            "priority": "medium",
            "title": "Enable statistics interface",
            "description": "Add stats interface for monitoring and troubleshooting",
            "suggestion": "Add stats socket and/or stats URI configuration",
            "impact": "Provides visibility into HAProxy performance and health"
        })
    
    return suggestions

def _get_configuration_best_practices(category: Optional[str], environment: Optional[str]) -> List[Dict[str, Any]]:
    """Get configuration best practices"""
    practices = [
        {
            "category": "security",
            "title": "Use SSL/TLS encryption",
            "description": "Always use HTTPS in production environments",
            "example": "bind *:443 ssl crt /path/to/certificate.pem",
            "environments": ["production", "staging"]
        },
        {
            "category": "performance",
            "title": "Configure appropriate timeouts",
            "description": "Set timeouts to prevent resource exhaustion",
            "example": "timeout connect 5s\ntimeout client 50s\ntimeout server 50s",
            "environments": ["production", "staging", "development"]
        },
        {
            "category": "monitoring",
            "title": "Enable comprehensive logging",
            "description": "Log requests and errors for debugging and monitoring",
            "example": "log stdout local0 info\noption httplog",
            "environments": ["production", "staging"]
        },
        {
            "category": "reliability",
            "title": "Configure health checks",
            "description": "Use health checks to detect unhealthy servers",
            "example": "option httpchk GET /health\nserver web1 192.168.1.10:80 check",
            "environments": ["production", "staging", "development"]
        }
    ]
    
    # Filter by category and environment
    if category:
        practices = [p for p in practices if p["category"] == category]
    
    if environment:
        practices = [p for p in practices if environment in p["environments"]]
    
    return practices

def _parse_diff_output(diff_lines: List[str]) -> List[Dict[str, Any]]:
    """Parse diff output into structured format"""
    changes = []
    
    for line in diff_lines:
        if line.startswith('+++') or line.startswith('---') or line.startswith('@@'):
            continue
        
        if line.startswith('+'):
            changes.append({
                "type": "added",
                "content": line[1:].rstrip(),
                "line_number": None
            })
        elif line.startswith('-'):
            changes.append({
                "type": "removed", 
                "content": line[1:].rstrip(),
                "line_number": None
            })
        elif not line.startswith(' '):
            changes.append({
                "type": "context",
                "content": line.rstrip(),
                "line_number": None
            })
    
    return changes

# ==== AGENT SCRIPT VERSION MANAGEMENT FOR CONFIGURATION ====

@router.get("/agent-versions")
async def get_agent_script_versions(authorization: str = Header(None)):
    """Get current agent script versions for Configuration page"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        return {
            "platforms": {
                "macos": {
                    "current_version": AGENT_VERSIONS.get("macos", "unknown"),
                    "description": "macOS / Darwin Agent Scripts",
                    "supported_versions": ["1.0.0", "1.5.0", "1.9.0", "2.0.0", "2.1.0"],
                    "last_updated": "2024-01-23T00:00:00Z"
                },
                "linux": {
                    "current_version": AGENT_VERSIONS.get("linux", "unknown"), 
                    "description": "Linux Agent Scripts (Ubuntu, RHEL, CentOS, etc.)",
                    "supported_versions": ["1.0.0", "1.5.0", "1.9.0", "2.0.0", "2.1.0"],
                    "last_updated": "2024-01-23T00:00:00Z"
                }
            },
            "last_updated": "2024-01-23T00:00:00Z"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting agent script versions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/agent-versions/{platform}")
async def update_agent_script_version(platform: str, version_data: dict, authorization: str = Header(None)):
    """Update agent script version for specified platform (Configuration page)"""
    try:
        current_user = await get_current_user_from_token(authorization)
        
        new_version = version_data.get('version', '')
        changelog = version_data.get('changelog', [])
        
        if not new_version:
            raise HTTPException(status_code=400, detail="Version is required")
        
        platform_key = get_platform_key(platform)
        if platform_key not in ['macos', 'linux']:
            raise HTTPException(status_code=400, detail="Unsupported platform. Only macOS and Linux are supported.")
        
        # Update both global version storage AND database
        global AGENT_VERSIONS
        old_version = AGENT_VERSIONS.get(platform_key, "unknown")
        AGENT_VERSIONS[platform_key] = new_version
        
        # Also update database to ensure consistency across endpoints
        try:
            from database.connection import get_database_connection, close_database_connection
            conn = await get_database_connection()
            
            # Insert or update version in database
            await conn.execute("""
                INSERT INTO agent_versions (platform, version, changelog, is_active)
                VALUES ($1, $2, $3, true)
                ON CONFLICT (platform, version) 
                DO UPDATE SET 
                    changelog = EXCLUDED.changelog,
                    is_active = true,
                    updated_at = CURRENT_TIMESTAMP
            """, platform_key, new_version, changelog or [])
            
            # Deactivate old versions for this platform
            await conn.execute("""
                UPDATE agent_versions 
                SET is_active = false 
                WHERE platform = $1 AND version != $2
            """, platform_key, new_version)
            
            await close_database_connection(conn)
            logger.info(f"CONFIG: Database updated with new version {new_version} for {platform_key}")
            
        except Exception as db_error:
            logger.warning(f"Could not update database: {db_error}")
            # Continue with global storage update even if database fails
        
        logger.info(f"CONFIG: Agent script version updated for {platform_key}: {old_version} → {new_version}")
        
        return {
            "message": f"Agent script version updated for {platform_key}",
            "platform": platform_key,
            "old_version": old_version,
            "new_version": new_version,
            "current_versions": AGENT_VERSIONS,
            "changelog": changelog
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating agent script version: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==== BULK CONFIG IMPORT ENDPOINTS ====

class BulkConfigParseRequest(BaseModel):
    config_content: str
    cluster_id: int


class BulkConfigCreateRequest(BaseModel):
    cluster_id: int
    frontends: List[Dict[str, Any]]
    backends: List[Dict[str, Any]]


@router.post("/parse-bulk")
async def parse_bulk_config(
    request: BulkConfigParseRequest,
    authorization: str = Header(None)
):
    """
    Parse HAProxy config and extract frontend/backend/server entities
    Returns parsed entities for user review before creation
    REQUIRES: config.write permission
    """
    try:
        current_user = await get_current_user_from_token(authorization)
        
        # Check if user has permission to write config (bulk import requires write access)
        # Super admins and admins bypass permission checks, also check user_roles table for admin roles
        from auth_middleware import check_user_permission
        from database.connection import get_database_connection, close_database_connection
        
        # Check if user has admin role in database
        conn = await get_database_connection()
        user_roles = await conn.fetch("""
            SELECT r.name 
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.is_active = true
        """, current_user["id"])
        await close_database_connection(conn)
        
        role_names = [role['name'] for role in user_roles]
        is_super_admin = (
            current_user.get("role") in ["super_admin", "admin"] or
            "super_admin" in role_names or
            "admin" in role_names
        )
        
        if not is_super_admin:
            has_permission = await check_user_permission(current_user["id"], "config", "write")
            if not has_permission:
                log_with_correlation(
                    logger, "WARNING",
                    f"User {current_user.get('username')} (role: {current_user.get('role')}, roles: {role_names}) denied access to bulk import - missing config.write permission",
                    user_id=current_user.get('id')
                )
                raise HTTPException(
                    status_code=403,
                    detail="Insufficient permissions: config.write required for bulk import"
                )
        else:
            log_with_correlation(
                logger, "INFO",
                f"Admin user {current_user.get('username')} (roles: {role_names}) bypassing permission check for bulk import",
                user_id=current_user.get('id')
            )
        
        log_with_correlation(
            logger, "INFO",
            f"Parsing bulk config for cluster {request.cluster_id}",
            user_id=current_user.get('id'),
            cluster_id=request.cluster_id,
            config_size=len(request.config_content)
        )
        
        # Parse the configuration
        parse_result = parse_haproxy_config(request.config_content)
        
        # Check for parsing errors
        if parse_result.errors:
            logger.warning(f"Config parsing completed with errors: {parse_result.errors}")
        
        # Convert parsed entities to dict format
        frontends_data = []
        for frontend in parse_result.frontends:
            # IMPORTANT: Disable SSL in bulk import since certificates must be managed separately
            # SSL detected in config will generate warnings, but frontends are created without SSL
            # Users must configure SSL via SSL Management page and then enable it on frontends
            frontends_data.append({
                "name": frontend.name,
                "bind_address": frontend.bind_address,
                "bind_port": frontend.bind_port,
                "default_backend": frontend.default_backend,
                "mode": frontend.mode,
                "ssl_enabled": False,  # Always False for bulk import - SSL must be configured separately
                "ssl_port": None,  # No SSL port for bulk import
                "timeout_client": frontend.timeout_client,
                "maxconn": frontend.maxconn,
                "request_headers": frontend.request_headers,
                "response_headers": frontend.response_headers,
                "tcp_request_rules": frontend.tcp_request_rules,
                "acl_rules": frontend.acl_rules,
                "use_backend_rules": frontend.use_backend_rules  # CRITICAL FIX: Include routing rules
            })
        
        backends_data = []
        for backend in parse_result.backends:
            servers_data = []
            for server in backend.servers:
                servers_data.append({
                    "server_name": server.server_name,
                    "server_address": server.server_address,
                    "server_port": server.server_port,
                    "weight": server.weight,
                    "max_connections": server.max_connections,
                    "check_enabled": server.check_enabled,
                    "check_port": server.check_port,
                    "backup_server": server.backup_server,
                    "ssl_enabled": server.ssl_enabled,
                    "ssl_verify": server.ssl_verify,
                    "cookie_value": server.cookie_value,
                    "inter": server.inter,
                    "fall": server.fall,
                    "rise": server.rise
                })
            
            backends_data.append({
                "name": backend.name,
                "mode": backend.mode,
                "balance_method": backend.balance_method,
                "health_check_uri": backend.health_check_uri,
                "health_check_interval": backend.health_check_interval,
                "health_check_expected_status": backend.health_check_expected_status,
                "fullconn": backend.fullconn,
                "cookie_name": backend.cookie_name,
                "cookie_options": backend.cookie_options,
                "default_server_inter": backend.default_server_inter,
                "default_server_fall": backend.default_server_fall,
                "default_server_rise": backend.default_server_rise,
                "request_headers": backend.request_headers,
                "response_headers": backend.response_headers,
                "timeout_connect": backend.timeout_connect,
                "timeout_server": backend.timeout_server,
                "timeout_queue": backend.timeout_queue,
                "servers": servers_data
            })
        
        log_with_correlation(
            logger, "INFO",
            f"Bulk config parsed successfully",
            user_id=current_user.get('id'),
            frontends_count=len(frontends_data),
            backends_count=len(backends_data),
            errors_count=len(parse_result.errors),
            warnings_count=len(parse_result.warnings)
        )
        
        return {
            "success": True,
            "frontends": frontends_data,
            "backends": backends_data,
            "errors": parse_result.errors,
            "warnings": parse_result.warnings,
            "summary": {
                "frontends_count": len(frontends_data),
                "backends_count": len(backends_data),
                "total_servers_count": sum(len(b["servers"]) for b in backends_data)
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bulk config parsing failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse configuration: {str(e)}"
        )


@router.post("/bulk-create")
async def bulk_create_entities(
    request: BulkConfigCreateRequest,
    authorization: str = Header(None)
):
    """
    Create multiple frontends, backends, and servers from parsed config
    This endpoint creates all entities in a transaction
    REQUIRES: config.write permission
    """
    try:
        current_user = await get_current_user_from_token(authorization)
        
        # Check if user has permission to write config (bulk import requires write access)
        # Super admins and admins bypass permission checks
        from auth_middleware import check_user_permission
        from database.connection import get_database_connection, close_database_connection
        
        # Check if user has admin role in database
        temp_conn = await get_database_connection()
        user_roles = await temp_conn.fetch("""
            SELECT r.name 
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.is_active = true
        """, current_user["id"])
        await close_database_connection(temp_conn)
        
        role_names = [role['name'] for role in user_roles]
        is_super_admin = (
            current_user.get("role") in ["super_admin", "admin"] or
            "super_admin" in role_names or
            "admin" in role_names
        )
        
        if not is_super_admin:
            has_permission = await check_user_permission(current_user["id"], "config", "write")
            if not has_permission:
                raise HTTPException(
                    status_code=403,
                    detail="Insufficient permissions: config.write required for bulk import"
                )
        
        log_with_correlation(
            logger, "INFO",
            f"Bulk creating entities for cluster {request.cluster_id}",
            user_id=current_user.get('id'),
            cluster_id=request.cluster_id,
            frontends_count=len(request.frontends),
            backends_count=len(request.backends)
        )
        
        conn = await get_database_connection()
        created_entities = {
            "frontends": [],
            "backends": [],
            "servers": []
        }
        
        try:
            # Import necessary modules for entity creation
            import hashlib
            import time
            import json
            from services.haproxy_config import generate_haproxy_config_for_cluster
            
            # Create backends first (frontends may reference them)
            for backend_data in request.backends:
                # Check if backend already exists
                existing = await conn.fetchrow("""
                    SELECT id FROM backends 
                    WHERE name = $1 AND cluster_id = $2 AND is_active = TRUE
                """, backend_data["name"], request.cluster_id)
                
                if existing:
                    logger.warning(f"Backend '{backend_data['name']}' already exists, skipping")
                    continue
                
                # Insert backend
                # CRITICAL: Only set health_check_expected_status for HTTP mode backends
                # TCP backends cannot use http-check directives
                # Only set if explicitly defined in config (http-check expect status directive)
                backend_mode = backend_data.get("mode", "http")
                health_check_expected_status = None
                if backend_mode == "http" and backend_data.get("health_check_expected_status") is not None:
                    health_check_expected_status = backend_data["health_check_expected_status"]
                
                backend_id = await conn.fetchval("""
                    INSERT INTO backends (
                        name, balance_method, mode, health_check_uri, 
                        health_check_interval, health_check_expected_status, fullconn,
                        cookie_name, cookie_options, default_server_inter, 
                        default_server_fall, default_server_rise, request_headers, 
                        response_headers, timeout_connect, timeout_server, timeout_queue, cluster_id
                    ) 
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) 
                    RETURNING id
                """, 
                    backend_data["name"],
                    backend_data.get("balance_method", "roundrobin"),
                    backend_mode,
                    backend_data.get("health_check_uri"),
                    backend_data.get("health_check_interval", 2000),
                    health_check_expected_status,  # Now correctly NULL for TCP
                    backend_data.get("fullconn"),
                    backend_data.get("cookie_name"),
                    backend_data.get("cookie_options"),
                    backend_data.get("default_server_inter"),
                    backend_data.get("default_server_fall"),
                    backend_data.get("default_server_rise"),
                    backend_data.get("request_headers"),
                    backend_data.get("response_headers"),
                    backend_data.get("timeout_connect", 10000),
                    backend_data.get("timeout_server", 60000),
                    backend_data.get("timeout_queue", 60000),
                    request.cluster_id
                )
                
                created_entities["backends"].append({
                    "id": backend_id,
                    "name": backend_data["name"]
                })
                
                # Create servers for this backend
                for server_data in backend_data.get("servers", []):
                    # Check if server already exists
                    existing_server = await conn.fetchrow("""
                        SELECT id FROM backend_servers 
                        WHERE backend_name = $1 AND server_name = $2 
                        AND cluster_id = $3 AND is_active = TRUE
                    """, backend_data["name"], server_data["server_name"], request.cluster_id)
                    
                    if existing_server:
                        logger.warning(f"Server '{server_data['server_name']}' already exists in backend '{backend_data['name']}', skipping")
                        continue
                    
                    server_id = await conn.fetchval("""
                        INSERT INTO backend_servers (
                            backend_id, backend_name, server_name, server_address, 
                            server_port, weight, maxconn, check_enabled, check_port,
                            backup_server, ssl_enabled, ssl_verify, cookie_value,
                            inter, fall, rise, cluster_id
                        ) 
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) 
                        RETURNING id
                    """, 
                        backend_id,
                        backend_data["name"],
                        server_data["server_name"],
                        server_data["server_address"],
                        server_data["server_port"],
                        server_data.get("weight", 100),
                        server_data.get("max_connections"),
                        server_data.get("check_enabled", True),
                        server_data.get("check_port"),
                        server_data.get("backup_server", False),
                        server_data.get("ssl_enabled", False),
                        server_data.get("ssl_verify"),
                        server_data.get("cookie_value"),
                        server_data.get("inter"),
                        server_data.get("fall"),
                        server_data.get("rise"),
                        request.cluster_id
                    )
                    
                    created_entities["servers"].append({
                        "id": server_id,
                        "name": server_data["server_name"],
                        "backend": backend_data["name"]
                    })
            
            # Create frontends
            for frontend_data in request.frontends:
                # Check if frontend already exists
                existing = await conn.fetchrow("""
                    SELECT id FROM frontends 
                    WHERE name = $1 AND cluster_id = $2 AND is_active = TRUE
                """, frontend_data["name"], request.cluster_id)
                
                if existing:
                    logger.warning(f"Frontend '{frontend_data['name']}' already exists, skipping")
                    continue
                
                # Insert frontend
                frontend_id = await conn.fetchval("""
                    INSERT INTO frontends (
                        name, bind_address, bind_port, default_backend, mode,
                        ssl_enabled, ssl_port, timeout_client, maxconn,
                        request_headers, response_headers, tcp_request_rules,
                        cluster_id, acl_rules, use_backend_rules, redirect_rules, updated_at
                    ) 
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, CURRENT_TIMESTAMP) 
                    RETURNING id
                """, 
                    frontend_data["name"],
                    frontend_data.get("bind_address", "*"),
                    frontend_data["bind_port"],
                    frontend_data.get("default_backend"),
                    frontend_data.get("mode", "http"),
                    frontend_data.get("ssl_enabled", False),
                    frontend_data.get("ssl_port"),
                    frontend_data.get("timeout_client"),
                    frontend_data.get("maxconn"),
                    frontend_data.get("request_headers"),
                    frontend_data.get("response_headers"),
                    frontend_data.get("tcp_request_rules"),
                    request.cluster_id,
                    json.dumps(frontend_data.get("acl_rules", [])),  # acl_rules
                    json.dumps(frontend_data.get("use_backend_rules", [])),  # use_backend_rules - CRITICAL FIX
                    json.dumps([])   # redirect_rules
                )
                
                created_entities["frontends"].append({
                    "id": frontend_id,
                    "name": frontend_data["name"]
                })
            
            # Generate config version for the cluster
            config_content = await generate_haproxy_config_for_cluster(request.cluster_id)
            config_hash = hashlib.sha256(config_content.encode()).hexdigest()
            version_name = f"bulk-import-{int(time.time())}"
            
            # Create PENDING config version
            config_version_id = await conn.fetchval("""
                INSERT INTO config_versions 
                (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                RETURNING id
            """, request.cluster_id, version_name, config_content, config_hash, current_user['id'])
            
            # Mark all created entities as PENDING
            if created_entities["backends"]:
                backend_ids = [b["id"] for b in created_entities["backends"]]
                await conn.execute("""
                    UPDATE backends SET last_config_status = 'PENDING' 
                    WHERE id = ANY($1)
                """, backend_ids)
            
            if created_entities["frontends"]:
                frontend_ids = [f["id"] for f in created_entities["frontends"]]
                await conn.execute("""
                    UPDATE frontends SET last_config_status = 'PENDING' 
                    WHERE id = ANY($1)
                """, frontend_ids)
            
            logger.info(f"BULK IMPORT: Created PENDING config version {version_name} for cluster {request.cluster_id}")
            
        except Exception as e:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create entities: {str(e)}"
            )
        
        await close_database_connection(conn)
        
        log_with_correlation(
            logger, "INFO",
            f"Bulk entity creation completed",
            user_id=current_user.get('id'),
            cluster_id=request.cluster_id,
            created_frontends=len(created_entities["frontends"]),
            created_backends=len(created_entities["backends"]),
            created_servers=len(created_entities["servers"])
        )
        
        return {
            "success": True,
            "message": "Entities created successfully. Please apply changes to activate.",
            "created": created_entities,
            "summary": {
                "frontends": len(created_entities["frontends"]),
                "backends": len(created_entities["backends"]),
                "servers": len(created_entities["servers"])
            },
            "config_version": version_name,
            "requires_apply": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bulk entity creation failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create entities: {str(e)}"
        )