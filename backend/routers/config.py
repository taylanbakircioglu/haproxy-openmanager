"""
Configuration Management and Validation API
Provides endpoints for HAProxy configuration validation, templates, and optimization
"""

from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import logging
import os
import re
import json

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
        # CRITICAL FIX: Keep connection open for SSL query later
        conn = await get_database_connection()
        user_roles = await conn.fetch("""
            SELECT r.name 
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.is_active = true
        """, current_user["id"])
        # DON'T close connection yet - needed for SSL query below
        
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
        
        # SMART SSL MATCHING: Check if SSL certificates exist in SSL Management
        # Get all SYNCED SSL certificates for this cluster (Global + Cluster-specific)
        ssl_certificates = await conn.fetch("""
            SELECT DISTINCT s.id, s.name, s.primary_domain as domain, s.status
            FROM ssl_certificates s
            LEFT JOIN ssl_certificate_clusters scc ON s.id = scc.ssl_certificate_id
            WHERE s.is_active = TRUE 
            AND s.last_config_status = 'APPLIED'
            AND (
                NOT EXISTS (SELECT 1 FROM ssl_certificate_clusters WHERE ssl_certificate_id = s.id)
                OR scc.cluster_id = $1
            )
        """, request.cluster_id)
        
        # Create SSL name to ID mapping
        ssl_name_map = {cert['name'].lower(): cert['id'] for cert in ssl_certificates}
        
        logger.info(f"BULK IMPORT SSL MATCHING: Found {len(ssl_certificates)} SYNCED SSL certificates for cluster {request.cluster_id}")
        logger.info(f"SSL name map: {list(ssl_name_map.keys())}")
        
        # Convert parsed entities to dict format
        frontends_data = []
        ssl_auto_assigned_frontends = []
        
        for frontend in parse_result.frontends:
            # SMART SSL MATCHING: Check if SSL cert path matches existing SYNCED SSL
            ssl_enabled = False
            ssl_certificate_ids = []
            ssl_port = None
            
            if frontend.ssl_cert_path:
                # Extract SSL certificate name from path
                # Example: /etc/ssl/haproxy/demo-global.pem → demo-global
                ssl_filename = os.path.basename(frontend.ssl_cert_path)
                ssl_name = re.sub(r'\.(pem|crt|key)$', '', ssl_filename, flags=re.IGNORECASE)
                
                # Check if this SSL exists in SSL Management and is SYNCED
                if ssl_name.lower() in ssl_name_map:
                    ssl_cert_id = ssl_name_map[ssl_name.lower()]
                    ssl_enabled = True
                    ssl_certificate_ids = [ssl_cert_id]
                    ssl_port = frontend.ssl_port
                    ssl_auto_assigned_frontends.append({
                        'frontend': frontend.name,
                        'ssl_name': ssl_name,
                        'ssl_id': ssl_cert_id
                    })
                    logger.info(f"BULK IMPORT SSL AUTO-ASSIGN: Frontend '{frontend.name}' matched SSL '{ssl_name}' (ID: {ssl_cert_id})")
            
            frontends_data.append({
                "name": frontend.name,
                "bind_address": frontend.bind_address,
                "bind_port": frontend.bind_port,
                "default_backend": frontend.default_backend,
                "mode": frontend.mode,
                "ssl_enabled": ssl_enabled,  # Smart: True if matched SSL found
                "ssl_certificate_ids": ssl_certificate_ids,  # Smart: Auto-assigned if matched
                "ssl_port": ssl_port,  # Smart: Preserved if SSL matched
                "timeout_client": frontend.timeout_client,
                "maxconn": frontend.maxconn,
                "request_headers": frontend.request_headers,
                "response_headers": frontend.response_headers,
                "options": frontend.options,
                "tcp_request_rules": frontend.tcp_request_rules,
                "acl_rules": frontend.acl_rules,
                "use_backend_rules": frontend.use_backend_rules
            })
        
        backends_data = []
        ssl_auto_assigned_servers = []
        
        for backend in parse_result.backends:
            servers_data = []
            for server in backend.servers:
                # SMART SSL MATCHING: Check if server had ca-file that matches SYNCED SSL
                # Parser stores SSL info in warnings, we need to check original config
                ssl_certificate_id = None
                
                # If server has ssl_enabled and ssl_verify, check if we can match SSL
                # Parser already changed verify to 'none' if ca-file was removed
                # We need to restore it to 'required' if we find matching SSL
                ssl_verify = server.ssl_verify
                original_verify_was_required = False  # Track if original config had verify required
                
                # Check if this server originally had ca-file by looking for matching SSL name
                # We'll parse it from the original config line if needed
                # For now, we'll use a different approach: check parser warnings for this server
                for warning in parse_result.warnings:
                    if f"Server '{server.server_name}'" in warning and "ca-file" in warning:
                        # Extract SSL path from warning
                        ca_file_match = re.search(r"ca-file '([^']+)'", warning)
                        
                        # Check if original config had 'verify required'
                        if "verify required" in warning.lower():
                            original_verify_was_required = True
                        
                        if ca_file_match:
                            ca_file_path = ca_file_match.group(1)
                            ssl_filename = os.path.basename(ca_file_path)
                            ssl_name = re.sub(r'\.(pem|crt|key)$', '', ssl_filename, flags=re.IGNORECASE)
                            
                            # Check if this SSL exists and is SYNCED
                            if ssl_name.lower() in ssl_name_map:
                                ssl_certificate_id = ssl_name_map[ssl_name.lower()]
                                ssl_verify = 'required'  # Restore original verify
                                ssl_auto_assigned_servers.append({
                                    'server': f"{backend.name}/{server.server_name}",
                                    'ssl_name': ssl_name,
                                    'ssl_id': ssl_certificate_id
                                })
                                logger.info(f"BULK IMPORT SSL AUTO-ASSIGN: Server '{backend.name}/{server.server_name}' matched SSL '{ssl_name}' (ID: {ssl_certificate_id})")
                            else:
                                # SSL certificate not found in database, but preserve original verify intent
                                if original_verify_was_required:
                                    ssl_verify = 'required'
                                    logger.warning(f"BULK IMPORT SSL: Server '{backend.name}/{server.server_name}' has 'verify required' but SSL certificate '{ssl_name}' not found in database. Preserving 'required' for manual SSL assignment.")
                            break
                
                # Get SSL certificate name for UI display
                ssl_certificate_name = None
                if ssl_certificate_id:
                    for cert in ssl_certificates:
                        if cert['id'] == ssl_certificate_id:
                            ssl_certificate_name = cert['name']
                            break
                
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
                    "ssl_verify": ssl_verify,  # Smart: 'required' if SSL matched, else parser value
                    "ssl_certificate_id": ssl_certificate_id,  # Smart: Auto-assigned if matched
                    "ssl_certificate_name": ssl_certificate_name,  # For UI display
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
                "options": backend.options,
                "timeout_connect": backend.timeout_connect,
                "timeout_server": backend.timeout_server,
                "timeout_queue": backend.timeout_queue,
                "servers": servers_data
            })
        
        # CRITICAL: Filter out SSL warnings for auto-assigned certificates
        # If SSL was auto-assigned, user doesn't need warnings about manual assignment
        auto_assigned_ssl_names = set()
        for f in ssl_auto_assigned_frontends:
            auto_assigned_ssl_names.add(f['ssl_name'].lower())
        for s in ssl_auto_assigned_servers:
            auto_assigned_ssl_names.add(s['ssl_name'].lower())
        
        # Filter warnings - remove SSL warnings for auto-assigned certificates
        filtered_warnings = []
        for warning in parse_result.warnings:
            # Check if this warning is about an auto-assigned SSL
            is_auto_assigned_warning = False
            for ssl_name in auto_assigned_ssl_names:
                if ssl_name in warning.lower() and ('ca-file' in warning or 'SSL certificates detected' in warning):
                    is_auto_assigned_warning = True
                    break
            
            # Keep warning only if NOT about auto-assigned SSL
            if not is_auto_assigned_warning:
                filtered_warnings.append(warning)
        
        # Add SSL auto-assignment info to warnings
        ssl_auto_assign_info = []
        if ssl_auto_assigned_frontends:
            ssl_auto_assign_info.append(
                f"SSL AUTO-ASSIGNED: {len(ssl_auto_assigned_frontends)} frontend(s) automatically matched with existing SSL certificates. "
                f"These frontends will be created with SSL enabled. "
                f"Matched: {', '.join([f['frontend'] + ' (' + f['ssl_name'] + ')' for f in ssl_auto_assigned_frontends])}"
            )
        if ssl_auto_assigned_servers:
            ssl_auto_assign_info.append(
                f"SSL AUTO-ASSIGNED: {len(ssl_auto_assigned_servers)} server(s) automatically matched with existing SSL certificates. "
                f"These servers will have SSL verification enabled with ca-file. "
                f"Matched: {', '.join([s['server'] + ' (' + s['ssl_name'] + ')' for s in ssl_auto_assigned_servers])}"
            )
        
        # Update SSL warning message to include pre-import tip (only if there are SSL warnings left)
        enhanced_warnings = filtered_warnings.copy()
        
        # Remove generic SSL handling instructions if ALL SSL was auto-assigned
        # If user still has unmatched SSL, they need the instructions
        has_unmatched_ssl = any('SSL' in w or 'ca-file' in w for w in enhanced_warnings)
        
        if has_unmatched_ssl:
            # There are still unmatched SSL certificates
            enhanced_warnings.insert(0, 
                "TIP: For automatic SSL assignment in bulk import, first create and apply SSL certificates "
                "via SSL Management page (enter PEM content) with matching names, then perform bulk import. "
                "Certificates with status SYNCED will be automatically assigned."
            )
        else:
            # All SSL was auto-assigned or no SSL in config
            # No need for manual SSL instructions
            pass
        
        # Add auto-assignment info at the beginning
        enhanced_warnings = ssl_auto_assign_info + enhanced_warnings
        
        # BULK IMPORT MVP: Check existing entities for UPSERT detection
        # Mark each entity as new or update for UI display
        # CRITICAL: Only mark as UPDATE if there are actual field changes
        new_frontends = 0
        update_frontends = 0
        new_backends = 0
        update_backends = 0
        new_servers = 0
        
        for frontend in frontends_data:
            existing = await conn.fetchrow("""
                SELECT * FROM frontends 
                WHERE name = $1 AND cluster_id = $2
            """, frontend["name"], request.cluster_id)
            
            if existing:
                # Check if any field has actually changed AND track which fields changed
                has_changes = False
                changes = {}  # Track field-level changes for UI highlighting
                
                # Compare all fields that can be updated
                if frontend.get("bind_address") and frontend["bind_address"] != existing["bind_address"]:
                    has_changes = True
                    changes["bind_address"] = {"old": existing["bind_address"], "new": frontend["bind_address"]}
                if frontend.get("bind_port") and frontend["bind_port"] != existing["bind_port"]:
                    has_changes = True
                    changes["bind_port"] = {"old": existing["bind_port"], "new": frontend["bind_port"]}
                if frontend.get("default_backend") and frontend["default_backend"] != existing["default_backend"]:
                    has_changes = True
                    changes["default_backend"] = {"old": existing["default_backend"], "new": frontend["default_backend"]}
                if frontend.get("mode") and frontend["mode"] != existing["mode"]:
                    has_changes = True
                    changes["mode"] = {"old": existing["mode"], "new": frontend["mode"]}
                # MVP DECISION: SSL settings are NOT compared for change detection
                # Bulk import preserves manual SSL configuration (ssl_enabled, ssl_certificate_ids, ssl_port)
                # This aligns with bulk-create endpoint behavior (line 1588-1589)
                # If SSL changes are detected in parse, they will be ignored in bulk-create anyway
                # So we don't mark frontend as UPDATE for SSL-only changes
                if frontend.get("timeout_client") and frontend["timeout_client"] != existing["timeout_client"]:
                    has_changes = True
                    changes["timeout_client"] = {"old": existing["timeout_client"], "new": frontend["timeout_client"]}
                if frontend.get("maxconn") and frontend["maxconn"] != existing["maxconn"]:
                    has_changes = True
                    changes["maxconn"] = {"old": existing["maxconn"], "new": frontend["maxconn"]}
                if frontend.get("request_headers") and frontend["request_headers"] != existing["request_headers"]:
                    has_changes = True
                    changes["request_headers"] = {"old": existing["request_headers"], "new": frontend["request_headers"]}
                if frontend.get("response_headers") and frontend["response_headers"] != existing["response_headers"]:
                    has_changes = True
                    changes["response_headers"] = {"old": existing["response_headers"], "new": frontend["response_headers"]}
                if frontend.get("options") and frontend["options"] != existing.get("options"):
                    has_changes = True
                    changes["options"] = {"old": existing.get("options"), "new": frontend["options"]}
                if frontend.get("tcp_request_rules") and frontend["tcp_request_rules"] != existing["tcp_request_rules"]:
                    has_changes = True
                    changes["tcp_request_rules"] = {"old": existing["tcp_request_rules"], "new": frontend["tcp_request_rules"]}
                
                # Additional frontend fields (timeout_http_request, rate_limit, compression, log_separate, monitor_uri)
                if frontend.get("timeout_http_request") and frontend["timeout_http_request"] != existing.get("timeout_http_request"):
                    has_changes = True
                    changes["timeout_http_request"] = {"old": existing.get("timeout_http_request"), "new": frontend["timeout_http_request"]}
                if frontend.get("rate_limit") and frontend["rate_limit"] != existing.get("rate_limit"):
                    has_changes = True
                    changes["rate_limit"] = {"old": existing.get("rate_limit"), "new": frontend["rate_limit"]}
                if "compression" in frontend and frontend["compression"] != existing.get("compression", False):
                    has_changes = True
                    changes["compression"] = {"old": existing.get("compression", False), "new": frontend["compression"]}
                if "log_separate" in frontend and frontend["log_separate"] != existing.get("log_separate", False):
                    has_changes = True
                    changes["log_separate"] = {"old": existing.get("log_separate", False), "new": frontend["log_separate"]}
                if frontend.get("monitor_uri") and frontend["monitor_uri"] != existing.get("monitor_uri"):
                    has_changes = True
                    changes["monitor_uri"] = {"old": existing.get("monitor_uri"), "new": frontend["monitor_uri"]}
                
                # Note: acl_rules and use_backend_rules are not stored in frontends table, they're managed separately
                
                # Check if entity is inactive (reactivation counts as change)
                if not existing['is_active']:
                    has_changes = True
                    changes["is_active"] = {"old": False, "new": True}
                
                frontend["_isNew"] = False
                frontend["_isUpdate"] = has_changes  # Only true if actual changes detected
                frontend["_existingId"] = existing['id']
                frontend["_isActive"] = existing['is_active']
                frontend["_changes"] = changes if changes else None  # Field-level changes for UI
                
                if has_changes:
                    update_frontends += 1
            else:
                frontend["_isNew"] = True
                frontend["_isUpdate"] = False
                new_frontends += 1
        
        for backend in backends_data:
            existing = await conn.fetchrow("""
                SELECT * FROM backends 
                WHERE name = $1 AND cluster_id = $2
            """, backend["name"], request.cluster_id)
            
            if existing:
                # Check if any field has actually changed AND track which fields changed
                has_changes = False
                changes = {}  # Track field-level changes for UI highlighting
                
                if backend.get("balance_method") and backend["balance_method"] != existing["balance_method"]:
                    has_changes = True
                    changes["balance_method"] = {"old": existing["balance_method"], "new": backend["balance_method"]}
                if backend.get("mode") and backend["mode"] != existing["mode"]:
                    has_changes = True
                    changes["mode"] = {"old": existing["mode"], "new": backend["mode"]}
                if backend.get("health_check_uri") and backend["health_check_uri"] != existing["health_check_uri"]:
                    has_changes = True
                    changes["health_check_uri"] = {"old": existing["health_check_uri"], "new": backend["health_check_uri"]}
                if backend.get("health_check_interval") and backend["health_check_interval"] != existing["health_check_interval"]:
                    has_changes = True
                    changes["health_check_interval"] = {"old": existing["health_check_interval"], "new": backend["health_check_interval"]}
                if backend.get("health_check_expected_status") is not None and backend["health_check_expected_status"] != existing["health_check_expected_status"]:
                    has_changes = True
                    changes["health_check_expected_status"] = {"old": existing["health_check_expected_status"], "new": backend["health_check_expected_status"]}
                if backend.get("fullconn") and backend["fullconn"] != existing["fullconn"]:
                    has_changes = True
                    changes["fullconn"] = {"old": existing["fullconn"], "new": backend["fullconn"]}
                if backend.get("timeout_connect") and backend["timeout_connect"] != existing["timeout_connect"]:
                    has_changes = True
                    changes["timeout_connect"] = {"old": existing["timeout_connect"], "new": backend["timeout_connect"]}
                if backend.get("timeout_server") and backend["timeout_server"] != existing["timeout_server"]:
                    has_changes = True
                    changes["timeout_server"] = {"old": existing["timeout_server"], "new": backend["timeout_server"]}
                if backend.get("timeout_queue") and backend["timeout_queue"] != existing["timeout_queue"]:
                    has_changes = True
                    changes["timeout_queue"] = {"old": existing["timeout_queue"], "new": backend["timeout_queue"]}
                if backend.get("cookie_name") and backend["cookie_name"] != existing["cookie_name"]:
                    has_changes = True
                    changes["cookie_name"] = {"old": existing["cookie_name"], "new": backend["cookie_name"]}
                if backend.get("cookie_options") and backend["cookie_options"] != existing["cookie_options"]:
                    has_changes = True
                    changes["cookie_options"] = {"old": existing["cookie_options"], "new": backend["cookie_options"]}
                if backend.get("default_server_inter") and backend["default_server_inter"] != existing["default_server_inter"]:
                    has_changes = True
                    changes["default_server_inter"] = {"old": existing["default_server_inter"], "new": backend["default_server_inter"]}
                if backend.get("default_server_fall") and backend["default_server_fall"] != existing["default_server_fall"]:
                    has_changes = True
                    changes["default_server_fall"] = {"old": existing["default_server_fall"], "new": backend["default_server_fall"]}
                if backend.get("default_server_rise") and backend["default_server_rise"] != existing["default_server_rise"]:
                    has_changes = True
                    changes["default_server_rise"] = {"old": existing["default_server_rise"], "new": backend["default_server_rise"]}
                if backend.get("request_headers") and backend["request_headers"] != existing["request_headers"]:
                    has_changes = True
                    changes["request_headers"] = {"old": existing["request_headers"], "new": backend["request_headers"]}
                if backend.get("response_headers") and backend["response_headers"] != existing["response_headers"]:
                    has_changes = True
                    changes["response_headers"] = {"old": existing["response_headers"], "new": backend["response_headers"]}
                if backend.get("options") and backend["options"] != existing.get("options"):
                    has_changes = True
                    changes["options"] = {"old": existing.get("options"), "new": backend["options"]}
                
                # Check if entity is inactive (reactivation counts as change)
                if not existing['is_active']:
                    has_changes = True
                    changes["is_active"] = {"old": False, "new": True}
                
                backend["_isNew"] = False
                backend["_isUpdate"] = has_changes  # Only true if actual changes detected
                backend["_existingId"] = existing['id']
                backend["_isActive"] = existing['is_active']
                backend["_changes"] = changes if changes else None  # Field-level changes for UI
                
                if has_changes:
                    update_backends += 1
                
                # Check servers for this backend
                for server in backend.get("servers", []):
                    existing_server = await conn.fetchrow("""
                        SELECT id FROM backend_servers 
                        WHERE backend_name = $1 AND server_name = $2 
                        AND cluster_id = $3 AND is_active = TRUE
                    """, backend["name"], server["server_name"], request.cluster_id)
                    
                    if not existing_server:
                        server["_isNew"] = True
                        new_servers += 1
                    else:
                        server["_isNew"] = False
            else:
                backend["_isNew"] = True
                backend["_isUpdate"] = False
                new_backends += 1
                
                # All servers are new for a new backend
                for server in backend.get("servers", []):
                    server["_isNew"] = True
                    new_servers += 1
        
        log_with_correlation(
            logger, "INFO",
            f"Bulk config parsed successfully",
            user_id=current_user.get('id'),
            frontends_count=len(frontends_data),
            backends_count=len(backends_data),
            errors_count=len(parse_result.errors),
            warnings_count=len(enhanced_warnings),
            ssl_auto_frontends=len(ssl_auto_assigned_frontends),
            ssl_auto_servers=len(ssl_auto_assigned_servers),
            new_frontends=new_frontends,
            update_frontends=update_frontends,
            new_backends=new_backends,
            update_backends=update_backends,
            new_servers=new_servers
        )
        
        # Close connection before returning
        await close_database_connection(conn)
        
        return {
            "success": True,
            "frontends": frontends_data,
            "backends": backends_data,
            "errors": parse_result.errors,
            "warnings": enhanced_warnings,
            "ssl_auto_assigned": {
                "frontends": ssl_auto_assigned_frontends,
                "servers": ssl_auto_assigned_servers
            },
            "summary": {
                "frontends_count": len(frontends_data),
                "backends_count": len(backends_data),
                "total_servers_count": sum(len(b["servers"]) for b in backends_data),
                "ssl_auto_assigned_count": len(ssl_auto_assigned_frontends) + len(ssl_auto_assigned_servers),
                "new_frontends": new_frontends,
                "update_frontends": update_frontends,
                "new_backends": new_backends,
                "update_backends": update_backends,
                "new_servers": new_servers
            }
        }
        
    except HTTPException:
        # Close connection on HTTP exception
        if 'conn' in locals():
            await close_database_connection(conn)
        raise
    except Exception as e:
        # Close connection on error
        if 'conn' in locals():
            await close_database_connection(conn)
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
        
        # BULK IMPORT MVP: Check for pending apply changes
        # Prevent bulk import if there are unapplied changes (conflict prevention)
        pending_changes = await conn.fetchval("""
            SELECT COUNT(*) FROM (
                SELECT 1 FROM frontends 
                WHERE cluster_id = $1 AND last_config_status = 'PENDING'
                UNION ALL
                SELECT 1 FROM backends 
                WHERE cluster_id = $1 AND last_config_status = 'PENDING'
                UNION ALL
                SELECT 1 FROM backend_servers 
                WHERE cluster_id = $1 AND last_config_status = 'PENDING'
            ) AS pending
        """, request.cluster_id)
        
        if pending_changes and pending_changes > 0:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=409,  # Conflict
                detail=f"Cannot perform bulk import: {pending_changes} pending changes found. "
                       f"Please apply or discard existing changes in Apply Management page before importing."
            )
        
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
            from utils.entity_snapshot import save_entity_snapshot
            
            # Track updated entities for user feedback
            updated_entities = {
                "frontends": [],
                "backends": []
            }
            
            # PHASE 4: Track all entity snapshots for bulk rollback
            bulk_snapshots = []
            
            # BULK IMPORT MVP: Process backends with UPSERT (merge strategy)
            # Create or update backends first (frontends may reference them)
            for backend_data in request.backends:
                # Check if backend already exists (check both active AND inactive)
                existing = await conn.fetchrow("""
                    SELECT id, is_active FROM backends 
                    WHERE name = $1 AND cluster_id = $2
                """, backend_data["name"], request.cluster_id)
                
                backend_id = None
                
                if existing and backend_data.get("_isUpdate"):
                    # UPDATE MODE: Merge strategy - only update fields present in config
                    # Preserve existing values for fields not in imported config
                    backend_id = existing['id']
                    
                    # Fetch full backend to compare values (only UPDATE if changed)
                    existing_full = await conn.fetchrow("SELECT * FROM backends WHERE id = $1", backend_id)
                    
                    # Build update query dynamically for merge strategy
                    update_fields = []
                    update_values = [backend_id]  # $1 is always backend_id
                    param_index = 2
                    
                    # Only update fields that are explicitly provided in import AND different from DB
                    if backend_data.get("balance_method") and backend_data["balance_method"] != existing_full["balance_method"]:
                        update_fields.append(f"balance_method = ${param_index}")
                        update_values.append(backend_data["balance_method"])
                        param_index += 1
                    
                    if backend_data.get("mode") and backend_data["mode"] != existing_full["mode"]:
                        update_fields.append(f"mode = ${param_index}")
                        update_values.append(backend_data["mode"])
                        param_index += 1
                    
                    if backend_data.get("health_check_uri") and backend_data["health_check_uri"] != existing_full["health_check_uri"]:
                        update_fields.append(f"health_check_uri = ${param_index}")
                        update_values.append(backend_data["health_check_uri"])
                        param_index += 1
                    
                    if backend_data.get("health_check_interval") and backend_data["health_check_interval"] != existing_full["health_check_interval"]:
                        update_fields.append(f"health_check_interval = ${param_index}")
                        update_values.append(backend_data["health_check_interval"])
                        param_index += 1
                    
                    # Health check expected status (only for HTTP mode)
                    backend_mode = backend_data.get("mode", existing_full["mode"])
                    if backend_mode == "http" and backend_data.get("health_check_expected_status") is not None:
                        if backend_data["health_check_expected_status"] != existing_full["health_check_expected_status"]:
                            update_fields.append(f"health_check_expected_status = ${param_index}")
                            update_values.append(backend_data["health_check_expected_status"])
                            param_index += 1
                    
                    if backend_data.get("fullconn") and backend_data["fullconn"] != existing_full["fullconn"]:
                        update_fields.append(f"fullconn = ${param_index}")
                        update_values.append(backend_data["fullconn"])
                        param_index += 1
                    
                    if backend_data.get("timeout_connect") and backend_data["timeout_connect"] != existing_full["timeout_connect"]:
                        update_fields.append(f"timeout_connect = ${param_index}")
                        update_values.append(backend_data["timeout_connect"])
                        param_index += 1
                    
                    if backend_data.get("timeout_server") and backend_data["timeout_server"] != existing_full["timeout_server"]:
                        update_fields.append(f"timeout_server = ${param_index}")
                        update_values.append(backend_data["timeout_server"])
                        param_index += 1
                    
                    if backend_data.get("timeout_queue") and backend_data["timeout_queue"] != existing_full["timeout_queue"]:
                        update_fields.append(f"timeout_queue = ${param_index}")
                        update_values.append(backend_data["timeout_queue"])
                        param_index += 1
                    
                    # CRITICAL FIX: Add missing fields from normal backend create with value comparison
                    if backend_data.get("cookie_name") and backend_data["cookie_name"] != existing_full["cookie_name"]:
                        update_fields.append(f"cookie_name = ${param_index}")
                        update_values.append(backend_data["cookie_name"])
                        param_index += 1
                    
                    if backend_data.get("cookie_options") and backend_data["cookie_options"] != existing_full["cookie_options"]:
                        update_fields.append(f"cookie_options = ${param_index}")
                        update_values.append(backend_data["cookie_options"])
                        param_index += 1
                    
                    if backend_data.get("default_server_inter") and backend_data["default_server_inter"] != existing_full["default_server_inter"]:
                        update_fields.append(f"default_server_inter = ${param_index}")
                        update_values.append(backend_data["default_server_inter"])
                        param_index += 1
                    
                    if backend_data.get("default_server_fall") and backend_data["default_server_fall"] != existing_full["default_server_fall"]:
                        update_fields.append(f"default_server_fall = ${param_index}")
                        update_values.append(backend_data["default_server_fall"])
                        param_index += 1
                    
                    if backend_data.get("default_server_rise") and backend_data["default_server_rise"] != existing_full["default_server_rise"]:
                        update_fields.append(f"default_server_rise = ${param_index}")
                        update_values.append(backend_data["default_server_rise"])
                        param_index += 1
                    
                    # BUGFIX: Preserve manually-added use-service directives during bulk import
                    # Use-service directives (like prometheus-exporter) are skipped during parsing
                    # but should be preserved if manually added to the backend (consistent with frontend)
                    if backend_data.get("request_headers"):
                        # Get existing request_headers
                        existing_headers = existing_full["request_headers"] or ""
                        new_headers = backend_data["request_headers"]
                        
                        # Extract use-service directives from existing headers
                        use_service_lines = []
                        if existing_headers:
                            for line in existing_headers.split('\n'):
                                if line.strip() and 'use-service' in line:
                                    use_service_lines.append(line.strip())
                        
                        # Merge: Add preserved use-service lines to new headers
                        merged_headers = new_headers
                        if use_service_lines:
                            # Append use-service lines to new headers
                            merged_headers = new_headers + '\n' + '\n'.join(use_service_lines)
                            logger.info(f"BULK IMPORT: Preserved {len(use_service_lines)} use-service directive(s) for backend '{backend_data['name']}'")
                        
                        # Only update if merged result is different from existing
                        if merged_headers != existing_headers:
                            update_fields.append(f"request_headers = ${param_index}")
                            update_values.append(merged_headers)
                            param_index += 1
                    
                    if backend_data.get("response_headers") and backend_data["response_headers"] != existing_full["response_headers"]:
                        update_fields.append(f"response_headers = ${param_index}")
                        update_values.append(backend_data["response_headers"])
                        param_index += 1
                    
                    # NEW: Options field support (option http-keep-alive, etc.)
                    if backend_data.get("options") and backend_data["options"] != existing_full.get("options"):
                        update_fields.append(f"options = ${param_index}")
                        update_values.append(backend_data["options"])
                        param_index += 1
                    
                    # NOTE: maxconn field exists in database but is not used in normal backend UPDATE
                    # Preserving consistency with existing backend UPDATE endpoint (backend.py)
                    # maxconn field intentionally excluded from bulk import UPDATE
                    
                    # Only update is_active if entity is currently inactive (reactivation)
                    # This prevents unnecessary UPDATE when backend is already active
                    if not existing['is_active']:
                        update_fields.append(f"is_active = ${param_index}")
                        update_values.append(True)
                        param_index += 1
                    
                    # Execute UPDATE only if there are actual field changes
                    if update_fields:
                        # PHASE 4: Create snapshot BEFORE update
                        snapshot = await save_entity_snapshot(
                            conn=conn,
                            entity_type="backend",
                            entity_id=backend_id,
                            old_values=existing_full,
                            new_values=backend_data,
                            operation="UPDATE"
                        )
                        if snapshot:
                            bulk_snapshots.append(snapshot)
                        
                        update_query = f"""
                            UPDATE backends 
                            SET {', '.join(update_fields)}, updated_at = CURRENT_TIMESTAMP
                            WHERE id = $1
                        """
                        await conn.execute(update_query, *update_values)
                        
                        updated_entities["backends"].append({
                            "id": backend_id,
                            "name": backend_data["name"],
                            "was_inactive": not existing['is_active']
                        })
                        
                        logger.info(f"Updated backend '{backend_data['name']}' (ID: {backend_id})")
                    
                    # Don't skip - continue to process servers below
                
                elif existing:
                    # Backend exists but not flagged for update (shouldn't happen with MVP logic)
                    # Skip silently
                    logger.warning(f"Backend '{backend_data['name']}' exists but not marked for update, skipping")
                    continue
                
                else:
                    # CREATE MODE: Insert new backend
                    # CRITICAL: Only set health_check_expected_status for HTTP mode backends
                    # TCP backends cannot use http-check directives
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
                            response_headers, options, timeout_connect, timeout_server, timeout_queue, cluster_id
                        ) 
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) 
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
                        backend_data.get("options"),
                        backend_data.get("timeout_connect", 10000),
                        backend_data.get("timeout_server", 60000),
                        backend_data.get("timeout_queue", 60000),
                        request.cluster_id
                    )
                    
                    created_entities["backends"].append({
                        "id": backend_id,
                        "name": backend_data["name"]
                    })
                    
                    # PHASE 4: Create snapshot for CREATE operation (for rollback = deletion)
                    snapshot = await save_entity_snapshot(
                        conn=conn,
                        entity_type="backend",
                        entity_id=backend_id,
                        old_values={},  # No old values for CREATE
                        operation="CREATE"
                    )
                    if snapshot:
                        bulk_snapshots.append(snapshot)
                
                # SERVERS: Process servers for both CREATE and UPDATE modes
                # MVP: Only add new servers, preserve existing ones (no deletion)
                backend_has_new_servers = False  # Track if new servers were added
                if backend_id:  # Only if we have a valid backend_id
                    for server_data in backend_data.get("servers", []):
                        # Only create server if marked as new (MVP: skip existing)
                        if not server_data.get("_isNew", True):
                            logger.debug(f"Server '{server_data['server_name']}' already exists in backend '{backend_data['name']}', preserving")
                            continue
                        
                        server_id = await conn.fetchval("""
                                INSERT INTO backend_servers (
                                backend_id, backend_name, server_name, server_address, 
                                server_port, weight, maxconn, check_enabled, check_port,
                                backup_server, ssl_enabled, ssl_verify, ssl_certificate_id, cookie_value,
                                inter, fall, rise, cluster_id
                            ) 
                            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) 
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
                            server_data.get("ssl_certificate_id"),  # CRITICAL: Auto-assigned SSL ID
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
                        backend_has_new_servers = True
                        
                        # PHASE 4: Create snapshot for new server (CREATE operation)
                        snapshot = await save_entity_snapshot(
                            conn=conn,
                            entity_type="server",
                            entity_id=server_id,
                            old_values={},  # No old values for CREATE
                            operation="CREATE"
                        )
                        if snapshot:
                            bulk_snapshots.append(snapshot)
                    
                    # If backend wasn't updated but has new servers, add to updated_entities
                    # This ensures backend gets marked as PENDING for Apply Management
                    if backend_has_new_servers and existing and backend_data.get("_isUpdate"):
                        if backend_id not in [b["id"] for b in updated_entities["backends"]]:
                            updated_entities["backends"].append({
                                "id": backend_id,
                                "name": backend_data["name"],
                                "was_inactive": not existing['is_active']
                            })
                            logger.info(f"Backend '{backend_data['name']}' marked for update (new servers added)")
            
            # BULK IMPORT MVP: Process frontends with UPSERT (merge strategy)
            for frontend_data in request.frontends:
                # Check if frontend already exists (check both active AND inactive)
                existing = await conn.fetchrow("""
                    SELECT id, is_active FROM frontends 
                    WHERE name = $1 AND cluster_id = $2
                """, frontend_data["name"], request.cluster_id)
                
                frontend_id = None
                
                if existing and frontend_data.get("_isUpdate"):
                    # UPDATE MODE: Merge strategy - only update fields present in config
                    # MVP DECISION: Preserve SSL mappings, ACL rules, and complex configurations
                    # NOTE: This differs from normal frontend UPDATE endpoint (PUT /api/frontends/{id})
                    # which does full replace. Bulk import uses merge strategy for safety.
                    frontend_id = existing['id']
                    
                    # Fetch full frontend to compare values (only UPDATE if changed)
                    existing_full = await conn.fetchrow("SELECT * FROM frontends WHERE id = $1", frontend_id)
                    
                    # Build update query dynamically for merge strategy
                    update_fields = []
                    update_values = [frontend_id]  # $1 is always frontend_id
                    param_index = 2
                    
                    # Only update fields that are explicitly provided in import AND different from DB
                    if frontend_data.get("bind_address") and frontend_data["bind_address"] != existing_full["bind_address"]:
                        update_fields.append(f"bind_address = ${param_index}")
                        update_values.append(frontend_data["bind_address"])
                        param_index += 1
                    
                    if frontend_data.get("bind_port") and frontend_data["bind_port"] != existing_full["bind_port"]:
                        update_fields.append(f"bind_port = ${param_index}")
                        update_values.append(frontend_data["bind_port"])
                        param_index += 1
                    
                    if frontend_data.get("default_backend") and frontend_data["default_backend"] != existing_full["default_backend"]:
                        update_fields.append(f"default_backend = ${param_index}")
                        update_values.append(frontend_data["default_backend"])
                        param_index += 1
                    
                    if frontend_data.get("mode") and frontend_data["mode"] != existing_full["mode"]:
                        update_fields.append(f"mode = ${param_index}")
                        update_values.append(frontend_data["mode"])
                        param_index += 1
                    
                    # MVP: DON'T update SSL settings (preserve manual configuration)
                    # ssl_enabled and ssl_certificate_ids are preserved
                    
                    if frontend_data.get("timeout_client") and frontend_data["timeout_client"] != existing_full["timeout_client"]:
                        update_fields.append(f"timeout_client = ${param_index}")
                        update_values.append(frontend_data["timeout_client"])
                        param_index += 1
                    
                    if frontend_data.get("maxconn") and frontend_data["maxconn"] != existing_full["maxconn"]:
                        update_fields.append(f"maxconn = ${param_index}")
                        update_values.append(frontend_data["maxconn"])
                        param_index += 1
                    
                    # CRITICAL FIX: Add missing fields from normal frontend create with value comparison
                    # BUGFIX: Preserve manually-added use-service directives during bulk import
                    # Use-service directives (like prometheus-exporter) are skipped during parsing
                    # but should be preserved if manually added to the frontend
                    if frontend_data.get("request_headers"):
                        # Get existing request_headers
                        existing_headers = existing_full["request_headers"] or ""
                        new_headers = frontend_data["request_headers"]
                        
                        # Extract use-service directives from existing headers
                        use_service_lines = []
                        if existing_headers:
                            for line in existing_headers.split('\n'):
                                if line.strip() and 'use-service' in line:
                                    use_service_lines.append(line.strip())
                        
                        # Merge: Add preserved use-service lines to new headers
                        merged_headers = new_headers
                        if use_service_lines:
                            # Append use-service lines to new headers
                            merged_headers = new_headers + '\n' + '\n'.join(use_service_lines)
                            logger.info(f"BULK IMPORT: Preserved {len(use_service_lines)} use-service directive(s) for frontend '{frontend_data['name']}'")
                        
                        # Only update if merged result is different from existing
                        if merged_headers != existing_headers:
                            update_fields.append(f"request_headers = ${param_index}")
                            update_values.append(merged_headers)
                            param_index += 1
                    
                    if frontend_data.get("response_headers") and frontend_data["response_headers"] != existing_full["response_headers"]:
                        update_fields.append(f"response_headers = ${param_index}")
                        update_values.append(frontend_data["response_headers"])
                        param_index += 1
                    
                    if frontend_data.get("tcp_request_rules") and frontend_data["tcp_request_rules"] != existing_full["tcp_request_rules"]:
                        update_fields.append(f"tcp_request_rules = ${param_index}")
                        update_values.append(frontend_data["tcp_request_rules"])
                        param_index += 1
                    
                    # NEW: Options field support (option httplog, option forwardfor, etc.)
                    if frontend_data.get("options") and frontend_data["options"] != existing_full.get("options"):
                        update_fields.append(f"options = ${param_index}")
                        update_values.append(frontend_data["options"])
                        param_index += 1
                    
                    if frontend_data.get("timeout_http_request") and frontend_data["timeout_http_request"] != existing_full["timeout_http_request"]:
                        update_fields.append(f"timeout_http_request = ${param_index}")
                        update_values.append(frontend_data["timeout_http_request"])
                        param_index += 1
                    
                    if frontend_data.get("rate_limit") and frontend_data["rate_limit"] != existing_full["rate_limit"]:
                        update_fields.append(f"rate_limit = ${param_index}")
                        update_values.append(frontend_data["rate_limit"])
                        param_index += 1
                    
                    if "compression" in frontend_data and frontend_data["compression"] != existing_full.get("compression", False):
                        update_fields.append(f"compression = ${param_index}")
                        update_values.append(frontend_data["compression"])
                        param_index += 1
                    
                    if "log_separate" in frontend_data and frontend_data["log_separate"] != existing_full.get("log_separate", False):
                        update_fields.append(f"log_separate = ${param_index}")
                        update_values.append(frontend_data["log_separate"])
                        param_index += 1
                    
                    if frontend_data.get("monitor_uri") and frontend_data["monitor_uri"] != existing_full["monitor_uri"]:
                        update_fields.append(f"monitor_uri = ${param_index}")
                        update_values.append(frontend_data["monitor_uri"])
                        param_index += 1
                    
                    # MVP: DON'T update ACL rules (preserve manual configuration)
                    # acl_rules, use_backend_rules are preserved
                    
                    # Only update is_active if entity is currently inactive (reactivation)
                    if not existing['is_active']:
                        update_fields.append(f"is_active = ${param_index}")
                        update_values.append(True)
                        param_index += 1
                    
                    # Execute UPDATE if there are fields to update
                    if update_fields:
                        update_query = f"""
                            UPDATE frontends 
                            SET {', '.join(update_fields)}, updated_at = CURRENT_TIMESTAMP
                            WHERE id = $1
                        """
                        await conn.execute(update_query, *update_values)
                        
                        updated_entities["frontends"].append({
                            "id": frontend_id,
                            "name": frontend_data["name"],
                            "was_inactive": not existing['is_active']
                        })
                        
                        logger.info(f"Updated frontend '{frontend_data['name']}' (ID: {frontend_id})")
                
                elif existing:
                    # Frontend exists but not flagged for update
                    logger.warning(f"Frontend '{frontend_data['name']}' exists but not marked for update, skipping")
                    continue
                
                else:
                    # CREATE MODE: Insert new frontend
                    # CRITICAL: Convert ssl_certificate_ids to JSON for database
                    ssl_cert_ids_json = json.dumps(frontend_data.get("ssl_certificate_ids", []))
                    
                    frontend_id = await conn.fetchval("""
                        INSERT INTO frontends (
                            name, bind_address, bind_port, default_backend, mode,
                            ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port, 
                            ssl_cert_path, ssl_cert, ssl_verify,
                            timeout_client, timeout_http_request, maxconn,
                            request_headers, response_headers, tcp_request_rules, options,
                            rate_limit, compression, log_separate, monitor_uri,
                            cluster_id, acl_rules, use_backend_rules, redirect_rules, updated_at
                        ) 
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, CURRENT_TIMESTAMP) 
                        RETURNING id
                    """, 
                        frontend_data["name"],
                        frontend_data.get("bind_address", "*"),
                        frontend_data["bind_port"],
                        frontend_data.get("default_backend"),
                        frontend_data.get("mode", "http"),
                        frontend_data.get("ssl_enabled", False),
                        frontend_data.get("ssl_certificate_id"),  # Legacy single SSL ID (backward compat)
                        ssl_cert_ids_json,  # ssl_certificate_ids (JSONB) - multiple SSL support
                        frontend_data.get("ssl_port"),
                        frontend_data.get("ssl_cert_path"),
                        frontend_data.get("ssl_cert"),
                        frontend_data.get("ssl_verify", "optional"),
                        frontend_data.get("timeout_client"),
                        frontend_data.get("timeout_http_request"),
                        frontend_data.get("maxconn"),
                        frontend_data.get("request_headers"),
                        frontend_data.get("response_headers"),
                        frontend_data.get("tcp_request_rules"),
                        frontend_data.get("options"),
                        frontend_data.get("rate_limit"),
                        frontend_data.get("compression", False),
                        frontend_data.get("log_separate", False),
                        frontend_data.get("monitor_uri"),
                        request.cluster_id,
                        json.dumps(frontend_data.get("acl_rules", [])),  # acl_rules
                        json.dumps(frontend_data.get("use_backend_rules", [])),  # use_backend_rules
                        json.dumps([])   # redirect_rules
                    )
                    
                    created_entities["frontends"].append({
                        "id": frontend_id,
                        "name": frontend_data["name"]
                    })
                    
                    # PHASE 4: Create snapshot for CREATE operation (for rollback = deletion)
                    snapshot = await save_entity_snapshot(
                        conn=conn,
                        entity_type="frontend",
                        entity_id=frontend_id,
                        old_values={},  # No old values for CREATE
                        operation="CREATE"
                    )
                    if snapshot:
                        bulk_snapshots.append(snapshot)
            
            # Generate config version for the cluster
            config_content = await generate_haproxy_config_for_cluster(request.cluster_id)
            config_hash = hashlib.sha256(config_content.encode()).hexdigest()
            version_name = f"bulk-import-{int(time.time())}"
            
            # PHASE 4: Get pre-apply snapshot for diff viewer
            old_config = await conn.fetchval("""
                SELECT config_content FROM config_versions 
                WHERE cluster_id = $1 AND status = 'APPLIED' AND is_active = TRUE
                ORDER BY created_at DESC LIMIT 1
            """, request.cluster_id)
            
            # PHASE 4: Create metadata with bulk snapshots
            metadata = {
                "pre_apply_snapshot": old_config or "",  # For diff viewer
                "bulk_snapshots": bulk_snapshots,  # For bulk rollback
                "operation": "BULK_IMPORT",
                "entity_count": len(bulk_snapshots)
            }
            
            # Create PENDING config version with metadata
            config_version_id = await conn.fetchval("""
                INSERT INTO config_versions 
                (cluster_id, version_name, config_content, checksum, created_by, is_active, status, metadata)
                VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING', $6)
                RETURNING id
            """, request.cluster_id, version_name, config_content, config_hash, current_user['id'],
                 json.dumps(metadata) if metadata else None)
            
            # CRITICAL: Mark ALL affected entities as PENDING (both created AND updated)
            # This ensures Apply Management shows all changes
            all_backend_ids = []
            if created_entities["backends"]:
                all_backend_ids.extend([b["id"] for b in created_entities["backends"]])
            if updated_entities["backends"]:
                all_backend_ids.extend([b["id"] for b in updated_entities["backends"]])
            
            if all_backend_ids:
                await conn.execute("""
                    UPDATE backends SET last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP
                    WHERE id = ANY($1)
                """, all_backend_ids)
                logger.info(f"Marked {len(all_backend_ids)} backends as PENDING")
            
            all_frontend_ids = []
            if created_entities["frontends"]:
                all_frontend_ids.extend([f["id"] for f in created_entities["frontends"]])
            if updated_entities["frontends"]:
                all_frontend_ids.extend([f["id"] for f in updated_entities["frontends"]])
            
            if all_frontend_ids:
                await conn.execute("""
                    UPDATE frontends SET last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP
                    WHERE id = ANY($1)
                """, all_frontend_ids)
                logger.info(f"Marked {len(all_frontend_ids)} frontends as PENDING")
            
            # Mark all created/updated servers as PENDING
            if created_entities["servers"]:
                server_ids = [s["id"] for s in created_entities["servers"]]
                try:
                    await conn.execute("""
                        UPDATE backend_servers SET last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP
                        WHERE id = ANY($1)
                    """, server_ids)
                    logger.info(f"Marked {len(server_ids)} servers as PENDING")
                except Exception as server_status_error:
                    # Column might not exist in older database versions
                    logger.warning(f"Could not mark servers as PENDING (column may not exist): {server_status_error}")
            
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
            created_servers=len(created_entities["servers"]),
            updated_frontends=len(updated_entities["frontends"]),
            updated_backends=len(updated_entities["backends"])
        )
        
        # Prepare user-friendly message with UPSERT details
        message_parts = []
        
        # Created entities
        created_count = len(created_entities["frontends"]) + len(created_entities["backends"]) + len(created_entities["servers"])
        if created_count > 0:
            message_parts.append(
                f"Created: {len(created_entities['frontends'])} frontends, "
                f"{len(created_entities['backends'])} backends, "
                f"{len(created_entities['servers'])} servers"
            )
        
        # Updated entities
        updated_count = len(updated_entities["frontends"]) + len(updated_entities["backends"])
        if updated_count > 0:
            message_parts.append(
                f"Updated: {len(updated_entities['frontends'])} frontends, "
                f"{len(updated_entities['backends'])} backends"
            )
        
        # Reactivated entities (were deleted)
        reactivated = []
        for fe in updated_entities["frontends"]:
            if fe.get("was_inactive"):
                reactivated.append(f"frontend '{fe['name']}'")
        for be in updated_entities["backends"]:
            if be.get("was_inactive"):
                reactivated.append(f"backend '{be['name']}'")
        
        if reactivated:
            message_parts.append(f"Reactivated: {', '.join(reactivated[:3])}")
            if len(reactivated) > 3:
                message_parts.append(f"... and {len(reactivated) - 3} more")
        
        message = ". ".join(message_parts) + ". Please apply changes to activate."
        
        return {
            "success": True,
            "message": message,
            "created": created_entities,
            "updated": updated_entities,
            "summary": {
                "frontends": len(created_entities["frontends"]),
                "backends": len(created_entities["backends"]),
                "servers": len(created_entities["servers"]),
                "updated_frontends": len(updated_entities["frontends"]),
                "updated_backends": len(updated_entities["backends"])
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