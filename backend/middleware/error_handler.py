"""
Production-Ready Error Handling Middleware
Provides global exception handling, request/response logging, and error tracking
"""

import time
import logging
import traceback
from typing import Callable, Any
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from utils.logging_config import (
    get_correlation_id, correlation_id_context, get_error_tracker,
    log_api_request, log_api_response, log_with_correlation
)

logger = logging.getLogger("haproxy_openmanager.error_handler")

class GlobalExceptionHandler:
    """Global exception handler for comprehensive error management"""
    
    @staticmethod
    def create_error_response(
        status_code: int, 
        message: str, 
        error_type: str = None,
        correlation_id: str = None,
        details: Any = None
    ) -> JSONResponse:
        """Create standardized error response"""
        
        error_response = {
            "error": {
                "message": message,
                "type": error_type or "ApplicationError",
                "timestamp": time.time(),
                "correlation_id": correlation_id or get_correlation_id()
            }
        }
        
        if details and isinstance(details, dict):
            error_response["error"]["details"] = details
        
        return JSONResponse(
            status_code=status_code,
            content=error_response
        )
    
    @staticmethod
    async def handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
        """Handle FastAPI HTTP exceptions"""
        correlation_id = get_correlation_id()
        
        # Log HTTP exception with more detail for debugging
        log_level = "ERROR" if exc.status_code >= 500 else "WARNING"
        log_with_correlation(
            logger, log_level,
            f"HTTP Exception: {exc.status_code} - {exc.detail}",
            status_code=exc.status_code,
            path=str(request.url.path),
            method=request.method,
            client_ip=request.client.host if request.client else "unknown",
            correlation_id=correlation_id
        )
        
        # For 400 errors, also log at INFO level to ensure visibility
        if exc.status_code == 400:
            logger.info(f"🚫 CLIENT ERROR 400: {exc.detail} | Path: {request.url.path} | Method: {request.method} | IP: {request.client.host if request.client else 'unknown'}")
        
        return GlobalExceptionHandler.create_error_response(
            status_code=exc.status_code,
            message=exc.detail,
            error_type="HTTPException",
            correlation_id=correlation_id
        )
    
    @staticmethod
    async def handle_validation_error(request: Request, exc: Exception) -> JSONResponse:
        """Handle validation errors (Pydantic, FastAPI)"""
        correlation_id = get_correlation_id()
        
        # Extract validation details
        if hasattr(exc, 'errors'):
            validation_errors = exc.errors()
            error_details = {
                "validation_errors": [
                    {
                        "field": " -> ".join(str(loc) for loc in error.get("loc", [])),
                        "message": error.get("msg", ""),
                        "type": error.get("type", "")
                    }
                    for error in validation_errors
                ]
            }
        else:
            error_details = {"raw_error": str(exc)}
        
        # Log validation error
        log_with_correlation(
            logger, "WARNING",
            f"Validation error: {str(exc)}",
            path=str(request.url.path),
            method=request.method,
            client_ip=request.client.host if request.client else "unknown",
            validation_details=error_details
        )
        
        return GlobalExceptionHandler.create_error_response(
            status_code=422,
            message="Validation error in request data",
            error_type="ValidationError",
            correlation_id=correlation_id,
            details=error_details
        )
    
    @staticmethod
    async def handle_database_error(request: Request, exc: Exception) -> JSONResponse:
        """Handle database-related errors"""
        correlation_id = get_correlation_id()
        error_tracker = get_error_tracker()
        
        # Track database error
        error_tracker.track_error(exc, {
            "category": "database",
            "path": str(request.url.path),
            "method": request.method
        })
        
        # Log database error with full traceback
        log_with_correlation(
            logger, "ERROR",
            f"Database error: {str(exc)}",
            path=str(request.url.path),
            method=request.method,
            client_ip=request.client.host if request.client else "unknown",
            error_traceback=traceback.format_exc()
        )
        
        return GlobalExceptionHandler.create_error_response(
            status_code=500,
            message="Database operation failed",
            error_type="DatabaseError",
            correlation_id=correlation_id,
            details={"category": "database", "recoverable": True}
        )
    
    @staticmethod
    async def handle_generic_exception(request: Request, exc: Exception) -> JSONResponse:
        """Handle all other unhandled exceptions"""
        correlation_id = get_correlation_id()
        error_tracker = get_error_tracker()
        
        # Track generic error
        error_tracker.track_error(exc, {
            "category": "application",
            "path": str(request.url.path),
            "method": request.method
        })
        
        # Log generic error with full context
        log_with_correlation(
            logger, "ERROR",
            f"Unhandled exception: {str(exc)}",
            path=str(request.url.path),
            method=request.method,
            client_ip=request.client.host if request.client else "unknown",
            error_type=type(exc).__name__,
            error_traceback=traceback.format_exc()
        )
        
        return GlobalExceptionHandler.create_error_response(
            status_code=500,
            message="Internal server error",
            error_type=type(exc).__name__,
            correlation_id=correlation_id,
            details={"category": "application", "recoverable": False}
        )

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for comprehensive request/response logging and error handling"""
    
    def __init__(self, app: ASGIApp, exclude_paths: list = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or ["/api/health/", "/docs", "/redoc", "/openapi.json"]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip logging for excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)
        
        # Generate correlation ID for this request
        correlation_id = get_correlation_id()
        correlation_id_context.set(correlation_id)
        
        # Start timing
        start_time = time.time()
        
        # Extract client information
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Log incoming request
        log_api_request(
            logger,
            method=request.method,
            path=str(request.url.path),
            client_ip=client_ip,
            user_agent=user_agent,
            query_params=dict(request.query_params) if request.query_params else None
        )
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration_ms = round((time.time() - start_time) * 1000, 2)
            
            # Log successful response
            log_api_response(
                logger,
                method=request.method,
                path=str(request.url.path),
                status_code=response.status_code,
                duration_ms=duration_ms,
                client_ip=client_ip
            )
            
            # Add correlation ID to response headers
            response.headers["X-Correlation-ID"] = correlation_id
            
            return response
            
        except HTTPException as exc:
            # Handle HTTP exceptions
            duration_ms = round((time.time() - start_time) * 1000, 2)
            response = await GlobalExceptionHandler.handle_http_exception(request, exc)
            response.headers["X-Correlation-ID"] = correlation_id
            
            log_api_response(
                logger,
                method=request.method,
                path=str(request.url.path),
                status_code=exc.status_code,
                duration_ms=duration_ms,
                client_ip=client_ip
            )
            
            return response
            
        except Exception as exc:
            # Handle all other exceptions
            duration_ms = round((time.time() - start_time) * 1000, 2)
            
            # Categorize exception type
            if "database" in str(exc).lower() or "connection" in str(exc).lower():
                response = await GlobalExceptionHandler.handle_database_error(request, exc)
            elif hasattr(exc, 'errors'):  # Validation errors
                response = await GlobalExceptionHandler.handle_validation_error(request, exc)
            else:
                response = await GlobalExceptionHandler.handle_generic_exception(request, exc)
                
            response.headers["X-Correlation-ID"] = correlation_id
            
            log_api_response(
                logger,
                method=request.method,
                path=str(request.url.path),
                status_code=response.status_code,
                duration_ms=duration_ms,
                client_ip=client_ip,
                error=True
            )
            
            return response

class PerformanceMonitoringMiddleware(BaseHTTPMiddleware):
    """Middleware for performance monitoring and slow request detection"""
    
    def __init__(self, app: ASGIApp, slow_request_threshold_ms: float = 1000):
        super().__init__(app)
        self.slow_request_threshold_ms = slow_request_threshold_ms
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        response = await call_next(request)
        
        duration_ms = round((time.time() - start_time) * 1000, 2)
        
        # Log slow requests
        if duration_ms > self.slow_request_threshold_ms:
            log_with_correlation(
                logger, "WARNING",
                f"Slow request detected: {request.method} {request.url.path}",
                method=request.method,
                path=str(request.url.path),
                duration_ms=duration_ms,
                threshold_ms=self.slow_request_threshold_ms,
                client_ip=request.client.host if request.client else "unknown"
            )
        
        # Add performance headers
        response.headers["X-Response-Time"] = f"{duration_ms}ms"
        
        return response

# Error statistics endpoint data
_error_stats = {"requests": 0, "errors": 0, "error_types": {}}

def get_error_statistics() -> dict:
    """Get current error statistics"""
    global _error_stats
    error_tracker = get_error_tracker()
    
    return {
        "total_requests": _error_stats["requests"],
        "total_errors": _error_stats["errors"],
        "error_rate": round(_error_stats["errors"] / max(_error_stats["requests"], 1) * 100, 2),
        "error_types": error_tracker.get_error_summary(),
        "timestamp": time.time()
    }

def increment_request_stats(is_error: bool = False):
    """Increment request statistics"""
    global _error_stats
    _error_stats["requests"] += 1
    if is_error:
        _error_stats["errors"] += 1