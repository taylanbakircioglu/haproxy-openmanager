"""
Production-Ready Logging Configuration
Provides structured logging, correlation IDs, and comprehensive error tracking
"""

import logging
import sys
import json
import uuid
import time
from datetime import datetime
from typing import Optional, Dict, Any
from contextvars import ContextVar
from functools import wraps

# Context variable for correlation ID tracking across requests
correlation_id_context: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)

class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured JSON logging in production"""
    
    def format(self, record: logging.LogRecord) -> str:
        # Create base log structure
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add correlation ID if available
        correlation_id = correlation_id_context.get()
        if correlation_id:
            log_entry["correlation_id"] = correlation_id
        
        # Add process and thread info
        log_entry["process_id"] = record.process
        log_entry["thread_id"] = record.thread
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info)
            }
        
        # Add extra fields from record
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        
        # Add performance metrics if available
        if hasattr(record, 'duration_ms'):
            log_entry["duration_ms"] = record.duration_ms
        
        if hasattr(record, 'status_code'):
            log_entry["status_code"] = record.status_code
            
        if hasattr(record, 'method'):
            log_entry["http_method"] = record.method
            
        if hasattr(record, 'path'):
            log_entry["http_path"] = record.path
        
        if hasattr(record, 'client_ip'):
            log_entry["client_ip"] = record.client_ip
        
        return json.dumps(log_entry, ensure_ascii=False, separators=(',', ':'))

def setup_production_logging(log_level: str = "INFO"):
    """Setup production-ready structured logging"""
    
    # Create structured formatter
    formatter = StructuredFormatter()
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove default handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add structured console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Setup specific loggers with appropriate levels
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)  # Reduce uvicorn noise
    logging.getLogger("asyncpg").setLevel(logging.WARNING)  # Reduce database noise
    
    # Application loggers
    app_logger = logging.getLogger("haproxy_openmanager")
    app_logger.setLevel(getattr(logging, log_level.upper()))
    
    return app_logger

def get_correlation_id() -> str:
    """Get or create correlation ID for request tracking"""
    correlation_id = correlation_id_context.get()
    if not correlation_id:
        correlation_id = str(uuid.uuid4())[:8]  # Short UUID for logs
        correlation_id_context.set(correlation_id)
    return correlation_id

def log_with_correlation(logger: logging.Logger, level: str, message: str, **extra_fields):
    """Log message with correlation ID and extra fields"""
    correlation_id = get_correlation_id()
    
    # Create LogRecord with extra fields
    record = logger.makeRecord(
        logger.name, getattr(logging, level.upper()), 
        __file__, 0, message, (), None
    )
    
    # Add extra fields to record
    if extra_fields:
        record.extra_fields = extra_fields
    
    logger.handle(record)

class PerformanceLogger:
    """Context manager for performance logging"""
    
    def __init__(self, logger: logging.Logger, operation: str, **context):
        self.logger = logger
        self.operation = operation
        self.context = context
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        log_with_correlation(
            self.logger, "INFO", 
            f"Starting operation: {self.operation}",
            **self.context
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = round((time.time() - self.start_time) * 1000, 2)
        
        if exc_type:
            log_with_correlation(
                self.logger, "ERROR",
                f"Operation failed: {self.operation}",
                duration_ms=duration_ms,
                error_type=exc_type.__name__,
                error_message=str(exc_val),
                **self.context
            )
        else:
            log_with_correlation(
                self.logger, "INFO",
                f"Operation completed: {self.operation}",
                duration_ms=duration_ms,
                **self.context
            )

def log_function_performance(logger: logging.Logger):
    """Decorator for automatic function performance logging"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            operation = f"{func.__module__}.{func.__name__}"
            with PerformanceLogger(logger, operation, function=func.__name__):
                return await func(*args, **kwargs)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            operation = f"{func.__module__}.{func.__name__}"
            with PerformanceLogger(logger, operation, function=func.__name__):
                return func(*args, **kwargs)
        
        return async_wrapper if hasattr(func, '__code__') and func.__code__.co_flags & 0x80 else sync_wrapper
    
    return decorator

class ErrorTracker:
    """Track and categorize application errors"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.error_counts = {}
    
    def track_error(self, error: Exception, context: Dict[str, Any] = None):
        """Track error occurrence with context"""
        error_type = type(error).__name__
        error_message = str(error)
        
        # Increment error count
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        
        # Log structured error
        log_with_correlation(
            self.logger, "ERROR",
            f"Application error: {error_message}",
            error_type=error_type,
            error_count=self.error_counts[error_type],
            **(context or {})
        )
    
    def get_error_summary(self) -> Dict[str, int]:
        """Get error count summary"""
        return self.error_counts.copy()

# Global error tracker instance
_error_tracker = None

def get_error_tracker(logger: logging.Logger = None) -> ErrorTracker:
    """Get global error tracker instance"""
    global _error_tracker
    if _error_tracker is None:
        if logger is None:
            logger = logging.getLogger("haproxy_openmanager")
        _error_tracker = ErrorTracker(logger)
    return _error_tracker

# Utility functions for common logging patterns
def log_api_request(logger: logging.Logger, method: str, path: str, client_ip: str, **extra):
    """Log API request with structured data"""
    log_with_correlation(
        logger, "INFO",
        f"API Request: {method} {path}",
        method=method,
        path=path,
        client_ip=client_ip,
        **extra
    )

def log_api_response(logger: logging.Logger, method: str, path: str, status_code: int, duration_ms: float, **extra):
    """Log API response with performance metrics"""
    level = "ERROR" if status_code >= 500 else "WARNING" if status_code >= 400 else "INFO"
    
    log_with_correlation(
        logger, level,
        f"API Response: {method} {path} - {status_code}",
        method=method,
        path=path,
        status_code=status_code,
        duration_ms=duration_ms,
        **extra
    )

def log_database_operation(logger: logging.Logger, operation: str, table: str, duration_ms: float, **extra):
    """Log database operation with performance metrics"""
    log_with_correlation(
        logger, "DEBUG",
        f"Database operation: {operation} on {table}",
        db_operation=operation,
        db_table=table,
        duration_ms=duration_ms,
        **extra
    )

def log_agent_interaction(logger: logging.Logger, agent_id: str, operation: str, result: str, **extra):
    """Log agent interaction with structured data"""
    log_with_correlation(
        logger, "INFO",
        f"Agent interaction: {operation} for agent {agent_id} - {result}",
        agent_id=agent_id,
        agent_operation=operation,
        result=result,
        **extra
    )