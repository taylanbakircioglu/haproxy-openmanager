"""
Rate Limiting Middleware for Production Security
Protects API endpoints from abuse and DDoS attacks
"""
import time
import logging
from typing import Callable
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from database.connection import redis_client

logger = logging.getLogger(__name__)

# Rate limiter instance using Redis backend  
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://redis:6379/0",
    default_limits=["1000/hour"],  # Default global limit
    retry_after=lambda name, t: int(t) + 10
)

# Custom rate limit exceeded handler
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """Custom handler for rate limit exceeded"""
    logger.warning(f"Rate limit exceeded for IP: {get_remote_address(request)}")
    
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "error": "Rate limit exceeded",
            "message": f"Too many requests. Limit: {exc.detail}",
            "retry_after": exc.retry_after,
            "ip": get_remote_address(request)
        }
    )

# Advanced rate limiting for sensitive endpoints
class AdvancedRateLimiter:
    """Advanced rate limiting with different limits for different endpoint types"""
    
    @staticmethod
    def get_auth_limiter():
        """Stricter limits for authentication endpoints"""
        return limiter.limit("10/minute")
    
    @staticmethod  
    def get_config_limiter():
        """Moderate limits for configuration changes"""
        return limiter.limit("100/hour")
    
    @staticmethod
    def get_read_limiter():
        """Higher limits for read-only endpoints"""
        return limiter.limit("500/hour")
    
    @staticmethod
    def get_apply_limiter():
        """Very strict limits for apply changes (critical operations)"""
        return limiter.limit("10/hour")

# IP-based suspicious activity detection
class SecurityMonitor:
    """Monitor and block suspicious IP addresses"""
    
    @staticmethod
    async def is_ip_blocked(ip: str) -> bool:
        """Check if IP is blocked"""
        try:
            return bool(redis_client.get(f"blocked_ip:{ip}"))
        except:
            return False
    
    @staticmethod
    async def block_ip(ip: str, duration: int = 3600):
        """Block IP address for specified duration (default 1 hour)"""
        try:
            redis_client.setex(f"blocked_ip:{ip}", duration, "blocked")
            logger.warning(f"IP {ip} blocked for {duration} seconds")
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
    
    @staticmethod
    async def track_failed_attempts(ip: str) -> int:
        """Track failed authentication attempts"""
        try:
            key = f"failed_attempts:{ip}"
            count = redis_client.incr(key)
            if count == 1:
                redis_client.expire(key, 900)  # 15 minutes
            
            # Auto-block after 5 failed attempts
            if count >= 5:
                await SecurityMonitor.block_ip(ip, 3600)  # Block for 1 hour
                logger.warning(f"IP {ip} auto-blocked after {count} failed attempts")
                
            return count
        except Exception as e:
            logger.error(f"Failed to track attempts for IP {ip}: {e}")
            return 0

# Middleware for IP blocking
async def ip_blocking_middleware(request: Request, call_next: Callable):
    """Middleware to check for blocked IPs"""
    client_ip = get_remote_address(request)
    
    if await SecurityMonitor.is_ip_blocked(client_ip):
        logger.warning(f"Blocked IP {client_ip} attempted access")
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "IP blocked",
                "message": "Your IP address has been temporarily blocked due to suspicious activity",
                "ip": client_ip
            }
        )
    
    return await call_next(request)