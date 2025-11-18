"""
JSON Sanitizer Middleware
Fixes common JSON syntax errors from agent heartbeats before FastAPI processes them
"""

import re
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("haproxy_openmanager.json_sanitizer")


class JSONSanitizerMiddleware(BaseHTTPMiddleware):
    """
    Middleware to sanitize malformed JSON from agent heartbeats.
    
    Fixes common issues:
    - Empty values before commas: "field": , -> "field": null,
    - Trailing commas: {field: value,} -> {field: value}
    """
    
    async def dispatch(self, request: Request, call_next):
        # Only process heartbeat endpoint
        if request.method == "POST" and "/api/agents/heartbeat" in request.url.path:
            try:
                # Read the raw body
                body = await request.body()
                
                if body:
                    try:
                        body_str = body.decode('utf-8')
                        original_body = body_str
                        sanitized = False
                        
                        # Fix 1: Empty values before comma/closing brace
                        # Pattern: "field": , or "field": } or "field": ]
                        pattern1 = r':\s*([,\}\]])'
                        if re.search(pattern1, body_str):
                            body_str = re.sub(pattern1, r': null\1', body_str)
                            sanitized = True
                            logger.info(f"JSON Sanitizer: Fixed empty values in heartbeat from {request.client.host}")
                        
                        # Fix 2: Trailing commas before closing braces/brackets
                        # Pattern: , } or , ]
                        pattern2 = r',(\s*[\}\]])'
                        if re.search(pattern2, body_str):
                            body_str = re.sub(pattern2, r'\1', body_str)
                            sanitized = True
                            logger.info(f"JSON Sanitizer: Fixed trailing commas in heartbeat from {request.client.host}")
                        
                        if sanitized:
                            # Log what was fixed (first 200 chars for security)
                            logger.debug(
                                f"JSON Sanitizer: Original (preview): {original_body[:200]}"
                            )
                            logger.debug(
                                f"JSON Sanitizer: Sanitized (preview): {body_str[:200]}"
                            )
                            
                            # Create new request with sanitized body
                            async def receive():
                                return {
                                    "type": "http.request",
                                    "body": body_str.encode('utf-8'),
                                }
                            
                            # Replace request receive
                            request._receive = receive
                    
                    except Exception as decode_error:
                        logger.warning(f"JSON Sanitizer: Could not decode body: {decode_error}")
            
            except Exception as e:
                logger.error(f"JSON Sanitizer: Error processing request: {e}")
        
        # Continue with request
        response = await call_next(request)
        return response

