"""
HAProxy Validation Error Parser
Parses HAProxy validation errors and provides structured information
for UI display and quick fix suggestions.
"""

import re
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger("haproxy_openmanager.error_parser")


class ErrorType(Enum):
    """Known HAProxy error types"""
    UNKNOWN_BACKEND = "unknown_backend"
    UNKNOWN_FRONTEND = "unknown_frontend"
    DUPLICATE_NAME = "duplicate_name"
    MODE_MISMATCH = "mode_mismatch"
    INVALID_KEYWORD = "invalid_keyword"
    SYNTAX_ERROR = "syntax_error"
    MISSING_SERVER = "missing_server"
    ACL_ERROR = "acl_error"
    BIND_ERROR = "bind_error"
    UNKNOWN = "unknown"


# Error type to user-friendly display name mapping
ERROR_TYPE_DISPLAY = {
    ErrorType.UNKNOWN_BACKEND: "Unknown Backend Reference",
    ErrorType.UNKNOWN_FRONTEND: "Unknown Frontend Reference",
    ErrorType.DUPLICATE_NAME: "Duplicate Proxy Name",
    ErrorType.MODE_MISMATCH: "Mode Mismatch",
    ErrorType.INVALID_KEYWORD: "Invalid Keyword for Mode",
    ErrorType.SYNTAX_ERROR: "Syntax Error",
    ErrorType.MISSING_SERVER: "Missing Server Definition",
    ErrorType.ACL_ERROR: "ACL Definition Error",
    ErrorType.BIND_ERROR: "Bind/Port Error",
    ErrorType.UNKNOWN: "Configuration Error",
}

# Error type to field hint mapping
ERROR_TYPE_FIELD_HINTS = {
    ErrorType.UNKNOWN_BACKEND: ["use_backend_rules", "default_backend"],
    ErrorType.UNKNOWN_FRONTEND: ["use_backend_rules"],
    ErrorType.DUPLICATE_NAME: ["name"],
    ErrorType.MODE_MISMATCH: ["mode"],
    ErrorType.INVALID_KEYWORD: ["options", "acl_rules", "use_backend_rules"],
    ErrorType.SYNTAX_ERROR: ["options", "acl_rules"],
    ErrorType.MISSING_SERVER: ["servers"],
    ErrorType.ACL_ERROR: ["acl_rules"],
    ErrorType.BIND_ERROR: ["bind_address", "bind_port"],
}

# Suggestion templates for each error type
SUGGESTION_TEMPLATES = {
    ErrorType.UNKNOWN_BACKEND: "Backend '{related_entity}' not found. Create this backend or fix the use_backend/default_backend rules in frontend '{entity_name}'.",
    ErrorType.UNKNOWN_FRONTEND: "Frontend '{related_entity}' not found. Create this frontend or fix the reference.",
    ErrorType.DUPLICATE_NAME: "Name '{entity_name}' is already in use (possibly by agent's local listen block). Choose a different name.",
    ErrorType.MODE_MISMATCH: "Frontend '{entity_name}' mode ({mode}) is incompatible with the backend. Change the frontend or backend mode.",
    ErrorType.INVALID_KEYWORD: "Keyword '{keyword}' is invalid in {mode} mode. Use http-request for HTTP mode, tcp-request for TCP mode.",
    ErrorType.SYNTAX_ERROR: "Syntax error detected. Check the affected line.",
    ErrorType.MISSING_SERVER: "Backend '{entity_name}' must have at least one server defined.",
    ErrorType.ACL_ERROR: "ACL definition error. Correct format: 'acl name condition value'",
    ErrorType.BIND_ERROR: "Port {port} is already in use or inaccessible. Try a different port.",
    ErrorType.UNKNOWN: "Please review the raw error message and check the related entity.",
}


@dataclass
class ParsedError:
    """Structured representation of a parsed HAProxy error"""
    # Parse status
    parse_success: bool = False
    parse_confidence: int = 0
    
    # Raw message (always present)
    raw_message: str = ""
    raw_message_truncated: bool = False
    
    # Parsed fields (nullable)
    line_number: Optional[int] = None
    error_type: str = "unknown"
    error_type_display: str = "Configuration Error"
    entity_type: Optional[str] = None  # "frontend", "backend", "server"
    entity_name: Optional[str] = None
    related_entity: Optional[str] = None
    field_hint: Optional[str] = None
    mode: Optional[str] = None
    keyword: Optional[str] = None
    port: Optional[int] = None
    
    # Suggestion
    suggestion: str = "Lütfen ham hata mesajını inceleyin ve ilgili entity'yi kontrol edin."
    suggestion_type: str = "generic"  # "specific", "generic", "none"
    
    # Quick fix
    quick_fix_available: bool = False
    quick_fix_url: Optional[str] = None
    
    # Multiple errors
    has_multiple_errors: bool = False
    additional_errors_count: int = 0
    additional_errors_raw: Optional[str] = None
    
    # Entity verification (set later by entity matcher)
    entity_id: Optional[int] = None
    entity_verified: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class HAProxyErrorParser:
    """
    Parses HAProxy validation error messages and extracts structured information.
    
    Key design principle: ALWAYS return a valid result, never raise exceptions.
    Parse is a "bonus" - the raw message is always the primary value.
    """
    
    # Regex patterns for parsing HAProxy errors
    PATTERNS = {
        # Line number pattern: parsing [/path/file.cfg:45]
        'line_number': re.compile(r'\[.*?:(\d+)\]'),
        
        # Unknown backend: references unknown backend 'name' in frontend 'name'
        'unknown_backend': re.compile(
            r"references unknown backend '([^']+)'.*?(?:in (?:frontend|backend) '([^']+)')?",
            re.IGNORECASE
        ),
        
        # Duplicate name: has the same name as a previously declared 'listen' block
        'duplicate_name': re.compile(
            r"(?:frontend|backend|listen) (?:section )?'([^']+)' has the same name",
            re.IGNORECASE
        ),
        
        # Mode mismatch / invalid keyword: unexpected keyword 'tcp-request' in 'http' mode
        'invalid_keyword': re.compile(
            r"unexpected keyword '([^']+)'.*?'(http|tcp)' mode.*?(?:frontend|backend) '([^']+)'",
            re.IGNORECASE
        ),
        
        # ACL error: acl 'name' involves some response-only criteria
        'acl_error': re.compile(
            r"acl '([^']+)'.*?(?:frontend|backend) '([^']+)'",
            re.IGNORECASE
        ),
        
        # Bind error: cannot bind socket
        'bind_error': re.compile(
            r"cannot bind (?:socket|to) .*?:(\d+)",
            re.IGNORECASE
        ),
        
        # General frontend/backend name extraction
        'entity_name': re.compile(
            r"(?:in |section )(?:frontend|backend) '([^']+)'",
            re.IGNORECASE
        ),
        
        # Frontend keyword in error
        'frontend_ref': re.compile(
            r"frontend '([^']+)'",
            re.IGNORECASE
        ),
        
        # Backend keyword in error
        'backend_ref': re.compile(
            r"backend '([^']+)'",
            re.IGNORECASE
        ),
        
        # Multiple errors detection
        'alert_count': re.compile(r'\[ALERT\]', re.IGNORECASE),
    }
    
    # Maximum message length before truncation
    MAX_MESSAGE_LENGTH = 10000
    
    def __init__(self):
        pass
    
    def parse(self, error_message: str) -> ParsedError:
        """
        Parse a HAProxy validation error message.
        
        ALWAYS returns a valid ParsedError, never raises exceptions.
        If parsing fails, returns a result with parse_success=False but
        the raw message is always preserved.
        
        Args:
            error_message: Raw HAProxy validation error output
            
        Returns:
            ParsedError with structured information
        """
        result = ParsedError()
        
        # Handle empty/null message
        if not error_message or not error_message.strip():
            result.raw_message = ""
            result.suggestion = "Hata detayı alınamadı. Agent loglarını kontrol edin."
            result.suggestion_type = "none"
            return result
        
        # Store raw message (with truncation if needed)
        if len(error_message) > self.MAX_MESSAGE_LENGTH:
            result.raw_message = error_message[:self.MAX_MESSAGE_LENGTH] + "\n... [truncated]"
            result.raw_message_truncated = True
        else:
            result.raw_message = error_message
        
        # Check for multiple errors
        alert_matches = self.PATTERNS['alert_count'].findall(error_message)
        if len(alert_matches) > 1:
            result.has_multiple_errors = True
            result.additional_errors_count = len(alert_matches) - 1
        
        try:
            # Extract line number
            line_match = self.PATTERNS['line_number'].search(error_message)
            if line_match:
                result.line_number = int(line_match.group(1))
            
            # Try to identify error type and extract details
            parsed = self._identify_error_type(error_message)
            
            result.error_type = parsed.get('error_type', ErrorType.UNKNOWN).value
            result.error_type_display = ERROR_TYPE_DISPLAY.get(
                parsed.get('error_type', ErrorType.UNKNOWN),
                "Configuration Error"
            )
            result.entity_type = parsed.get('entity_type')
            result.entity_name = parsed.get('entity_name')
            result.related_entity = parsed.get('related_entity')
            result.mode = parsed.get('mode')
            result.keyword = parsed.get('keyword')
            result.port = parsed.get('port')
            
            # Set field hint based on error type
            error_type_enum = parsed.get('error_type', ErrorType.UNKNOWN)
            field_hints = ERROR_TYPE_FIELD_HINTS.get(error_type_enum, [])
            if field_hints:
                result.field_hint = field_hints[0]
            
            # Generate suggestion
            result.suggestion = self._generate_suggestion(result, parsed)
            result.suggestion_type = "specific" if error_type_enum != ErrorType.UNKNOWN else "generic"
            
            # Calculate confidence score
            result.parse_confidence = self._calculate_confidence(result)
            result.parse_success = result.parse_confidence >= 30
            
            # Quick fix is available if we have entity info
            result.quick_fix_available = bool(result.entity_name and result.entity_type)
            
            logger.info(f"Parsed HAProxy error: type={result.error_type}, entity={result.entity_name}, confidence={result.parse_confidence}")
            
        except Exception as e:
            # Parse failed - log but don't raise
            logger.warning(f"HAProxy error parse failed: {e}")
            # result already has safe defaults
        
        return result
    
    def _identify_error_type(self, message: str) -> Dict[str, Any]:
        """
        Identify the error type and extract relevant details.
        
        Returns dict with:
            - error_type: ErrorType enum
            - entity_type: "frontend" or "backend"
            - entity_name: name of affected entity
            - related_entity: name of related entity (e.g., unknown backend name)
            - mode: http/tcp if relevant
            - keyword: problematic keyword if relevant
            - port: port number if relevant
        """
        result = {
            'error_type': ErrorType.UNKNOWN,
            'entity_type': None,
            'entity_name': None,
            'related_entity': None,
            'mode': None,
            'keyword': None,
            'port': None,
        }
        
        message_lower = message.lower()
        
        # Check for unknown backend
        if 'unknown backend' in message_lower or 'references unknown' in message_lower:
            match = self.PATTERNS['unknown_backend'].search(message)
            if match:
                result['error_type'] = ErrorType.UNKNOWN_BACKEND
                result['related_entity'] = match.group(1)  # The unknown backend
                result['entity_type'] = 'frontend'
                if match.group(2):
                    result['entity_name'] = match.group(2)  # The frontend
            else:
                result['error_type'] = ErrorType.UNKNOWN_BACKEND
            return result
        
        # Check for duplicate name
        if 'same name' in message_lower or 'already exists' in message_lower:
            match = self.PATTERNS['duplicate_name'].search(message)
            if match:
                result['error_type'] = ErrorType.DUPLICATE_NAME
                result['entity_name'] = match.group(1)
                # Determine entity type from message
                if 'frontend' in message_lower:
                    result['entity_type'] = 'frontend'
                elif 'backend' in message_lower:
                    result['entity_type'] = 'backend'
            else:
                result['error_type'] = ErrorType.DUPLICATE_NAME
            return result
        
        # Check for invalid keyword (mode mismatch)
        if 'unexpected keyword' in message_lower:
            match = self.PATTERNS['invalid_keyword'].search(message)
            if match:
                result['error_type'] = ErrorType.INVALID_KEYWORD
                result['keyword'] = match.group(1)
                result['mode'] = match.group(2)
                result['entity_name'] = match.group(3)
                result['entity_type'] = 'frontend'  # Usually frontend
            else:
                result['error_type'] = ErrorType.INVALID_KEYWORD
            return result
        
        # Check for ACL error
        if 'acl' in message_lower and ('error' in message_lower or 'invalid' in message_lower or 'involves' in message_lower):
            match = self.PATTERNS['acl_error'].search(message)
            if match:
                result['error_type'] = ErrorType.ACL_ERROR
                result['related_entity'] = match.group(1)  # ACL name
                result['entity_name'] = match.group(2) if len(match.groups()) > 1 else None
                result['entity_type'] = 'frontend'
            else:
                result['error_type'] = ErrorType.ACL_ERROR
                # Try to extract entity name
                frontend_match = self.PATTERNS['frontend_ref'].search(message)
                if frontend_match:
                    result['entity_name'] = frontend_match.group(1)
                    result['entity_type'] = 'frontend'
            return result
        
        # Check for bind error
        if 'cannot bind' in message_lower or 'address already in use' in message_lower:
            match = self.PATTERNS['bind_error'].search(message)
            if match:
                result['error_type'] = ErrorType.BIND_ERROR
                result['port'] = int(match.group(1))
            else:
                result['error_type'] = ErrorType.BIND_ERROR
            # Try to extract frontend
            frontend_match = self.PATTERNS['frontend_ref'].search(message)
            if frontend_match:
                result['entity_name'] = frontend_match.group(1)
                result['entity_type'] = 'frontend'
            return result
        
        # Check for missing server
        if 'no server' in message_lower or 'missing server' in message_lower:
            result['error_type'] = ErrorType.MISSING_SERVER
            backend_match = self.PATTERNS['backend_ref'].search(message)
            if backend_match:
                result['entity_name'] = backend_match.group(1)
                result['entity_type'] = 'backend'
            return result
        
        # Generic error - try to extract any entity reference
        frontend_match = self.PATTERNS['frontend_ref'].search(message)
        backend_match = self.PATTERNS['backend_ref'].search(message)
        
        if frontend_match:
            result['entity_name'] = frontend_match.group(1)
            result['entity_type'] = 'frontend'
        elif backend_match:
            result['entity_name'] = backend_match.group(1)
            result['entity_type'] = 'backend'
        
        # Check for syntax keywords
        if 'syntax' in message_lower or 'parsing' in message_lower:
            result['error_type'] = ErrorType.SYNTAX_ERROR
        
        return result
    
    def _generate_suggestion(self, result: ParsedError, parsed: Dict[str, Any]) -> str:
        """Generate a helpful suggestion based on the error type"""
        error_type = parsed.get('error_type', ErrorType.UNKNOWN)
        template = SUGGESTION_TEMPLATES.get(error_type, SUGGESTION_TEMPLATES[ErrorType.UNKNOWN])
        
        try:
            return template.format(
                entity_name=result.entity_name or 'unknown',
                related_entity=result.related_entity or 'unknown',
                mode=result.mode or 'unknown',
                keyword=result.keyword or 'unknown',
                port=result.port or 'unknown',
            )
        except KeyError:
            return SUGGESTION_TEMPLATES[ErrorType.UNKNOWN]
    
    def _calculate_confidence(self, result: ParsedError) -> int:
        """
        Calculate confidence score (0-100) based on parsed information.
        
        Scoring:
            - Line number found: +30
            - Entity name found: +25
            - Error type identified: +20
            - Field hint available: +10
            - Related entity found: +10
            - Mode/keyword extracted: +5
        """
        score = 0
        
        if result.line_number:
            score += 30
        
        if result.entity_name:
            score += 25
        
        if result.error_type != "unknown":
            score += 20
        
        if result.field_hint:
            score += 10
        
        if result.related_entity:
            score += 10
        
        if result.mode or result.keyword:
            score += 5
        
        return min(score, 100)


# Singleton instance for convenience
_parser_instance = None

def get_parser() -> HAProxyErrorParser:
    """Get singleton parser instance"""
    global _parser_instance
    if _parser_instance is None:
        _parser_instance = HAProxyErrorParser()
    return _parser_instance


def parse_haproxy_error(error_message: str) -> Dict[str, Any]:
    """
    Convenience function to parse HAProxy error.
    
    Args:
        error_message: Raw HAProxy validation error output
        
    Returns:
        Dictionary with parsed error information
    """
    parser = get_parser()
    result = parser.parse(error_message)
    return result.to_dict()


async def find_affected_entity(
    parsed_error: Dict[str, Any],
    cluster_id: int,
    conn
) -> Dict[str, Any]:
    """
    Find the affected entity in the database based on parsed error.
    
    Args:
        parsed_error: Dictionary from parse_haproxy_error()
        cluster_id: Cluster ID to search in
        conn: Database connection
        
    Returns:
        Dictionary with entity information:
            - entity_id: Database ID
            - entity_type: "frontend" or "backend"
            - entity_name: Entity name
            - entity_verified: True if found in DB
            - edit_url: URL to edit the entity
            - field_to_fix: Field that needs fixing
            - current_value: Current value of the field (if applicable)
    """
    result = {
        'entity_id': None,
        'entity_type': parsed_error.get('entity_type'),
        'entity_name': parsed_error.get('entity_name'),
        'entity_verified': False,
        'edit_url': None,
        'field_to_fix': parsed_error.get('field_hint'),
        'current_value': None,
    }
    
    entity_name = parsed_error.get('entity_name')
    entity_type = parsed_error.get('entity_type')
    
    if not entity_name or not entity_type:
        return result
    
    try:
        if entity_type == 'frontend':
            # Find frontend
            frontend = await conn.fetchrow(
                """
                SELECT id, name, default_backend, use_backend_rules, acl_rules, mode, 
                       bind_address, bind_port, options
                FROM frontends
                WHERE cluster_id = $1 AND LOWER(name) = LOWER($2)
                """,
                cluster_id, entity_name
            )
            
            if frontend:
                result['entity_id'] = frontend['id']
                result['entity_verified'] = True
                result['edit_url'] = f"/frontends?edit={frontend['id']}"
                
                # Get current value of problematic field
                field_hint = parsed_error.get('field_hint')
                if field_hint and field_hint in frontend.keys():
                    result['current_value'] = frontend[field_hint]
                    result['edit_url'] += f"&highlight={field_hint}"
        
        elif entity_type == 'backend':
            # Find backend
            backend = await conn.fetchrow(
                """
                SELECT id, name, mode, options
                FROM backends
                WHERE cluster_id = $1 AND LOWER(name) = LOWER($2)
                """,
                cluster_id, entity_name
            )
            
            if backend:
                result['entity_id'] = backend['id']
                result['entity_verified'] = True
                result['edit_url'] = f"/backends?edit={backend['id']}"
                
                field_hint = parsed_error.get('field_hint')
                if field_hint and field_hint in backend.keys():
                    result['current_value'] = backend[field_hint]
                    result['edit_url'] += f"&highlight={field_hint}"
        
        logger.info(f"Entity lookup: type={entity_type}, name={entity_name}, verified={result['entity_verified']}")
        
    except Exception as e:
        logger.warning(f"Failed to find affected entity: {e}")
    
    return result
