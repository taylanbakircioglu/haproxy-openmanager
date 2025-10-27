"""
Production-Ready HAProxy Configuration Validation
Provides comprehensive syntax checking, validation, and optimization suggestions
"""

import re
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("haproxy_openmanager.config_validator")

class ValidationLevel(Enum):
    """Validation severity levels"""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    SUGGESTION = "suggestion"

@dataclass
class ValidationResult:
    """Single validation result"""
    level: ValidationLevel
    message: str
    line_number: Optional[int] = None
    section: Optional[str] = None
    directive: Optional[str] = None
    suggestion: Optional[str] = None

@dataclass
class ConfigValidationReport:
    """Complete validation report"""
    is_valid: bool
    error_count: int
    warning_count: int
    suggestion_count: int
    results: List[ValidationResult]
    syntax_score: float  # 0-100 score
    performance_score: float  # 0-100 score
    security_score: float  # 0-100 score

class HAProxyConfigValidator:
    """Comprehensive HAProxy configuration validator"""
    
    def __init__(self):
        self.results = []
        self.sections = {}
        self.current_section = None
        self.line_number = 0
        
        # Valid directives by section
        self.valid_directives = {
            'global': {
                'daemon', 'master-worker', 'nbproc', 'nbthread', 'cpu-map',
                'stats', 'user', 'group', 'chroot', 'pidfile', 'log', 'log-tag',
                'maxconn', 'ulimit-n', 'spread-checks', 'tune.ssl.default-dh-param',
                'ssl-default-bind-options', 'ssl-default-bind-ciphers', 'ca-base',
                'crt-base', 'tune.bufsize', 'tune.maxrewrite', 'tune.rcvbuf.client',
                'tune.rcvbuf.server', 'tune.sndbuf.client', 'tune.sndbuf.server'
            },
            'defaults': {
                'mode', 'balance', 'option', 'timeout', 'retries', 'maxconn',
                'http-request', 'http-response', 'errorfile', 'default-server',
                'log', 'compression'
            },
            'frontend': {
                'bind', 'mode', 'option', 'timeout', 'maxconn', 'default_backend',
                'use_backend', 'acl', 'http-request', 'http-response', 'redirect',
                'capture', 'monitor-uri', 'log', 'compression', 'rate-limit'
            },
            'backend': {
                'mode', 'balance', 'option', 'timeout', 'server', 'http-request',
                'http-response', 'stick-table', 'stick', 'hash-type', 'default-server',
                'log', 'compression', 'http-check'
            },
            'listen': {
                'bind', 'mode', 'balance', 'option', 'timeout', 'server', 'maxconn',
                'http-request', 'http-response', 'acl', 'default-server', 'log'
            }
        }
    
    def validate_config(self, config_content: str) -> ConfigValidationReport:
        """Validate complete HAProxy configuration"""
        self.results = []
        self.sections = {}
        self.current_section = None
        self.line_number = 0
        
        lines = config_content.split('\n')
        
        # Parse and validate each line
        for line_num, line in enumerate(lines, 1):
            self.line_number = line_num
            self._validate_line(line.strip())
        
        # Perform section-level validations
        self._validate_sections()
        
        # Calculate scores
        error_count = len([r for r in self.results if r.level == ValidationLevel.ERROR])
        warning_count = len([r for r in self.results if r.level == ValidationLevel.WARNING])
        suggestion_count = len([r for r in self.results if r.level == ValidationLevel.SUGGESTION])
        
        syntax_score = self._calculate_syntax_score()
        performance_score = self._calculate_performance_score()
        security_score = self._calculate_security_score()
        
        return ConfigValidationReport(
            is_valid=error_count == 0,
            error_count=error_count,
            warning_count=warning_count, 
            suggestion_count=suggestion_count,
            results=self.results,
            syntax_score=syntax_score,
            performance_score=performance_score,
            security_score=security_score
        )
    
    def _validate_line(self, line: str):
        """Validate individual line"""
        if not line or line.startswith('#'):
            return
        
        # Check for section headers
        if self._is_section_header(line):
            self._validate_section_header(line)
            return
        
        # Skip empty lines
        if not line.strip():
            return
        
        # Validate directive
        if self.current_section:
            self._validate_directive(line)
    
    def _is_section_header(self, line: str) -> bool:
        """Check if line is a section header"""
        return bool(re.match(r'^(global|defaults|frontend|backend|listen)\s', line))
    
    def _validate_section_header(self, line: str):
        """Validate section header syntax"""
        parts = line.split()
        section_type = parts[0]
        
        if section_type in ['frontend', 'backend', 'listen']:
            if len(parts) < 2:
                self._add_result(
                    ValidationLevel.ERROR,
                    f"Section '{section_type}' requires a name",
                    suggestion=f"{section_type} my_{section_type}_name"
                )
                return
            
            section_name = parts[1]
            
            # Check name format
            if not re.match(r'^[a-zA-Z0-9_-]+$', section_name):
                self._add_result(
                    ValidationLevel.WARNING,
                    f"Section name '{section_name}' contains invalid characters",
                    suggestion="Use only letters, numbers, underscore and hyphen"
                )
        
        # Set current section for validation
        self.current_section = section_type
        if section_type not in self.sections:
            self.sections[section_type] = []
        
        if len(parts) > 1:
            self.sections[section_type].append(parts[1])
    
    def _validate_directive(self, line: str):
        """Validate directive within current section"""
        if not self.current_section:
            self._add_result(
                ValidationLevel.ERROR,
                "Directive found outside of any section",
                suggestion="Add directive inside a section (global, defaults, frontend, backend, or listen)"
            )
            return
        
        parts = line.split()
        if not parts:
            return
        
        directive = parts[0]
        
        # Check if directive is valid for current section
        valid_directives = self.valid_directives.get(self.current_section, set())
        
        if directive not in valid_directives:
            self._add_result(
                ValidationLevel.WARNING,
                f"Directive '{directive}' may not be valid in '{self.current_section}' section",
                directive=directive
            )
        
        # Validate specific directives
        self._validate_specific_directive(directive, parts[1:])
    
    def _validate_specific_directive(self, directive: str, args: List[str]):
        """Validate specific directive syntax and values"""
        
        if directive == 'bind':
            self._validate_bind_directive(args)
        elif directive == 'server':
            self._validate_server_directive(args)
        elif directive == 'timeout':
            self._validate_timeout_directive(args)
        elif directive == 'balance':
            self._validate_balance_directive(args)
        elif directive == 'mode':
            self._validate_mode_directive(args)
        elif directive == 'option':
            self._validate_option_directive(args)
        elif directive == 'maxconn':
            self._validate_maxconn_directive(args)
    
    def _validate_bind_directive(self, args: List[str]):
        """Validate bind directive"""
        if not args:
            self._add_result(
                ValidationLevel.ERROR,
                "bind directive requires address:port",
                directive="bind",
                suggestion="bind *:80 or bind 192.168.1.1:443"
            )
            return
        
        bind_addr = args[0]
        
        # Check format
        if ':' not in bind_addr:
            self._add_result(
                ValidationLevel.WARNING,
                "bind address should include port",
                directive="bind",
                suggestion=f"{bind_addr}:80"
            )
        
        # Check for SSL options
        if 'ssl' in args:
            if 'crt' not in ' '.join(args):
                self._add_result(
                    ValidationLevel.WARNING,
                    "SSL binding without certificate specified",
                    directive="bind",
                    suggestion="Add 'crt /path/to/certificate.pem'"
                )
    
    def _validate_server_directive(self, args: List[str]):
        """Validate server directive"""
        if len(args) < 2:
            self._add_result(
                ValidationLevel.ERROR,
                "server directive requires name and address",
                directive="server",
                suggestion="server web1 192.168.1.10:80 check"
            )
            return
        
        server_name = args[0]
        server_addr = args[1]
        
        # Check server name format
        if not re.match(r'^[a-zA-Z0-9_-]+$', server_name):
            self._add_result(
                ValidationLevel.WARNING,
                f"Server name '{server_name}' contains invalid characters",
                directive="server",
                suggestion="Use only letters, numbers, underscore and hyphen"
            )
        
        # Check address format
        if ':' not in server_addr:
            self._add_result(
                ValidationLevel.WARNING,
                "Server address should include port",
                directive="server",
                suggestion=f"{server_addr}:80"
            )
        
        # Recommend health checks
        if 'check' not in args:
            self._add_result(
                ValidationLevel.SUGGESTION,
                "Consider adding health check to server",
                directive="server",
                suggestion=f"server {server_name} {server_addr} check"
            )
    
    def _validate_timeout_directive(self, args: List[str]):
        """Validate timeout directive"""
        if len(args) < 2:
            self._add_result(
                ValidationLevel.ERROR,
                "timeout directive requires type and value",
                directive="timeout",
                suggestion="timeout connect 5s"
            )
            return
        
        timeout_type = args[0]
        timeout_value = args[1]
        
        # Check timeout type
        valid_timeout_types = {
            'client', 'server', 'connect', 'queue', 'tunnel', 'http-request',
            'http-keep-alive', 'check', 'tarpit'
        }
        
        if timeout_type not in valid_timeout_types:
            self._add_result(
                ValidationLevel.WARNING,
                f"Unknown timeout type '{timeout_type}'",
                directive="timeout"
            )
        
        # Validate timeout value format
        if not re.match(r'^\d+[smhd]?$', timeout_value):
            self._add_result(
                ValidationLevel.ERROR,
                f"Invalid timeout value '{timeout_value}'",
                directive="timeout",
                suggestion="Use format like '5s', '30000ms', '1m'"
            )
    
    def _validate_balance_directive(self, args: List[str]):
        """Validate balance directive"""
        if not args:
            self._add_result(
                ValidationLevel.ERROR,
                "balance directive requires algorithm",
                directive="balance",
                suggestion="balance roundrobin"
            )
            return
        
        algorithm = args[0]
        valid_algorithms = {
            'roundrobin', 'static-rr', 'leastconn', 'first', 'source', 'uri',
            'url_param', 'hdr', 'rdp-cookie'
        }
        
        if algorithm not in valid_algorithms:
            self._add_result(
                ValidationLevel.WARNING,
                f"Unknown balance algorithm '{algorithm}'",
                directive="balance",
                suggestion="Use roundrobin, leastconn, or source"
            )
    
    def _validate_mode_directive(self, args: List[str]):
        """Validate mode directive"""
        if not args:
            self._add_result(
                ValidationLevel.ERROR,
                "mode directive requires value",
                directive="mode",
                suggestion="mode http"
            )
            return
        
        mode = args[0]
        valid_modes = {'http', 'tcp', 'health'}
        
        if mode not in valid_modes:
            self._add_result(
                ValidationLevel.ERROR,
                f"Invalid mode '{mode}'",
                directive="mode",
                suggestion="Use 'http' or 'tcp'"
            )
    
    def _validate_option_directive(self, args: List[str]):
        """Validate option directive"""
        if not args:
            self._add_result(
                ValidationLevel.ERROR,
                "option directive requires value",
                directive="option"
            )
            return
        
        option = args[0]
        common_options = {
            'httplog', 'tcplog', 'dontlognull', 'log-health-checks',
            'httpchk', 'ssl-hello-chk', 'tcp-check', 'forwardfor',
            'httpclose', 'http-keep-alive', 'abortonclose'
        }
        
        if option not in common_options:
            self._add_result(
                ValidationLevel.INFO,
                f"Option '{option}' not in common options list",
                directive="option"
            )
    
    def _validate_maxconn_directive(self, args: List[str]):
        """Validate maxconn directive"""
        if not args:
            self._add_result(
                ValidationLevel.ERROR,
                "maxconn directive requires value",
                directive="maxconn",
                suggestion="maxconn 2000"
            )
            return
        
        try:
            value = int(args[0])
            if value <= 0:
                self._add_result(
                    ValidationLevel.ERROR,
                    "maxconn value must be positive",
                    directive="maxconn"
                )
            elif value > 65535:
                self._add_result(
                    ValidationLevel.WARNING,
                    "maxconn value seems very high, check system limits",
                    directive="maxconn"
                )
        except ValueError:
            self._add_result(
                ValidationLevel.ERROR,
                f"maxconn value must be a number",
                directive="maxconn"
            )
    
    def _validate_sections(self):
        """Validate section-level requirements"""
        
        # Check for required global settings
        if 'global' not in self.sections:
            self._add_result(
                ValidationLevel.WARNING,
                "Missing 'global' section - recommended for production",
                suggestion="Add global section with basic settings"
            )
        
        # Check for defaults section
        if 'defaults' not in self.sections:
            self._add_result(
                ValidationLevel.SUGGESTION,
                "Consider adding 'defaults' section for common settings",
                suggestion="Add defaults section to reduce configuration duplication"
            )
        
        # Check balance of frontends and backends
        frontend_count = len(self.sections.get('frontend', []))
        backend_count = len(self.sections.get('backend', []))
        
        if frontend_count > 0 and backend_count == 0:
            self._add_result(
                ValidationLevel.WARNING,
                "Frontends defined without backends",
                suggestion="Add backend sections for your frontends"
            )
    
    def _calculate_syntax_score(self) -> float:
        """Calculate syntax quality score (0-100)"""
        total_issues = len(self.results)
        error_weight = 10
        warning_weight = 5
        suggestion_weight = 1
        
        penalty = sum(
            error_weight if r.level == ValidationLevel.ERROR else
            warning_weight if r.level == ValidationLevel.WARNING else
            suggestion_weight if r.level == ValidationLevel.SUGGESTION else 1
            for r in self.results
        )
        
        # Base score calculation
        if total_issues == 0:
            return 100.0
        
        # Penalize based on severity
        score = max(0, 100 - penalty)
        return round(score, 1)
    
    def _calculate_performance_score(self) -> float:
        """Calculate performance optimization score (0-100)"""
        score = 75.0  # Base score
        
        # Check for performance-related configurations
        performance_indicators = {
            'has_timeouts': False,
            'has_compression': False,
            'has_health_checks': False,
            'has_keepalive': False,
            'proper_logging': False
        }
        
        config_text = ' '.join(r.message for r in self.results)
        
        if 'timeout' in config_text.lower():
            performance_indicators['has_timeouts'] = True
            score += 5
        
        if 'compression' in config_text.lower():
            performance_indicators['has_compression'] = True
            score += 5
        
        if 'check' in config_text.lower():
            performance_indicators['has_health_checks'] = True
            score += 10
        
        if 'keep-alive' in config_text.lower():
            performance_indicators['has_keepalive'] = True
            score += 5
        
        return min(100.0, round(score, 1))
    
    def _calculate_security_score(self) -> float:
        """Calculate security configuration score (0-100)"""
        score = 70.0  # Base score
        
        # Security indicators
        security_checks = {
            'ssl_configured': False,
            'secure_headers': False,
            'logging_enabled': False,
            'user_group_set': False
        }
        
        config_text = ' '.join(r.message for r in self.results)
        
        if 'ssl' in config_text.lower() or 'https' in config_text.lower():
            security_checks['ssl_configured'] = True
            score += 10
        
        if 'http-response set-header' in config_text.lower():
            security_checks['secure_headers'] = True
            score += 5
        
        if 'log' in config_text.lower():
            security_checks['logging_enabled'] = True
            score += 10
        
        if 'user' in config_text.lower() and 'group' in config_text.lower():
            security_checks['user_group_set'] = True
            score += 5
        
        return min(100.0, round(score, 1))
    
    def _add_result(self, level: ValidationLevel, message: str, directive: str = None, suggestion: str = None):
        """Add validation result"""
        result = ValidationResult(
            level=level,
            message=message,
            line_number=self.line_number,
            section=self.current_section,
            directive=directive,
            suggestion=suggestion
        )
        self.results.append(result)

def validate_haproxy_config(config_content: str) -> ConfigValidationReport:
    """Main function to validate HAProxy configuration"""
    validator = HAProxyConfigValidator()
    return validator.validate_config(config_content)

def get_validation_summary(report: ConfigValidationReport) -> Dict[str, Any]:
    """Get validation summary for API response"""
    return {
        "is_valid": report.is_valid,
        "overall_score": round((report.syntax_score + report.performance_score + report.security_score) / 3, 1),
        "scores": {
            "syntax": report.syntax_score,
            "performance": report.performance_score,
            "security": report.security_score
        },
        "issue_counts": {
            "errors": report.error_count,
            "warnings": report.warning_count,
            "suggestions": report.suggestion_count,
            "total": len(report.results)
        },
        "issues": [
            {
                "level": result.level.value,
                "message": result.message,
                "line": result.line_number,
                "section": result.section,
                "directive": result.directive,
                "suggestion": result.suggestion
            }
            for result in report.results
        ]
    }