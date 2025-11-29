"""
Framework Detection Module (NOVEL COMPONENT #1)

Automatically identifies the web framework of target applications:
- Django (Python)
- Flask (Python)
- Express (Node.js)
- PHP

Uses multiple detection methods:
1. HTTP Header Analysis
2. Error Page Fingerprinting
3. Response Behavior Testing
"""

import re
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


class Framework(Enum):
    """Supported web frameworks"""
    DJANGO = "Django"
    FLASK = "Flask"
    EXPRESS = "Express"
    PHP = "PHP"
    ASP_NET = "ASP.NET"
    UNKNOWN = "Unknown"


@dataclass
class FrameworkSignature:
    """Signature patterns for framework detection"""
    name: Framework
    header_patterns: List[Tuple[str, str]]  # (header_name, pattern)
    error_patterns: List[str]
    cookie_patterns: List[str]
    parameter_behavior: str  # 'first', 'last', 'array', 'concat'


# Framework signature database
FRAMEWORK_SIGNATURES = {
    Framework.DJANGO: FrameworkSignature(
        name=Framework.DJANGO,
        header_patterns=[
            ('Server', r'WSGIServer'),
            ('X-Frame-Options', r'DENY|SAMEORIGIN'),
            ('Content-Type', r'text/html; charset=utf-8'),
        ],
        error_patterns=[
            r'Django',
            r'DisallowedHost',
            r'CSRF verification failed',
            r'ImproperlyConfigured',
            r'OperationalError',
            r'TemplateDoesNotExist',
            r'Page not found \(404\)',
            r'csrfmiddlewaretoken',
        ],
        cookie_patterns=[
            r'csrftoken',
            r'sessionid',
            r'django',
        ],
        parameter_behavior='last'
    ),
    
    Framework.FLASK: FrameworkSignature(
        name=Framework.FLASK,
        header_patterns=[
            ('Server', r'Werkzeug'),
            ('Server', r'Flask'),
        ],
        error_patterns=[
            r'Werkzeug',
            r'werkzeug\.routing',
            r'jinja2',
            r'DebuggedApplication',
            r'flask\.app',
            r'The requested URL was not found',
        ],
        cookie_patterns=[
            r'session',
        ],
        parameter_behavior='first'
    ),
    
    Framework.EXPRESS: FrameworkSignature(
        name=Framework.EXPRESS,
        header_patterns=[
            ('X-Powered-By', r'Express'),
            ('Server', r'Express'),
        ],
        error_patterns=[
            r'Cannot GET',
            r'Cannot POST',
            r'express',
            r'node\.js',
            r'ReferenceError',
            r'TypeError.*undefined',
            r'ENOENT',
        ],
        cookie_patterns=[
            r'connect\.sid',
            r'express',
        ],
        parameter_behavior='array'
    ),
    
    Framework.PHP: FrameworkSignature(
        name=Framework.PHP,
        header_patterns=[
            ('X-Powered-By', r'PHP'),
            ('Server', r'Apache.*PHP'),
        ],
        error_patterns=[
            r'Parse error',
            r'Fatal error',
            r'Warning:',
            r'Notice:',
            r'<?php',
            r'\.php on line',
            r'Call Stack',
            r'PHPSESSID',
        ],
        cookie_patterns=[
            r'PHPSESSID',
            r'laravel_session',
        ],
        parameter_behavior='last'
    ),
    
    Framework.ASP_NET: FrameworkSignature(
        name=Framework.ASP_NET,
        header_patterns=[
            ('X-Powered-By', r'ASP\.NET'),
            ('X-AspNet-Version', r'.*'),
            ('Server', r'Microsoft-IIS'),
        ],
        error_patterns=[
            r'ASP\.NET',
            r'System\.Web',
            r'__VIEWSTATE',
            r'Server Error in',
            r'\.aspx',
        ],
        cookie_patterns=[
            r'ASP\.NET_SessionId',
            r'\.ASPXAUTH',
        ],
        parameter_behavior='concat'
    ),
}


class FrameworkDetector:
    """
    Detects web framework of target application.
    
    Novel contribution: No existing HPP scanner performs
    framework-specific detection to optimize testing.
    """
    
    def __init__(self, http_client=None):
        """
        Initialize detector.
        
        Args:
            http_client: HTTP client for making requests (optional)
        """
        self.http_client = http_client
        self.detection_results: Dict[str, float] = {}
        self.detected_framework: Optional[Framework] = None
        self.confidence: float = 0.0
        
    def detect(self, target_url: str, response_data: Dict = None) -> Tuple[Framework, float]:
        """
        Detect framework using multiple methods.
        
        Args:
            target_url: Target URL to analyze
            response_data: Optional pre-fetched response data
            
        Returns:
            Tuple of (Framework, confidence_score)
        """
        scores = {fw: 0.0 for fw in Framework}
        
        if response_data:
            # Analyze provided response data
            if 'headers' in response_data:
                header_scores = self._analyze_headers(response_data['headers'])
                for fw, score in header_scores.items():
                    scores[fw] += score * 0.4  # 40% weight
                    
            if 'body' in response_data:
                body_scores = self._analyze_body(response_data['body'])
                for fw, score in body_scores.items():
                    scores[fw] += score * 0.3  # 30% weight
                    
            if 'cookies' in response_data:
                cookie_scores = self._analyze_cookies(response_data['cookies'])
                for fw, score in cookie_scores.items():
                    scores[fw] += score * 0.2  # 20% weight
                    
            if 'behavior' in response_data:
                behavior_scores = self._analyze_behavior(response_data['behavior'])
                for fw, score in behavior_scores.items():
                    scores[fw] += score * 0.1  # 10% weight
        
        # Find best match
        best_framework = max(scores, key=scores.get)
        confidence = scores[best_framework]
        
        # If confidence too low, mark as unknown
        if confidence < 0.3:
            best_framework = Framework.UNKNOWN
            confidence = 0.0
            
        self.detected_framework = best_framework
        self.confidence = confidence
        self.detection_results = scores
        
        return best_framework, confidence
    
    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[Framework, float]:
        """Analyze HTTP headers for framework signatures."""
        scores = {fw: 0.0 for fw in Framework}
        
        for framework, signature in FRAMEWORK_SIGNATURES.items():
            matches = 0
            for header_name, pattern in signature.header_patterns:
                header_value = headers.get(header_name, '')
                if re.search(pattern, header_value, re.IGNORECASE):
                    matches += 1
            
            if signature.header_patterns:
                scores[framework] = matches / len(signature.header_patterns)
                
        return scores
    
    def _analyze_body(self, body: str) -> Dict[Framework, float]:
        """Analyze response body for framework error patterns."""
        scores = {fw: 0.0 for fw in Framework}
        
        for framework, signature in FRAMEWORK_SIGNATURES.items():
            matches = 0
            for pattern in signature.error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    matches += 1
            
            if signature.error_patterns:
                scores[framework] = min(1.0, matches / 3)  # Cap at 1.0
                
        return scores
    
    def _analyze_cookies(self, cookies: Dict[str, str]) -> Dict[Framework, float]:
        """Analyze cookies for framework signatures."""
        scores = {fw: 0.0 for fw in Framework}
        cookie_str = ' '.join(cookies.keys())
        
        for framework, signature in FRAMEWORK_SIGNATURES.items():
            matches = 0
            for pattern in signature.cookie_patterns:
                if re.search(pattern, cookie_str, re.IGNORECASE):
                    matches += 1
            
            if signature.cookie_patterns:
                scores[framework] = matches / len(signature.cookie_patterns)
                
        return scores
    
    def _analyze_behavior(self, behavior: Dict) -> Dict[Framework, float]:
        """
        Analyze parameter handling behavior.
        
        behavior dict should contain:
        - 'duplicate_param_result': The value returned when ?p=1&p=2 is sent
        """
        scores = {fw: 0.0 for fw in Framework}
        
        if 'duplicate_param_result' not in behavior:
            return scores
            
        result = behavior['duplicate_param_result']
        
        for framework, signature in FRAMEWORK_SIGNATURES.items():
            expected = signature.parameter_behavior
            
            if expected == 'first' and result == 'first_value':
                scores[framework] = 1.0
            elif expected == 'last' and result == 'last_value':
                scores[framework] = 1.0
            elif expected == 'array' and result == 'array_value':
                scores[framework] = 1.0
            elif expected == 'concat' and result == 'concatenated_value':
                scores[framework] = 1.0
                
        return scores
    
    def get_parameter_behavior(self) -> str:
        """
        Get expected parameter handling behavior for detected framework.
        
        Returns:
            'first': Uses first parameter value
            'last': Uses last parameter value
            'array': Creates array of values
            'concat': Concatenates values
            'unknown': Behavior not determined
        """
        if self.detected_framework and self.detected_framework in FRAMEWORK_SIGNATURES:
            return FRAMEWORK_SIGNATURES[self.detected_framework].parameter_behavior
        return 'unknown'
    
    def get_detection_report(self) -> Dict:
        """Generate detailed detection report."""
        return {
            'detected_framework': self.detected_framework.value if self.detected_framework else 'Unknown',
            'confidence': round(self.confidence * 100, 1),
            'parameter_behavior': self.get_parameter_behavior(),
            'all_scores': {
                fw.value: round(score * 100, 1) 
                for fw, score in self.detection_results.items()
            }
        }


def detect_framework_from_response(headers: Dict, body: str, cookies: Dict = None) -> Tuple[Framework, float]:
    """
    Convenience function to detect framework from response data.
    
    Args:
        headers: HTTP response headers
        body: Response body content
        cookies: Response cookies (optional)
        
    Returns:
        Tuple of (Framework, confidence)
    """
    detector = FrameworkDetector()
    response_data = {
        'headers': headers,
        'body': body,
        'cookies': cookies or {}
    }
    return detector.detect('', response_data)
