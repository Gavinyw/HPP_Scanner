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
        self.active_fingerprinting_enabled: bool = True  # Enable active testing
        
    def detect(self, target_url: str, response_data: Dict = None, make_request_func=None) -> Tuple[Framework, float]:
        """
        Detect framework using multiple methods.

        Args:
            target_url: Target URL to analyze
            response_data: Optional pre-fetched response data
            make_request_func: Optional function to make HTTP requests for active fingerprinting

        Returns:
            Tuple of (Framework, confidence_score)
        """
        scores = {fw: 0.0 for fw in Framework}
        passive_max_score = 0.0  # Track best passive detection score

        # PASSIVE DETECTION (from response data)
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

            passive_max_score = max(scores.values()) if scores else 0.0

        # ACTIVE FINGERPRINTING (if enabled and passive detection failed or has low confidence)
        # WHY: If passive detection found nothing (headers/cookies hidden), try active tests
        # WHEN: Only if make_request_func provided and (no passive data OR low confidence)
        if (self.active_fingerprinting_enabled and
            make_request_func and
            passive_max_score < 0.5):  # Only if passive detection uncertain

            active_scores = self.active_fingerprint(target_url, make_request_func)

            # Combine active scores with passive scores
            # WHY: Active tests are weighted MORE when passive fails
            for fw, active_score in active_scores.items():
                # If passive found nothing, active tests dominate (80% weight)
                # If passive found something weak, blend them (50/50)
                if passive_max_score < 0.1:
                    scores[fw] = active_score * 0.8 + scores[fw] * 0.2
                else:
                    scores[fw] = active_score * 0.6 + scores[fw] * 0.4

        # Find best match
        best_framework = max(scores, key=scores.get)
        confidence = scores[best_framework]

        # If confidence too low, mark as unknown
        # WHY lower threshold to 0.2: With active fingerprinting, even weak signals
        # (like 1-2 header matches) can be valuable when combined with active tests
        if confidence < 0.2:
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

    def active_fingerprint(self, target_url: str, make_request_func) -> Dict[str, float]:
        """
        Perform active fingerprinting by probing the server.

        WHY THIS WORKS: Production sites hide headers/cookies but can't hide
        how they behave. We actively test their behavior patterns.

        Args:
            target_url: Base URL to test
            make_request_func: Function to make HTTP requests

        Returns:
            Dict mapping Framework to confidence scores
        """
        scores = {fw: 0.0 for fw in Framework}

        # Test 1: 404 Error Page Fingerprinting (HIGHEST ACCURACY)
        # WHY: Each framework has distinctive error messages they can't hide
        error_scores = self._test_404_page(target_url, make_request_func)
        for fw, score in error_scores.items():
            scores[fw] += score * 0.4  # 40% weight - very reliable

        # Test 2: Django Admin Path Detection (HIGH CONFIDENCE)
        # WHY: Many sites forget to disable /admin/ even in production
        admin_scores = self._test_admin_paths(target_url, make_request_func)
        for fw, score in admin_scores.items():
            scores[fw] += score * 0.35  # 35% weight - if found, very sure

        # Test 3: Duplicate Parameter Behavior Testing (MEDIUM ACCURACY)
        # WHY: Tests actual parameter handling logic of the framework
        param_scores = self._test_duplicate_params(target_url, make_request_func)
        for fw, score in param_scores.items():
            scores[fw] += score * 0.25  # 25% weight - good but can be ambiguous

        return scores

    def _test_404_page(self, target_url: str, make_request_func) -> Dict[Framework, float]:
        """
        Test 404 error page patterns.

        WHY: Error pages reveal framework info even when headers are stripped.
        Django says "Page not found (404)", Flask shows Werkzeug errors,
        Express says "Cannot GET /path", PHP shows server errors.
        """
        from urllib.parse import urljoin
        scores = {fw: 0.0 for fw in Framework}

        try:
            # Request a non-existent path
            nonexistent_url = urljoin(target_url, '/hpp_scanner_test_nonexistent_12345')
            response = make_request_func(nonexistent_url, 'GET', {})

            if response.status_code == 0:
                return scores  # Connection failed

            body = response.body.lower()

            # Django patterns
            if 'page not found (404)' in body or 'page not found</h1>' in body:
                scores[Framework.DJANGO] = 0.8  # High confidence
            elif 'django' in body and '404' in body:
                scores[Framework.DJANGO] = 0.5

            # Flask/Werkzeug patterns
            if 'werkzeug' in body or 'debugger' in body:
                scores[Framework.FLASK] = 0.9
            elif 'the requested url was not found' in body:
                scores[Framework.FLASK] = 0.4

            # Express/Node.js patterns
            if 'cannot get' in body or 'cannot post' in body:
                scores[Framework.EXPRESS] = 0.7
            elif 'express' in body and '404' in body:
                scores[Framework.EXPRESS] = 0.5

            # PHP patterns
            if 'notice:' in body or 'warning:' in body or 'fatal error:' in body:
                scores[Framework.PHP] = 0.6
            elif '<?php' in body:
                scores[Framework.PHP] = 0.8

        except Exception:
            pass  # Ignore errors, return empty scores

        return scores

    def _test_admin_paths(self, target_url: str, make_request_func) -> Dict[Framework, float]:
        """
        Test common admin/framework-specific paths.

        WHY: Django admin is enabled by default and many developers forget to
        disable it. Finding /admin/ is a smoking gun for Django.
        """
        from urllib.parse import urljoin
        scores = {fw: 0.0 for fw in Framework}

        # Django admin paths
        django_paths = [
            '/admin/',
            '/admin/login/',
            '/static/admin/css/base.css'
        ]

        try:
            for path in django_paths:
                test_url = urljoin(target_url, path)
                response = make_request_func(test_url, 'GET', {})

                if response.status_code == 0:
                    continue

                # Django admin found
                if response.status_code in [200, 302]:  # 200 OK or 302 redirect to login
                    body_lower = response.body.lower()
                    if 'django' in body_lower or 'csrfmiddlewaretoken' in body_lower:
                        scores[Framework.DJANGO] = 0.9  # Very high confidence!
                        break
                    elif path == '/admin/' and response.status_code == 302:
                        scores[Framework.DJANGO] = 0.7  # Admin exists, likely Django
                        break

        except Exception:
            pass

        return scores

    def _test_duplicate_params(self, target_url: str, make_request_func) -> Dict[Framework, float]:
        """
        Test how server handles duplicate parameters.

        WHY: This tests the ACTUAL framework behavior - Django uses last value,
        Flask uses first, Express creates array. Can't be hidden.
        """
        scores = {fw: 0.0 for fw in Framework}

        try:
            # Create test URL with duplicate params
            # We use a parameter name unlikely to exist
            test_params = [
                ('hpp_test_param', 'first_value'),
                ('hpp_test_param', 'last_value')
            ]

            response = make_request_func(target_url, 'GET', test_params)

            if response.status_code == 0:
                return scores

            body = response.body

            # Check which value appears in response
            has_first = 'first_value' in body
            has_last = 'last_value' in body
            has_array = ('[' in body and ']' in body and
                        'first_value' in body and 'last_value' in body)

            if has_array:
                # Express creates array
                scores[Framework.EXPRESS] = 0.6
            elif has_last and not has_first:
                # Django/PHP use last value
                scores[Framework.DJANGO] = 0.4
                scores[Framework.PHP] = 0.4
            elif has_first and not has_last:
                # Flask uses first value
                scores[Framework.FLASK] = 0.5
            # If both appear, could be reflected in error message - inconclusive

        except Exception:
            pass

        return scores
    
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
