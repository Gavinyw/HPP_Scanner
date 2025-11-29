"""
Response Analysis Engine

Compares HTTP responses to detect HPP vulnerabilities:
- Status code comparison
- Content length analysis
- Body content diff
- Header analysis
- Behavior detection
"""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import re
import hashlib
from difflib import SequenceMatcher


@dataclass
class ResponseData:
    """Represents an HTTP response"""
    status_code: int
    headers: Dict[str, str]
    body: str
    cookies: Dict[str, str]
    response_time: float  # in milliseconds
    url: str = ""
    
    def get_content_length(self) -> int:
        return len(self.body)
    
    def get_body_hash(self) -> str:
        return hashlib.md5(self.body.encode()).hexdigest()
    
    def to_dict(self) -> Dict:
        return {
            'status_code': self.status_code,
            'content_length': self.get_content_length(),
            'body_hash': self.get_body_hash(),
            'response_time': self.response_time,
            'headers': self.headers,
            'cookies': self.cookies
        }


@dataclass
class ComparisonResult:
    """Result of comparing two responses"""
    is_different: bool
    differences: Dict[str, Any]
    similarity_score: float  # 0.0 to 1.0
    vulnerability_indicators: List[str]
    confidence: float
    
    def to_dict(self) -> Dict:
        return {
            'is_different': self.is_different,
            'differences': self.differences,
            'similarity_score': round(self.similarity_score, 3),
            'vulnerability_indicators': self.vulnerability_indicators,
            'confidence': round(self.confidence, 2)
        }


@dataclass
class ParameterBehavior:
    """Detected parameter handling behavior"""
    behavior: str  # 'first', 'last', 'array', 'concat', 'error', 'unknown'
    evidence: str
    confidence: float
    raw_response: str


class ResponseAnalyzer:
    """
    Analyzes HTTP responses to detect HPP vulnerabilities.
    
    Compares baseline (single parameter) with test (duplicate parameters)
    to identify behavioral differences that indicate HPP.
    """
    
    # Patterns that indicate security-relevant differences
    SECURITY_PATTERNS = {
        'auth_success': [
            r'logged in', r'welcome', r'dashboard', r'authenticated',
            r'login successful', r'access granted'
        ],
        'auth_failure': [
            r'login failed', r'invalid credentials', r'access denied',
            r'unauthorized', r'forbidden', r'authentication required'
        ],
        'error': [
            r'error', r'exception', r'traceback', r'stack trace',
            r'syntax error', r'parse error', r'fatal'
        ],
        'admin': [
            r'admin', r'administrator', r'superuser', r'root access',
            r'elevated privileges', r'management'
        ],
        'user_data': [
            r'user_id', r'username', r'email', r'profile',
            r'account', r'personal'
        ],
        'financial': [
            r'price', r'amount', r'total', r'payment', r'balance',
            r'\$\d+', r'€\d+', r'£\d+'
        ]
    }
    
    def __init__(self):
        """Initialize response analyzer."""
        self.comparison_history: List[ComparisonResult] = []
        
    def compare_responses(self, baseline: ResponseData, test: ResponseData) -> ComparisonResult:
        """
        Compare baseline response with HPP test response.
        
        Args:
            baseline: Response with single parameter
            test: Response with duplicate parameters
            
        Returns:
            Comparison result with vulnerability indicators
        """
        differences = {}
        indicators = []
        
        # Compare status codes
        if baseline.status_code != test.status_code:
            differences['status_code'] = {
                'baseline': baseline.status_code,
                'test': test.status_code
            }
            indicators.append(f"Status code changed: {baseline.status_code} -> {test.status_code}")
            
            # Check for specific status code patterns
            if baseline.status_code == 403 and test.status_code == 200:
                indicators.append("CRITICAL: Access control bypass detected (403 -> 200)")
            elif baseline.status_code == 401 and test.status_code == 200:
                indicators.append("CRITICAL: Authentication bypass detected (401 -> 200)")
            elif test.status_code == 500:
                indicators.append("Server error triggered - possible vulnerability")
        
        # Compare content length
        len_baseline = baseline.get_content_length()
        len_test = test.get_content_length()
        len_diff = abs(len_baseline - len_test)
        len_diff_percent = (len_diff / max(len_baseline, 1)) * 100
        
        if len_diff_percent > 10:  # More than 10% difference
            differences['content_length'] = {
                'baseline': len_baseline,
                'test': len_test,
                'difference': len_diff,
                'difference_percent': round(len_diff_percent, 1)
            }
            indicators.append(f"Content length changed by {len_diff_percent:.1f}%")
        
        # Compare body content
        body_similarity = self._calculate_similarity(baseline.body, test.body)
        if body_similarity < 0.95:  # Less than 95% similar
            differences['body'] = {
                'similarity': body_similarity,
                'baseline_hash': baseline.get_body_hash()[:8],
                'test_hash': test.get_body_hash()[:8]
            }
            
            # Analyze what changed
            body_changes = self._analyze_body_changes(baseline.body, test.body)
            if body_changes:
                differences['body']['changes'] = body_changes
                indicators.extend(body_changes.get('indicators', []))
        
        # Compare headers
        header_diff = self._compare_headers(baseline.headers, test.headers)
        if header_diff:
            differences['headers'] = header_diff
            indicators.append("Response headers changed")
            
            # Check for security-relevant headers
            if 'Set-Cookie' in header_diff:
                indicators.append("Session cookie changed - possible session manipulation")
            if 'Location' in header_diff:
                indicators.append("Redirect location changed - possible open redirect")
        
        # Compare cookies
        cookie_diff = self._compare_cookies(baseline.cookies, test.cookies)
        if cookie_diff:
            differences['cookies'] = cookie_diff
            indicators.append("Cookies changed")
        
        # Compare response time (timing attack detection)
        time_diff = abs(baseline.response_time - test.response_time)
        if time_diff > 500:  # More than 500ms difference
            differences['response_time'] = {
                'baseline': baseline.response_time,
                'test': test.response_time,
                'difference': time_diff
            }
            indicators.append(f"Response time difference: {time_diff}ms (possible timing attack vector)")
        
        # Check for security pattern matches
        security_findings = self._check_security_patterns(baseline.body, test.body)
        if security_findings:
            differences['security_patterns'] = security_findings
            indicators.extend(security_findings.get('indicators', []))
        
        # Calculate overall similarity and confidence
        is_different = len(differences) > 0
        similarity = body_similarity * 0.6 + (1 if baseline.status_code == test.status_code else 0) * 0.4
        confidence = self._calculate_confidence(differences, indicators)
        
        result = ComparisonResult(
            is_different=is_different,
            differences=differences,
            similarity_score=similarity,
            vulnerability_indicators=indicators,
            confidence=confidence
        )
        
        self.comparison_history.append(result)
        return result
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity ratio between two texts."""
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0
        return SequenceMatcher(None, text1, text2).ratio()
    
    def _analyze_body_changes(self, baseline_body: str, test_body: str) -> Dict:
        """Analyze specific changes in response body."""
        changes = {
            'indicators': []
        }
        
        # Check for user ID changes
        baseline_ids = set(re.findall(r'user[_-]?id["\']?\s*[:=]\s*["\']?(\w+)', baseline_body, re.I))
        test_ids = set(re.findall(r'user[_-]?id["\']?\s*[:=]\s*["\']?(\w+)', test_body, re.I))
        
        if baseline_ids != test_ids:
            changes['user_ids'] = {
                'baseline': list(baseline_ids),
                'test': list(test_ids)
            }
            changes['indicators'].append(f"User ID changed: {baseline_ids} -> {test_ids}")
        
        # Check for role changes
        baseline_roles = set(re.findall(r'role["\']?\s*[:=]\s*["\']?(\w+)', baseline_body, re.I))
        test_roles = set(re.findall(r'role["\']?\s*[:=]\s*["\']?(\w+)', test_body, re.I))
        
        if baseline_roles != test_roles:
            changes['roles'] = {
                'baseline': list(baseline_roles),
                'test': list(test_roles)
            }
            changes['indicators'].append(f"Role changed: {baseline_roles} -> {test_roles}")
        
        # Check for price changes
        baseline_prices = re.findall(r'[\$€£]\s*(\d+(?:\.\d{2})?)', baseline_body)
        test_prices = re.findall(r'[\$€£]\s*(\d+(?:\.\d{2})?)', test_body)
        
        if baseline_prices != test_prices:
            changes['prices'] = {
                'baseline': baseline_prices,
                'test': test_prices
            }
            changes['indicators'].append(f"Price values changed")
        
        return changes if changes['indicators'] else {}
    
    def _compare_headers(self, baseline: Dict, test: Dict) -> Dict:
        """Compare response headers."""
        diff = {}
        
        all_keys = set(baseline.keys()) | set(test.keys())
        for key in all_keys:
            b_val = baseline.get(key)
            t_val = test.get(key)
            
            if b_val != t_val:
                diff[key] = {
                    'baseline': b_val,
                    'test': t_val
                }
        
        return diff
    
    def _compare_cookies(self, baseline: Dict, test: Dict) -> Dict:
        """Compare response cookies."""
        diff = {}
        
        all_keys = set(baseline.keys()) | set(test.keys())
        for key in all_keys:
            b_val = baseline.get(key)
            t_val = test.get(key)
            
            if b_val != t_val:
                diff[key] = {
                    'baseline': b_val,
                    'test': t_val
                }
        
        return diff
    
    def _check_security_patterns(self, baseline_body: str, test_body: str) -> Dict:
        """Check for security-relevant pattern changes."""
        findings = {
            'indicators': []
        }
        
        for category, patterns in self.SECURITY_PATTERNS.items():
            baseline_matches = []
            test_matches = []
            
            for pattern in patterns:
                if re.search(pattern, baseline_body, re.I):
                    baseline_matches.append(pattern)
                if re.search(pattern, test_body, re.I):
                    test_matches.append(pattern)
            
            # Check for new matches in test that weren't in baseline
            new_matches = set(test_matches) - set(baseline_matches)
            lost_matches = set(baseline_matches) - set(test_matches)
            
            if new_matches or lost_matches:
                findings[category] = {
                    'new': list(new_matches),
                    'lost': list(lost_matches)
                }
                
                if category == 'admin' and new_matches:
                    findings['indicators'].append("CRITICAL: Admin-related content appeared in response")
                elif category == 'auth_success' and new_matches:
                    findings['indicators'].append("Authentication-related change detected")
                elif category == 'error' and new_matches:
                    findings['indicators'].append("New error messages in response")
        
        return findings if findings['indicators'] else {}
    
    def _calculate_confidence(self, differences: Dict, indicators: List[str]) -> float:
        """Calculate confidence score for vulnerability detection."""
        confidence = 0.0
        
        # Status code change is strong indicator
        if 'status_code' in differences:
            confidence += 0.3
        
        # Body changes indicate something happened
        if 'body' in differences:
            confidence += 0.2
        
        # Security pattern changes are significant
        if 'security_patterns' in differences:
            confidence += 0.3
        
        # Critical indicators boost confidence
        critical_keywords = ['CRITICAL', 'bypass', 'escalation', 'unauthorized']
        for indicator in indicators:
            if any(kw in indicator for kw in critical_keywords):
                confidence += 0.1
        
        return min(1.0, confidence)
    
    def detect_parameter_behavior(
        self,
        responses: Dict[str, ResponseData]
    ) -> ParameterBehavior:
        """
        Detect which parameter value is used by the server.
        
        Args:
            responses: Dict mapping test type to response
                - 'baseline': Response with single param
                - 'first_marked': Response with first param as marker
                - 'last_marked': Response with last param as marker
                
        Returns:
            Detected parameter behavior
        """
        baseline = responses.get('baseline')
        first_marked = responses.get('first_marked')
        last_marked = responses.get('last_marked')
        
        if not all([baseline, first_marked, last_marked]):
            return ParameterBehavior(
                behavior='unknown',
                evidence='Insufficient test data',
                confidence=0.0,
                raw_response=''
            )
        
        # Check if marker appears in response
        first_marker = 'HPPTEST_FIRST'
        last_marker = 'HPPTEST_LAST'
        
        first_in_response = first_marker in first_marked.body
        last_in_response = last_marker in last_marked.body
        
        if first_in_response and not last_in_response:
            return ParameterBehavior(
                behavior='first',
                evidence=f'First parameter marker ({first_marker}) found in response',
                confidence=0.9,
                raw_response=first_marked.body[:200]
            )
        elif last_in_response and not first_in_response:
            return ParameterBehavior(
                behavior='last',
                evidence=f'Last parameter marker ({last_marker}) found in response',
                confidence=0.9,
                raw_response=last_marked.body[:200]
            )
        elif first_in_response and last_in_response:
            return ParameterBehavior(
                behavior='array',
                evidence='Both markers found - server creates array of values',
                confidence=0.8,
                raw_response=first_marked.body[:200]
            )
        elif ',' in first_marked.body and first_marker.split('_')[1] in first_marked.body:
            return ParameterBehavior(
                behavior='concat',
                evidence='Values appear concatenated in response',
                confidence=0.7,
                raw_response=first_marked.body[:200]
            )
        else:
            return ParameterBehavior(
                behavior='unknown',
                evidence='Could not determine parameter handling behavior',
                confidence=0.3,
                raw_response=first_marked.body[:200]
            )
    
    def get_analysis_summary(self) -> Dict:
        """Get summary of all analysis performed."""
        if not self.comparison_history:
            return {'total_comparisons': 0}
        
        vuln_count = sum(1 for c in self.comparison_history if c.is_different)
        high_confidence = sum(1 for c in self.comparison_history if c.confidence > 0.7)
        
        all_indicators = []
        for c in self.comparison_history:
            all_indicators.extend(c.vulnerability_indicators)
        
        return {
            'total_comparisons': len(self.comparison_history),
            'differences_found': vuln_count,
            'high_confidence_findings': high_confidence,
            'average_similarity': sum(c.similarity_score for c in self.comparison_history) / len(self.comparison_history),
            'unique_indicators': list(set(all_indicators))
        }
