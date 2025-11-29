"""
HPP Scanner - Main Module

Integrates all components:
- Framework Detection (Novel #1)
- Context Tracking (Novel #2)  
- Impact Scoring (Novel #3)
- Payload Generation
- Response Analysis
- Report Generation

This is the primary interface for the HPP detection tool.
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
import time

from .framework_detector import FrameworkDetector, Framework
from .payload_generator import PayloadGenerator, PayloadType, ParameterLocation, HPPPayload
from .context_tracker import ContextTracker, WorkflowStep, WorkflowStepType, SessionState
from .impact_scorer import ImpactScorer, VulnerabilityMetrics, Severity
from .response_analyzer import ResponseAnalyzer, ResponseData, ComparisonResult
from .report_generator import ReportGenerator, ScanResult


@dataclass
class ScanConfig:
    """Configuration for HPP scan"""
    target_url: str
    max_depth: int = 3
    timeout: int = 30
    follow_redirects: bool = True
    test_methods: List[str] = field(default_factory=lambda: ['GET', 'POST'])
    include_cookies: bool = True
    user_agent: str = 'HPP-Scanner/1.0'
    
    # Novel features toggle
    framework_detection: bool = True
    context_tracking: bool = True
    impact_scoring: bool = True
    
    # Output options
    verbose: bool = False
    output_format: str = 'html'  # html, json, text, markdown


@dataclass
class HPPVulnerability:
    """Represents a detected HPP vulnerability"""
    name: str
    parameter: str
    endpoint: str
    method: str
    severity: str
    score: Dict
    description: str
    exploit_chain: str
    payload_used: HPPPayload
    comparison_result: ComparisonResult
    framework: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'parameter': self.parameter,
            'endpoint': self.endpoint,
            'method': self.method,
            'severity': self.severity,
            'score': self.score,
            'description': self.description,
            'exploit_chain': self.exploit_chain,
            'framework': self.framework,
            'timestamp': self.timestamp.isoformat()
        }


class HPPScanner:
    """
    Context-Aware HTTP Parameter Pollution Scanner
    
    Novel contributions:
    1. Framework-specific detection and testing
    2. Context-aware multi-step workflow analysis
    3. Impact-based severity scoring
    
    Usage:
        scanner = HPPScanner(target_url)
        results = scanner.scan()
        report = scanner.generate_report()
    """
    
    def __init__(self, target_url: str, config: ScanConfig = None):
        """
        Initialize HPP Scanner.
        
        Args:
            target_url: Target URL to scan
            config: Optional scan configuration
        """
        self.target_url = target_url
        self.config = config or ScanConfig(target_url=target_url)
        
        # Initialize components
        self.framework_detector = FrameworkDetector()
        self.payload_generator = PayloadGenerator()
        self.context_tracker = ContextTracker()
        self.impact_scorer = ImpactScorer()
        self.response_analyzer = ResponseAnalyzer()
        self.report_generator = ReportGenerator()
        
        # Results storage
        self.detected_framework: Framework = Framework.UNKNOWN
        self.framework_confidence: float = 0.0
        self.vulnerabilities: List[HPPVulnerability] = []
        self.endpoints_tested: List[str] = []
        self.parameters_tested: List[str] = []
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time: Optional[datetime] = None
        
        # HTTP client placeholder (to be implemented with requests library)
        self._http_client = None
        
    def scan(self, endpoints: List[Dict] = None, http_client=None) -> List[HPPVulnerability]:
        """
        Perform HPP vulnerability scan.
        
        Args:
            endpoints: Optional list of endpoints to test
                      Each endpoint: {'url': str, 'method': str, 'params': Dict}
            http_client: Optional HTTP client for making requests
            
        Returns:
            List of detected vulnerabilities
        """
        self.scan_start_time = datetime.now()
        self._http_client = http_client
        
        if self.config.verbose:
            print(f"[*] Starting HPP scan on {self.target_url}")
            print(f"[*] Scan started at {self.scan_start_time}")
        
        # Step 1: Framework Detection (Novel #1)
        if self.config.framework_detection:
            self._detect_framework()
        
        # Step 2: Discover or use provided endpoints
        if endpoints is None:
            endpoints = self._discover_endpoints()
        
        # Step 3: Test each endpoint
        for endpoint in endpoints:
            self._test_endpoint(endpoint)
        
        # Step 4: Context-Aware Analysis (Novel #2)
        if self.config.context_tracking:
            self._analyze_context()
        
        # Step 5: Score vulnerabilities (Novel #3)
        if self.config.impact_scoring:
            self._score_vulnerabilities()
        
        self.scan_end_time = datetime.now()
        
        if self.config.verbose:
            duration = (self.scan_end_time - self.scan_start_time).total_seconds()
            print(f"[*] Scan completed in {duration:.2f} seconds")
            print(f"[*] Found {len(self.vulnerabilities)} vulnerabilities")
        
        return self.vulnerabilities
    
    def _detect_framework(self):
        """Detect target framework using Novel Component #1."""
        if self.config.verbose:
            print("[*] Detecting framework...")
        
        # In real implementation, make HTTP request and analyze response
        # For now, using mock response data
        response_data = self._get_framework_detection_data()
        
        self.detected_framework, self.framework_confidence = \
            self.framework_detector.detect(self.target_url, response_data)
        
        # Configure payload generator with detected framework
        self.payload_generator.set_framework(self.detected_framework)
        
        if self.config.verbose:
            print(f"[+] Detected framework: {self.detected_framework.value}")
            print(f"[+] Confidence: {self.framework_confidence * 100:.0f}%")
    
    def _get_framework_detection_data(self) -> Dict:
        """Get response data for framework detection."""
        # Placeholder - in real implementation, make actual HTTP requests
        return {
            'headers': {},
            'body': '',
            'cookies': {}
        }
    
    def _discover_endpoints(self) -> List[Dict]:
        """Discover endpoints to test."""
        # Placeholder - in real implementation, crawl the target
        # Return sample endpoints for demonstration
        parsed = urlparse(self.target_url)
        base_path = parsed.path or '/'
        
        return [
            {
                'url': f"{parsed.scheme}://{parsed.netloc}{base_path}",
                'method': 'GET',
                'params': {'id': '1', 'action': 'view'}
            }
        ]
    
    def _test_endpoint(self, endpoint: Dict):
        """Test a single endpoint for HPP vulnerabilities."""
        url = endpoint.get('url', self.target_url)
        method = endpoint.get('method', 'GET')
        params = endpoint.get('params', {})
        
        self.endpoints_tested.append(url)
        
        if self.config.verbose:
            print(f"[*] Testing {method} {url}")
        
        # Test each parameter
        for param_name, param_value in params.items():
            self.parameters_tested.append(param_name)
            
            # Generate payloads for this parameter
            payloads = self.payload_generator.generate_payloads(
                param_name,
                location=ParameterLocation.QUERY if method == 'GET' else ParameterLocation.BODY
            )
            
            # Test each payload
            for payload in payloads:
                result = self._test_payload(url, method, params, payload)
                if result:
                    self.vulnerabilities.append(result)
    
    def _test_payload(
        self, 
        url: str, 
        method: str, 
        original_params: Dict,
        payload: HPPPayload
    ) -> Optional[HPPVulnerability]:
        """
        Test a single HPP payload.
        
        Args:
            url: Target URL
            method: HTTP method
            original_params: Original parameters
            payload: HPP payload to test
            
        Returns:
            HPPVulnerability if vulnerable, None otherwise
        """
        # Create baseline request (single parameter)
        baseline_response = self._make_request(url, method, original_params)
        
        # Create HPP test request (duplicate parameter)
        hpp_params = self._create_hpp_params(original_params, payload)
        test_response = self._make_request(url, method, hpp_params)
        
        # Compare responses
        comparison = self.response_analyzer.compare_responses(
            baseline_response, test_response
        )
        
        # Check if vulnerable
        if comparison.is_different and comparison.confidence > 0.5:
            # Determine vulnerability name based on payload type
            vuln_name = self._get_vulnerability_name(payload)
            
            return HPPVulnerability(
                name=vuln_name,
                parameter=payload.param_name,
                endpoint=url,
                method=method,
                severity=payload.risk_level,
                score={},  # Will be filled by impact scorer
                description=payload.description,
                exploit_chain=self._build_exploit_chain(url, method, payload),
                payload_used=payload,
                comparison_result=comparison,
                framework=self.detected_framework.value
            )
        
        return None
    
    def _create_hpp_params(self, original_params: Dict, payload: HPPPayload) -> Dict:
        """Create parameters with HPP injection."""
        hpp_params = original_params.copy()
        # In real implementation, would create list of tuples for duplicate params
        # For now, just mark as modified
        hpp_params[payload.param_name] = payload.values
        return hpp_params
    
    def _make_request(self, url: str, method: str, params: Dict) -> ResponseData:
        """
        Make HTTP request.
        
        Note: In real implementation, use requests library.
        This is a placeholder for demonstration.
        """
        # Placeholder response - in real implementation, make actual request
        return ResponseData(
            status_code=200,
            headers={'Content-Type': 'text/html'},
            body='<html><body>Response</body></html>',
            cookies={},
            response_time=100.0,
            url=url
        )
    
    def _get_vulnerability_name(self, payload: HPPPayload) -> str:
        """Get vulnerability name based on payload type."""
        names = {
            PayloadType.BASIC_DUPLICATE: 'HTTP Parameter Pollution Detected',
            PayloadType.PRIVILEGE_ESCALATION: 'Privilege Escalation via HPP',
            PayloadType.AUTH_BYPASS: 'Authentication Bypass via HPP',
            PayloadType.PRICE_MANIPULATION: 'Price Manipulation via HPP',
            PayloadType.ACCESS_CONTROL: 'Access Control Bypass via HPP',
            PayloadType.WAF_BYPASS: 'WAF Bypass via HPP',
            PayloadType.ARRAY_INJECTION: 'Array Injection via HPP'
        }
        return names.get(payload.payload_type, 'HPP Vulnerability')
    
    def _build_exploit_chain(self, url: str, method: str, payload: HPPPayload) -> str:
        """Build exploit chain description."""
        return f"""1. Send {method} request to {url}
2. Include duplicate parameter: {payload.param_name}={payload.values[0]}&{payload.param_name}={payload.values[1]}
3. Server processes {'last' if self.detected_framework in [Framework.DJANGO, Framework.PHP] else 'first' if self.detected_framework == Framework.FLASK else 'both'} value
4. Result: {payload.expected_behavior}"""
    
    def _analyze_context(self):
        """Perform context-aware analysis using Novel Component #2."""
        if self.config.verbose:
            print("[*] Performing context-aware analysis...")
        
        # Start workflow tracking
        self.context_tracker.start_workflow()
        
        # Add tested endpoints as workflow steps
        for i, endpoint in enumerate(self.endpoints_tested):
            step = WorkflowStep(
                name=f"Step_{i+1}",
                step_type=WorkflowStepType.VIEW,
                endpoint=endpoint,
                method="GET"
            )
            self.context_tracker.add_step(step)
        
        # Analyze for context-dependent vulnerabilities
        context_vulns = self.context_tracker.analyze_workflow()
        
        # Convert context vulnerabilities to HPP vulnerabilities
        for cv in context_vulns:
            vuln = HPPVulnerability(
                name=cv.name,
                parameter=cv.affected_parameter,
                endpoint=self.target_url,
                method='GET',
                severity=cv.severity,
                score={},
                description=cv.description,
                exploit_chain=cv.exploit_chain,
                payload_used=None,
                comparison_result=None,
                framework=self.detected_framework.value
            )
            self.vulnerabilities.append(vuln)
    
    def _score_vulnerabilities(self):
        """Score vulnerabilities using Novel Component #3."""
        if self.config.verbose:
            print("[*] Scoring vulnerabilities...")
        
        for vuln in self.vulnerabilities:
            # Create metrics from vulnerability
            vuln_data = {
                'parameter': vuln.parameter,
                'type': vuln.name,
                'requires_auth': False,
                'multi_step': len(self.endpoints_tested) > 1,
                'framework_dependent': vuln.framework != 'Unknown'
            }
            
            # Calculate score
            score = self.impact_scorer.score_from_vulnerability_data(vuln_data)
            vuln.score = score.to_dict()
            vuln.severity = score.severity.value
    
    def generate_report(self, format: str = None) -> str:
        """
        Generate vulnerability report.
        
        Args:
            format: Output format (html, json, text, markdown)
            
        Returns:
            Report string
        """
        format = format or self.config.output_format
        
        # Create scan result
        scan_result = ScanResult(
            target_url=self.target_url,
            scan_time=self.scan_start_time or datetime.now(),
            framework_detected=self.detected_framework.value,
            framework_confidence=self.framework_confidence,
            total_endpoints=len(self.endpoints_tested),
            total_parameters=len(self.parameters_tested),
            vulnerabilities=[v.to_dict() for v in self.vulnerabilities],
            scan_duration=(self.scan_end_time - self.scan_start_time).total_seconds() 
                          if self.scan_end_time and self.scan_start_time else 0.0
        )
        
        # Generate report in requested format
        if format == 'html':
            return self.report_generator.generate_html_report(scan_result)
        elif format == 'json':
            return self.report_generator.generate_json_report(scan_result)
        elif format == 'text':
            return self.report_generator.generate_text_report(scan_result)
        elif format == 'markdown':
            return self.report_generator.generate_markdown_report(scan_result)
        else:
            return self.report_generator.generate_text_report(scan_result)
    
    def get_summary(self) -> Dict:
        """Get scan summary."""
        severity_counts = {}
        for vuln in self.vulnerabilities:
            sev = vuln.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            'target': self.target_url,
            'framework': {
                'detected': self.detected_framework.value,
                'confidence': self.framework_confidence
            },
            'coverage': {
                'endpoints': len(self.endpoints_tested),
                'parameters': len(self.parameters_tested)
            },
            'findings': {
                'total': len(self.vulnerabilities),
                'by_severity': severity_counts
            },
            'scan_duration': (self.scan_end_time - self.scan_start_time).total_seconds()
                            if self.scan_end_time and self.scan_start_time else 0.0,
            'novel_features': {
                'framework_detection': self.config.framework_detection,
                'context_tracking': self.config.context_tracking,
                'impact_scoring': self.config.impact_scoring
            }
        }


def quick_scan(url: str, verbose: bool = True) -> Dict:
    """
    Quick HPP scan with default settings.
    
    Args:
        url: Target URL
        verbose: Print progress
        
    Returns:
        Scan summary
    """
    config = ScanConfig(target_url=url, verbose=verbose)
    scanner = HPPScanner(url, config)
    scanner.scan()
    return scanner.get_summary()
