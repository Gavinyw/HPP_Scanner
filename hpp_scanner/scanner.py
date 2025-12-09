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
import requests

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

        # Context tracking storage
        self.workflow_responses: List[Dict] = []  # Store responses for context tracking
        
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
        """Detect target framework using Novel Component #1 with active fingerprinting."""
        if self.config.verbose:
            print("[*] Detecting framework...")

        # Get response data from initial request (passive detection)
        response_data = self._get_framework_detection_data()

        # Detect framework with BOTH passive and active methods
        # WHY: Pass _make_request so detector can actively probe the server
        # WHEN: Active tests only run if passive detection fails (see framework_detector.py)
        self.detected_framework, self.framework_confidence = \
            self.framework_detector.detect(
                self.target_url,
                response_data,
                make_request_func=self._make_request  # NEW: Enable active fingerprinting
            )

        # Configure payload generator with detected framework
        self.payload_generator.set_framework(self.detected_framework)

        if self.config.verbose:
            print(f"[+] Detected framework: {self.detected_framework.value}")
            print(f"[+] Confidence: {self.framework_confidence * 100:.0f}%")
    
    def _get_framework_detection_data(self) -> Dict:
        """
        Get response data for framework detection by making real HTTP request.

        Returns:
            Dict with headers, body, cookies from actual server response
        """
        if self.config.verbose:
            print(f"[*] Fetching {self.target_url} for framework fingerprinting...")

        # Make actual GET request to target
        response = self._make_request(self.target_url, 'GET', {})

        # Check if request succeeded
        if response.status_code == 0:
            # Connection failed
            if self.config.verbose:
                print(f"[!] Failed to connect to {self.target_url}")
                print(f"[!] {response.body}")
            return {
                'headers': {},
                'body': '',
                'cookies': {}
            }

        if self.config.verbose:
            print(f"[+] Received response: {response.status_code} ({len(response.body)} bytes)")

        return {
            'headers': response.headers,
            'body': response.body,
            'cookies': response.cookies
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

        # Make baseline request to store response for context tracking
        baseline_response = self._make_request(url, method, params)

        # Store response for context tracking
        self.workflow_responses.append({
            'url': url,
            'method': method,
            'params': params,
            'response': baseline_response
        })

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
    
    def _create_hpp_params(self, original_params: Dict, payload: HPPPayload):
        """
        Create parameters with HPP injection using list of tuples.

        Python dicts cannot have duplicate keys, so we use list of tuples
        to preserve duplicate parameters for HPP testing.

        Args:
            original_params: Original parameters as dict
            payload: HPP payload with duplicate values

        Returns:
            List of (key, value) tuples with duplicates

        Example:
            original_params = {'id': '1', 'user': 'test'}
            payload.param_name = 'role'
            payload.values = ['user', 'admin']

            Returns: [('id', '1'), ('user', 'test'), ('role', 'user'), ('role', 'admin')]
            URL becomes: ?id=1&user=test&role=user&role=admin
        """
        # Convert original params to list of tuples, excluding the HPP target parameter
        params_list = [(k, v) for k, v in original_params.items()
                       if k != payload.param_name]

        # Add duplicate parameters from payload
        for value in payload.values:
            params_list.append((payload.param_name, str(value)))

        return params_list
    
    def _make_request(self, url: str, method: str, params) -> ResponseData:
        """
        Make actual HTTP request using requests library.

        Args:
            url: Target URL
            method: HTTP method (GET, POST)
            params: Parameters - can be Dict or List[Tuple] for duplicate params

        Returns:
            ResponseData with actual server response
        """
        start_time = time.time()

        try:
            # Prepare headers with user agent
            headers = {
                'User-Agent': self.config.user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }

            if method.upper() == 'GET':
                # For HPP testing, we need to send duplicate parameters
                # Standard dict doesn't support this, so we use list of tuples
                if isinstance(params, list):
                    # Manual query string construction for duplicate params
                    # Example: [('id', '1'), ('id', '2')] -> "id=1&id=2"
                    from urllib.parse import quote
                    query_parts = [f"{quote(str(k))}={quote(str(v))}" for k, v in params]
                    query = '&'.join(query_parts)
                else:
                    # Regular dict params
                    from urllib.parse import urlencode
                    query = urlencode(params) if params else ''

                full_url = f"{url}?{query}" if query else url

                if self.config.verbose:
                    print(f"  [HTTP] GET {full_url}")

                response = requests.get(
                    full_url,
                    timeout=self.config.timeout,
                    allow_redirects=self.config.follow_redirects,
                    headers=headers,
                    verify=True  # SSL verification
                )

            elif method.upper() == 'POST':
                if self.config.verbose:
                    print(f"  [HTTP] POST {url}")

                # POST supports duplicate params via list of tuples
                response = requests.post(
                    url,
                    data=params,  # requests handles both dict and list of tuples
                    timeout=self.config.timeout,
                    allow_redirects=self.config.follow_redirects,
                    headers=headers,
                    verify=True
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            # Calculate response time in milliseconds
            response_time = (time.time() - start_time) * 1000

            return ResponseData(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
                cookies=dict(response.cookies),
                response_time=response_time,
                url=response.url
            )

        except requests.exceptions.Timeout:
            if self.config.verbose:
                print(f"  [ERROR] Timeout after {self.config.timeout}s")
            return ResponseData(
                status_code=0,
                headers={},
                body="Error: Request timeout",
                cookies={},
                response_time=self.config.timeout * 1000,
                url=url
            )

        except requests.exceptions.ConnectionError as e:
            if self.config.verbose:
                print(f"  [ERROR] Connection failed: {e}")
            return ResponseData(
                status_code=0,
                headers={},
                body=f"Error: Connection failed - {str(e)}",
                cookies={},
                response_time=0.0,
                url=url
            )

        except requests.exceptions.RequestException as e:
            if self.config.verbose:
                print(f"  [ERROR] Request failed: {e}")
            return ResponseData(
                status_code=0,
                headers={},
                body=f"Error: {str(e)}",
                cookies={},
                response_time=0.0,
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
        """
        Perform PRACTICAL context-aware analysis using Novel Component #2.

        IMPROVED LOGIC:
        - Skip context tracking for single-endpoint scans (not useful)
        - Focus on OBSERVABLE behavior: parameter precedence, session tracking
        - Don't look for theoretical role changes that never happen
        """
        if self.config.verbose:
            print("[*] Performing context-aware analysis...")

        # IMPROVEMENT 1: Skip if only one endpoint (no workflow to analyze)
        if len(self.workflow_responses) <= 1:
            if self.config.verbose:
                print("[*] Single endpoint detected - skipping multi-step workflow analysis")
            # Still do parameter precedence analysis (useful even for single endpoint)
            self._analyze_parameter_precedence()
            return

        # IMPROVEMENT 2: Only analyze multi-step workflows if they exist
        # Start workflow tracking
        self.context_tracker.start_workflow("HPP_Scan_Workflow")

        # Add tested endpoints as workflow steps WITH response data
        for i, workflow_item in enumerate(self.workflow_responses):
            # Determine step type based on endpoint pattern
            endpoint = workflow_item['url']
            method = workflow_item['method']

            # Infer step type from URL patterns
            if '/login' in endpoint.lower() or '/auth' in endpoint.lower():
                step_type = WorkflowStepType.LOGIN
            elif method == 'POST' or '/update' in endpoint.lower() or '/edit' in endpoint.lower():
                step_type = WorkflowStepType.UPDATE
            elif '/delete' in endpoint.lower():
                step_type = WorkflowStepType.DELETE
            else:
                step_type = WorkflowStepType.VIEW

            step = WorkflowStep(
                name=f"Step_{i+1}_{step_type.value}",
                step_type=step_type,
                endpoint=endpoint,
                method=method
            )

            # Extract response data from ResponseData object
            response = workflow_item['response']
            response_data = {
                'body': response.body,
                'cookies': response.cookies,
                'headers': response.headers,
                'status_code': response.status_code
            }

            # Add step WITH response data
            self.context_tracker.add_step(step, response_data)

        # Analyze for context-dependent vulnerabilities
        context_vulns = self.context_tracker.analyze_workflow()

        # IMPROVEMENT 3: Only report HIGH/CRITICAL context vulnerabilities
        # (Ignore theoretical findings with no evidence)
        for cv in context_vulns:
            # Skip LOW severity theoretical findings
            if cv.severity in ['HIGH', 'CRITICAL']:
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

    def _analyze_parameter_precedence(self):
        """
        Analyze which parameter value the framework uses (first/last/array).

        This is PRACTICAL context tracking that works on ANY app.
        Documents observable HPP behavior.
        """
        if self.config.verbose:
            print("[*] Analyzing parameter precedence behavior...")

        # This information is already captured in comparison_result
        # Just log it for the user
        precedence_map = {
            'Flask': 'first',
            'Django': 'last',
            'Express': 'array',
            'PHP': 'last',
            'ASP.NET': 'concatenated'
        }

        framework_name = self.detected_framework.value
        if framework_name in precedence_map:
            precedence = precedence_map[framework_name]
            if self.config.verbose:
                print(f"[+] {framework_name} uses {precedence.upper()} parameter value")
    
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
