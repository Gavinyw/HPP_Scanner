"""
Impact Scoring Algorithm (NOVEL COMPONENT #3)

Calculates actual security impact of HPP vulnerabilities:
- Exploitability score (0-10)
- Impact score (0-10)
- Combined severity rating (CRITICAL/HIGH/MEDIUM/LOW)

Novel contribution: Existing tools use generic severity.
This module calculates severity based on actual impact.

Based on CVSS v3.1 methodology adapted for HPP.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class AttackVector(Enum):
    """CVSS-style attack vectors"""
    NETWORK = "Network"      # Remotely exploitable
    ADJACENT = "Adjacent"    # Same network segment
    LOCAL = "Local"          # Local access required
    PHYSICAL = "Physical"    # Physical access required


class AttackComplexity(Enum):
    """Attack complexity levels"""
    LOW = "Low"              # No special conditions
    HIGH = "High"            # Specific conditions required


class PrivilegesRequired(Enum):
    """Privileges required for exploitation"""
    NONE = "None"            # No authentication needed
    LOW = "Low"              # Basic user access
    HIGH = "High"            # Admin/privileged access


class UserInteraction(Enum):
    """User interaction required"""
    NONE = "None"            # No user interaction
    REQUIRED = "Required"    # User must click/interact


class ImpactLevel(Enum):
    """Impact levels for C/I/A"""
    NONE = "None"
    LOW = "Low"
    HIGH = "High"


@dataclass
class VulnerabilityMetrics:
    """Metrics for vulnerability scoring"""
    # Exploitability metrics
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    
    # Impact metrics
    confidentiality_impact: ImpactLevel = ImpactLevel.NONE
    integrity_impact: ImpactLevel = ImpactLevel.NONE
    availability_impact: ImpactLevel = ImpactLevel.NONE
    
    # HPP-specific metrics
    affects_authentication: bool = False
    affects_authorization: bool = False
    affects_financial: bool = False
    affects_data_access: bool = False
    multi_step_required: bool = False
    framework_dependent: bool = False
    
    # Context
    parameter_name: str = ""
    parameter_type: str = ""  # user_id, role, price, etc.
    workflow_steps: int = 1


@dataclass
class ImpactScore:
    """Calculated impact score"""
    exploitability_score: float
    impact_score: float
    base_score: float
    severity: Severity
    
    # Breakdown
    exploitability_breakdown: Dict[str, float]
    impact_breakdown: Dict[str, float]
    
    # Justification
    severity_justification: str
    recommendations: List[str]
    
    def to_dict(self) -> Dict:
        return {
            'exploitability_score': round(self.exploitability_score, 1),
            'impact_score': round(self.impact_score, 1),
            'base_score': round(self.base_score, 1),
            'severity': self.severity.value,
            'severity_justification': self.severity_justification,
            'recommendations': self.recommendations,
            'breakdown': {
                'exploitability': self.exploitability_breakdown,
                'impact': self.impact_breakdown
            }
        }


class ImpactScorer:
    """
    Calculates actual security impact of HPP vulnerabilities.
    
    Novel contribution: Provides justified severity ratings
    based on exploitability and real-world impact.
    """
    
    # CVSS v3.1 base weights
    ATTACK_VECTOR_WEIGHTS = {
        AttackVector.NETWORK: 0.85,
        AttackVector.ADJACENT: 0.62,
        AttackVector.LOCAL: 0.55,
        AttackVector.PHYSICAL: 0.20
    }
    
    ATTACK_COMPLEXITY_WEIGHTS = {
        AttackComplexity.LOW: 0.77,
        AttackComplexity.HIGH: 0.44
    }
    
    PRIVILEGES_REQUIRED_WEIGHTS = {
        PrivilegesRequired.NONE: 0.85,
        PrivilegesRequired.LOW: 0.62,
        PrivilegesRequired.HIGH: 0.27
    }
    
    USER_INTERACTION_WEIGHTS = {
        UserInteraction.NONE: 0.85,
        UserInteraction.REQUIRED: 0.62
    }
    
    IMPACT_WEIGHTS = {
        ImpactLevel.NONE: 0.0,
        ImpactLevel.LOW: 0.22,
        ImpactLevel.HIGH: 0.56
    }
    
    def __init__(self):
        """Initialize impact scorer."""
        self.scored_vulnerabilities: List[ImpactScore] = []
        
    def calculate_score(self, metrics: VulnerabilityMetrics) -> ImpactScore:
        """
        Calculate impact score for a vulnerability.
        
        Args:
            metrics: Vulnerability metrics
            
        Returns:
            Calculated impact score
        """
        # Calculate exploitability sub-score
        exploitability, exp_breakdown = self._calculate_exploitability(metrics)
        
        # Calculate impact sub-score
        impact, imp_breakdown = self._calculate_impact(metrics)
        
        # Calculate base score (CVSS formula)
        if impact <= 0:
            base_score = 0.0
        else:
            base_score = min(10, 
                1.08 * (impact + exploitability))
        
        # Apply HPP-specific adjustments
        base_score = self._apply_hpp_adjustments(base_score, metrics)
        
        # Determine severity
        severity = self._determine_severity(base_score)
        
        # Generate justification
        justification = self._generate_justification(metrics, base_score, severity)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(metrics, severity)
        
        score = ImpactScore(
            exploitability_score=exploitability * 10,
            impact_score=impact * 10,
            base_score=base_score,
            severity=severity,
            exploitability_breakdown=exp_breakdown,
            impact_breakdown=imp_breakdown,
            severity_justification=justification,
            recommendations=recommendations
        )
        
        self.scored_vulnerabilities.append(score)
        return score
    
    def _calculate_exploitability(self, metrics: VulnerabilityMetrics) -> Tuple[float, Dict]:
        """Calculate exploitability sub-score."""
        av = self.ATTACK_VECTOR_WEIGHTS[metrics.attack_vector]
        ac = self.ATTACK_COMPLEXITY_WEIGHTS[metrics.attack_complexity]
        pr = self.PRIVILEGES_REQUIRED_WEIGHTS[metrics.privileges_required]
        ui = self.USER_INTERACTION_WEIGHTS[metrics.user_interaction]
        
        # Exploitability = 8.22 × AV × AC × PR × UI (CVSS formula)
        exploitability = 8.22 * av * ac * pr * ui / 10  # Normalize to 0-1
        
        breakdown = {
            'attack_vector': round(av, 2),
            'attack_complexity': round(ac, 2),
            'privileges_required': round(pr, 2),
            'user_interaction': round(ui, 2),
            'formula': '8.22 × AV × AC × PR × UI'
        }
        
        return exploitability, breakdown
    
    def _calculate_impact(self, metrics: VulnerabilityMetrics) -> Tuple[float, Dict]:
        """Calculate impact sub-score."""
        c = self.IMPACT_WEIGHTS[metrics.confidentiality_impact]
        i = self.IMPACT_WEIGHTS[metrics.integrity_impact]
        a = self.IMPACT_WEIGHTS[metrics.availability_impact]
        
        # ISS = 1 - [(1-C) × (1-I) × (1-A)]
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        # Impact = 6.42 × ISS (CVSS formula, simplified)
        impact = 6.42 * iss / 10  # Normalize to 0-1
        
        breakdown = {
            'confidentiality': round(c, 2),
            'integrity': round(i, 2),
            'availability': round(a, 2),
            'impact_sub_score': round(iss, 2),
            'formula': '6.42 × ISS'
        }
        
        return impact, breakdown
    
    def _apply_hpp_adjustments(self, base_score: float, metrics: VulnerabilityMetrics) -> float:
        """Apply HPP-specific score adjustments."""
        adjusted = base_score
        
        # Increase score for authentication-related HPP
        if metrics.affects_authentication:
            adjusted += 0.5
            
        # Increase score for authorization bypass
        if metrics.affects_authorization:
            adjusted += 0.8
            
        # Increase score for financial impact
        if metrics.affects_financial:
            adjusted += 0.5
            
        # Slight decrease if multi-step attack required
        if metrics.multi_step_required:
            adjusted -= 0.3
            
        # Slight decrease if framework-dependent
        if metrics.framework_dependent:
            adjusted -= 0.2
        
        return max(0, min(10, adjusted))
    
    def _determine_severity(self, base_score: float) -> Severity:
        """Determine severity from base score."""
        if base_score >= 9.0:
            return Severity.CRITICAL
        elif base_score >= 7.0:
            return Severity.HIGH
        elif base_score >= 4.0:
            return Severity.MEDIUM
        elif base_score >= 0.1:
            return Severity.LOW
        else:
            return Severity.INFORMATIONAL
    
    def _generate_justification(self, metrics: VulnerabilityMetrics, 
                               base_score: float, severity: Severity) -> str:
        """Generate human-readable severity justification."""
        parts = []
        
        parts.append(f"Base Score: {base_score:.1f}/10 ({severity.value})")
        parts.append("")
        
        # Exploitability factors
        exp_factors = []
        if metrics.attack_vector == AttackVector.NETWORK:
            exp_factors.append("remotely exploitable")
        if metrics.attack_complexity == AttackComplexity.LOW:
            exp_factors.append("low complexity")
        if metrics.privileges_required == PrivilegesRequired.NONE:
            exp_factors.append("no authentication required")
        if metrics.user_interaction == UserInteraction.NONE:
            exp_factors.append("no user interaction needed")
            
        if exp_factors:
            parts.append(f"Exploitability: {', '.join(exp_factors)}")
        
        # Impact factors
        imp_factors = []
        if metrics.confidentiality_impact != ImpactLevel.NONE:
            imp_factors.append(f"{metrics.confidentiality_impact.value} confidentiality impact")
        if metrics.integrity_impact != ImpactLevel.NONE:
            imp_factors.append(f"{metrics.integrity_impact.value} integrity impact")
        if metrics.availability_impact != ImpactLevel.NONE:
            imp_factors.append(f"{metrics.availability_impact.value} availability impact")
            
        if imp_factors:
            parts.append(f"Impact: {', '.join(imp_factors)}")
        
        # HPP-specific factors
        hpp_factors = []
        if metrics.affects_authentication:
            hpp_factors.append("affects authentication")
        if metrics.affects_authorization:
            hpp_factors.append("enables authorization bypass")
        if metrics.affects_financial:
            hpp_factors.append("financial impact possible")
        if metrics.affects_data_access:
            hpp_factors.append("unauthorized data access")
            
        if hpp_factors:
            parts.append(f"HPP Impact: {', '.join(hpp_factors)}")
        
        return "\n".join(parts)
    
    def _generate_recommendations(self, metrics: VulnerabilityMetrics, 
                                  severity: Severity) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []
        
        # Always include basic HPP prevention
        recommendations.append("Validate and sanitize all input parameters")
        recommendations.append("Use framework-specific parameter parsing consistently")
        
        if metrics.affects_authentication:
            recommendations.append("Implement strict parameter validation in authentication flows")
            recommendations.append("Use single, unambiguous parameter names for credentials")
            
        if metrics.affects_authorization:
            recommendations.append("Enforce server-side authorization checks independent of parameters")
            recommendations.append("Use session-based role verification, not parameter-based")
            
        if metrics.affects_financial:
            recommendations.append("Implement server-side price/amount calculation")
            recommendations.append("Add integrity checks for financial parameters")
            
        if metrics.affects_data_access:
            recommendations.append("Implement object-level access control")
            recommendations.append("Verify user owns requested resource before returning data")
        
        if severity in [Severity.CRITICAL, Severity.HIGH]:
            recommendations.append("URGENT: Remediate before next release")
            recommendations.append("Consider temporary WAF rules to block duplicate parameters")
        
        return recommendations
    
    def score_from_vulnerability_data(self, vuln_data: Dict) -> ImpactScore:
        """
        Calculate score from vulnerability dictionary.
        
        Args:
            vuln_data: Dictionary with vulnerability details
            
        Returns:
            Calculated impact score
        """
        metrics = VulnerabilityMetrics(
            parameter_name=vuln_data.get('parameter', ''),
            parameter_type=vuln_data.get('parameter_type', ''),
            workflow_steps=vuln_data.get('workflow_steps', 1)
        )
        
        # Set attack vector
        if vuln_data.get('requires_auth', False):
            metrics.privileges_required = PrivilegesRequired.LOW
        
        if vuln_data.get('requires_admin', False):
            metrics.privileges_required = PrivilegesRequired.HIGH
            
        if vuln_data.get('requires_user_action', False):
            metrics.user_interaction = UserInteraction.REQUIRED
            
        # Set impact based on vulnerability type
        vuln_type = vuln_data.get('type', '').lower()
        
        if 'auth' in vuln_type or 'authentication' in vuln_type:
            metrics.affects_authentication = True
            metrics.confidentiality_impact = ImpactLevel.HIGH
            metrics.integrity_impact = ImpactLevel.HIGH
            
        if 'privilege' in vuln_type or 'authorization' in vuln_type or 'escalation' in vuln_type:
            metrics.affects_authorization = True
            metrics.confidentiality_impact = ImpactLevel.HIGH
            metrics.integrity_impact = ImpactLevel.HIGH
            
        if 'price' in vuln_type or 'financial' in vuln_type or 'payment' in vuln_type:
            metrics.affects_financial = True
            metrics.integrity_impact = ImpactLevel.HIGH
            
        if 'access' in vuln_type or 'data' in vuln_type:
            metrics.affects_data_access = True
            metrics.confidentiality_impact = ImpactLevel.HIGH
        
        if vuln_data.get('multi_step', False):
            metrics.multi_step_required = True
            
        if vuln_data.get('framework_dependent', False):
            metrics.framework_dependent = True
        
        return self.calculate_score(metrics)
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Score and prioritize a list of vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Sorted list with scores, highest severity first
        """
        scored = []
        
        for vuln in vulnerabilities:
            score = self.score_from_vulnerability_data(vuln)
            vuln['score'] = score.to_dict()
            vuln['priority'] = self._calculate_priority(score)
            scored.append(vuln)
        
        # Sort by base score (descending)
        scored.sort(key=lambda x: x['score']['base_score'], reverse=True)
        
        return scored
    
    def _calculate_priority(self, score: ImpactScore) -> str:
        """Calculate remediation priority."""
        if score.severity == Severity.CRITICAL:
            return "IMMEDIATE"
        elif score.severity == Severity.HIGH:
            return "URGENT"
        elif score.severity == Severity.MEDIUM:
            return "SCHEDULED"
        else:
            return "BACKLOG"
    
    def get_summary(self) -> Dict:
        """Get summary of all scored vulnerabilities."""
        if not self.scored_vulnerabilities:
            return {'total': 0}
            
        severity_counts = {}
        total_score = 0
        
        for score in self.scored_vulnerabilities:
            sev = score.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            total_score += score.base_score
        
        return {
            'total': len(self.scored_vulnerabilities),
            'average_score': round(total_score / len(self.scored_vulnerabilities), 1),
            'by_severity': severity_counts,
            'highest_score': max(s.base_score for s in self.scored_vulnerabilities),
            'critical_count': severity_counts.get('CRITICAL', 0),
            'high_count': severity_counts.get('HIGH', 0)
        }


# Convenience functions
def quick_score(
    parameter_name: str,
    affects_auth: bool = False,
    affects_authz: bool = False,
    affects_financial: bool = False,
    requires_auth: bool = False,
    multi_step: bool = False
) -> ImpactScore:
    """
    Quick scoring for common scenarios.
    
    Args:
        parameter_name: Name of affected parameter
        affects_auth: True if authentication affected
        affects_authz: True if authorization affected
        affects_financial: True if financial impact
        requires_auth: True if authentication required
        multi_step: True if multi-step attack
        
    Returns:
        Impact score
    """
    metrics = VulnerabilityMetrics(
        parameter_name=parameter_name,
        affects_authentication=affects_auth,
        affects_authorization=affects_authz,
        affects_financial=affects_financial,
        multi_step_required=multi_step,
        privileges_required=PrivilegesRequired.LOW if requires_auth else PrivilegesRequired.NONE
    )
    
    if affects_auth:
        metrics.confidentiality_impact = ImpactLevel.HIGH
        metrics.integrity_impact = ImpactLevel.HIGH
    
    if affects_authz:
        metrics.confidentiality_impact = ImpactLevel.HIGH
        metrics.integrity_impact = ImpactLevel.HIGH
    
    if affects_financial:
        metrics.integrity_impact = ImpactLevel.HIGH
    
    scorer = ImpactScorer()
    return scorer.calculate_score(metrics)
