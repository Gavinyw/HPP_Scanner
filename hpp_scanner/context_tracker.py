"""
Context Tracking System (NOVEL COMPONENT #2)

Tracks state across multi-step HTTP workflows to detect
HPP vulnerabilities that only appear in context.

Novel contribution: No existing HPP scanner tracks state
across requests to detect privilege escalation chains.

Features:
- Workflow mapping
- State extraction
- Session tracking
- Privilege escalation detection
- Identity confusion detection
"""

from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import hashlib
import json


class WorkflowStepType(Enum):
    """Types of workflow steps"""
    LOGIN = "login"
    LOGOUT = "logout"
    VIEW = "view"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    NAVIGATE = "navigate"
    API_CALL = "api_call"


@dataclass
class SessionState:
    """Represents session state at a point in time"""
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    username: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    is_authenticated: bool = False
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    custom_state: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'username': self.username,
            'role': self.role,
            'permissions': self.permissions,
            'is_authenticated': self.is_authenticated,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
    
    def get_hash(self) -> str:
        """Get hash of state for comparison."""
        state_str = json.dumps({
            'user_id': self.user_id,
            'role': self.role,
            'permissions': sorted(self.permissions),
            'is_authenticated': self.is_authenticated
        }, sort_keys=True)
        return hashlib.md5(state_str.encode()).hexdigest()[:8]


@dataclass
class WorkflowStep:
    """Represents a single step in a workflow"""
    name: str
    step_type: WorkflowStepType
    endpoint: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    expected_status: int = 200
    
    # State tracking
    state_before: Optional[SessionState] = None
    state_after: Optional[SessionState] = None
    response_data: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'type': self.step_type.value,
            'endpoint': self.endpoint,
            'method': self.method,
            'params': self.params,
            'state_before': self.state_before.to_dict() if self.state_before else None,
            'state_after': self.state_after.to_dict() if self.state_after else None
        }


@dataclass
class StateTransition:
    """Represents a state change between steps"""
    from_step: str
    to_step: str
    state_before: SessionState
    state_after: SessionState
    changes: Dict[str, Tuple[Any, Any]] = field(default_factory=dict)  # field: (old, new)
    is_suspicious: bool = False
    suspicion_reason: Optional[str] = None


@dataclass
class ContextVulnerability:
    """Vulnerability detected through context tracking"""
    name: str
    vulnerability_type: str
    severity: str
    workflow_steps: List[str]
    state_changes: List[StateTransition]
    description: str
    exploit_chain: str
    affected_parameter: str
    proof_of_concept: Dict
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'type': self.vulnerability_type,
            'severity': self.severity,
            'workflow': self.workflow_steps,
            'description': self.description,
            'exploit_chain': self.exploit_chain,
            'affected_parameter': self.affected_parameter,
            'poc': self.proof_of_concept
        }


class ContextTracker:
    """
    Tracks context across multi-step workflows.
    
    Novel contribution: Detects HPP vulnerabilities that only
    appear when parameters are tracked across multiple requests.
    """
    
    def __init__(self):
        """Initialize context tracker."""
        self.workflows: List[List[WorkflowStep]] = []
        self.current_workflow: List[WorkflowStep] = []
        self.state_history: List[SessionState] = []
        self.transitions: List[StateTransition] = []
        self.vulnerabilities: List[ContextVulnerability] = []
        self.current_state: SessionState = SessionState()
        
    def start_workflow(self, name: str = "default"):
        """Start a new workflow tracking session."""
        self.current_workflow = []
        self.state_history = []
        self.transitions = []
        self.current_state = SessionState()
        
    def end_workflow(self) -> List[WorkflowStep]:
        """End current workflow and return steps."""
        if self.current_workflow:
            self.workflows.append(self.current_workflow)
        return self.current_workflow
    
    def add_step(self, step: WorkflowStep, response_data: Dict = None):
        """
        Add a step to the current workflow.
        
        Args:
            step: The workflow step
            response_data: Response data from executing the step
        """
        # Capture state before
        step.state_before = self._copy_state(self.current_state)
        
        # Process response and update state
        if response_data:
            step.response_data = response_data
            self._update_state_from_response(response_data)
        
        # Capture state after
        step.state_after = self._copy_state(self.current_state)
        
        # Record transition
        if len(self.current_workflow) > 0:
            prev_step = self.current_workflow[-1]
            transition = self._create_transition(prev_step, step)
            self.transitions.append(transition)
        
        # Add to workflow
        self.current_workflow.append(step)
        self.state_history.append(self._copy_state(self.current_state))
        
    def _copy_state(self, state: SessionState) -> SessionState:
        """Create a copy of session state."""
        return SessionState(
            session_id=state.session_id,
            user_id=state.user_id,
            username=state.username,
            role=state.role,
            permissions=state.permissions.copy(),
            is_authenticated=state.is_authenticated,
            cookies=state.cookies.copy(),
            headers=state.headers.copy(),
            custom_state=state.custom_state.copy(),
            timestamp=datetime.now()
        )
    
    def _update_state_from_response(self, response_data: Dict):
        """Update current state based on response."""
        # Update from cookies
        if 'cookies' in response_data:
            self.current_state.cookies.update(response_data['cookies'])
            
            # Check for session cookie
            for key, value in response_data['cookies'].items():
                if 'session' in key.lower() or 'sid' in key.lower():
                    self.current_state.session_id = value
                    self.current_state.is_authenticated = True
        
        # Update from response body (if contains user info)
        if 'body' in response_data:
            body = response_data['body']
            if isinstance(body, dict):
                if 'user_id' in body:
                    self.current_state.user_id = str(body['user_id'])
                if 'user' in body and isinstance(body['user'], dict):
                    self.current_state.user_id = str(body['user'].get('id', ''))
                    self.current_state.username = body['user'].get('username', '')
                    self.current_state.role = body['user'].get('role', '')
                if 'role' in body:
                    self.current_state.role = body['role']
                if 'permissions' in body:
                    self.current_state.permissions = body['permissions']
                    
        # Update from headers
        if 'headers' in response_data:
            self.current_state.headers.update(response_data['headers'])
    
    def _create_transition(self, from_step: WorkflowStep, to_step: WorkflowStep) -> StateTransition:
        """Create state transition record."""
        changes = {}
        state_before = from_step.state_after
        state_after = to_step.state_after
        
        if state_before and state_after:
            # Check each field for changes
            if state_before.user_id != state_after.user_id:
                changes['user_id'] = (state_before.user_id, state_after.user_id)
            if state_before.role != state_after.role:
                changes['role'] = (state_before.role, state_after.role)
            if state_before.is_authenticated != state_after.is_authenticated:
                changes['is_authenticated'] = (state_before.is_authenticated, state_after.is_authenticated)
            if set(state_before.permissions) != set(state_after.permissions):
                changes['permissions'] = (state_before.permissions, state_after.permissions)
        
        # Determine if suspicious
        is_suspicious, reason = self._analyze_transition(changes, from_step, to_step)
        
        return StateTransition(
            from_step=from_step.name,
            to_step=to_step.name,
            state_before=state_before,
            state_after=state_after,
            changes=changes,
            is_suspicious=is_suspicious,
            suspicion_reason=reason
        )
    
    def _analyze_transition(self, changes: Dict, from_step: WorkflowStep, to_step: WorkflowStep) -> Tuple[bool, Optional[str]]:
        """Analyze if a state transition is suspicious."""
        
        # Check for privilege escalation
        if 'role' in changes:
            old_role, new_role = changes['role']
            if self._is_privilege_escalation(old_role, new_role):
                return True, f"Privilege escalation: {old_role} -> {new_role}"
        
        # Check for user ID change without logout
        if 'user_id' in changes:
            old_id, new_id = changes['user_id']
            if old_id and new_id and old_id != new_id:
                if from_step.step_type != WorkflowStepType.LOGIN:
                    return True, f"User ID changed without login: {old_id} -> {new_id}"
        
        # Check for authentication state change
        if 'is_authenticated' in changes:
            was_auth, is_auth = changes['is_authenticated']
            if not was_auth and is_auth:
                if from_step.step_type != WorkflowStepType.LOGIN:
                    return True, "Authentication gained without login step"
        
        # Check for permission gain
        if 'permissions' in changes:
            old_perms, new_perms = changes['permissions']
            gained_perms = set(new_perms) - set(old_perms)
            if gained_perms:
                return True, f"Permissions gained: {gained_perms}"
        
        return False, None
    
    def _is_privilege_escalation(self, old_role: str, new_role: str) -> bool:
        """Check if role change represents privilege escalation."""
        # Define role hierarchy (lower index = lower privilege)
        role_hierarchy = ['guest', 'user', 'member', 'moderator', 'admin', 'superadmin', 'root']
        
        old_idx = -1
        new_idx = -1
        
        for i, role in enumerate(role_hierarchy):
            if old_role and role in old_role.lower():
                old_idx = i
            if new_role and role in new_role.lower():
                new_idx = i
        
        return new_idx > old_idx
    
    def analyze_workflow(self) -> List[ContextVulnerability]:
        """
        Analyze current workflow for vulnerabilities.
        
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # Check for suspicious transitions
        for transition in self.transitions:
            if transition.is_suspicious:
                vuln = self._create_vulnerability_from_transition(transition)
                if vuln:
                    vulnerabilities.append(vuln)
        
        # Check for identity confusion patterns
        identity_vulns = self._detect_identity_confusion()
        vulnerabilities.extend(identity_vulns)
        
        # Check for session fixation patterns
        session_vulns = self._detect_session_issues()
        vulnerabilities.extend(session_vulns)
        
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def _create_vulnerability_from_transition(self, transition: StateTransition) -> Optional[ContextVulnerability]:
        """Create vulnerability from suspicious transition."""
        
        # Find the steps involved
        workflow_steps = [transition.from_step, transition.to_step]
        
        # Determine type and severity based on the change
        if 'role' in transition.changes:
            return ContextVulnerability(
                name="Privilege Escalation via HPP",
                vulnerability_type="privilege_escalation",
                severity="CRITICAL",
                workflow_steps=workflow_steps,
                state_changes=[transition],
                description=f"HPP enabled role change: {transition.changes['role'][0]} -> {transition.changes['role'][1]}",
                exploit_chain=f"1. Execute {transition.from_step}\n2. Inject HPP payload\n3. Execute {transition.to_step}\n4. Gain elevated privileges",
                affected_parameter="role",
                proof_of_concept={
                    'original_role': transition.changes['role'][0],
                    'escalated_role': transition.changes['role'][1],
                    'steps': workflow_steps
                }
            )
        
        if 'user_id' in transition.changes:
            return ContextVulnerability(
                name="Identity Confusion via HPP",
                vulnerability_type="auth_bypass",
                severity="HIGH",
                workflow_steps=workflow_steps,
                state_changes=[transition],
                description=f"HPP enabled user ID switch: {transition.changes['user_id'][0]} -> {transition.changes['user_id'][1]}",
                exploit_chain=f"1. Authenticate as User A\n2. Inject HPP with User B's ID\n3. Access User B's data",
                affected_parameter="user_id",
                proof_of_concept={
                    'original_user': transition.changes['user_id'][0],
                    'target_user': transition.changes['user_id'][1],
                    'steps': workflow_steps
                }
            )
        
        return None
    
    def _detect_identity_confusion(self) -> List[ContextVulnerability]:
        """Detect identity confusion vulnerabilities."""
        vulnerabilities = []
        
        # Check if user_id changed while session remained same
        for i, step in enumerate(self.current_workflow[1:], 1):
            prev_step = self.current_workflow[i-1]
            
            if (step.state_before and step.state_after and
                prev_step.state_after and
                step.state_after.session_id == prev_step.state_after.session_id and
                step.state_after.user_id != prev_step.state_after.user_id):
                
                vuln = ContextVulnerability(
                    name="Session-User ID Mismatch",
                    vulnerability_type="identity_confusion",
                    severity="HIGH",
                    workflow_steps=[prev_step.name, step.name],
                    state_changes=[],
                    description="Same session accessing different user data",
                    exploit_chain="Session belongs to User A but data accessed for User B",
                    affected_parameter="user_id",
                    proof_of_concept={
                        'session': step.state_after.session_id,
                        'expected_user': prev_step.state_after.user_id,
                        'actual_user': step.state_after.user_id
                    }
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _detect_session_issues(self) -> List[ContextVulnerability]:
        """Detect session-related vulnerabilities."""
        vulnerabilities = []
        
        # Check for session not changing after login
        for i, step in enumerate(self.current_workflow):
            if step.step_type == WorkflowStepType.LOGIN:
                if (step.state_before and step.state_after and
                    step.state_before.session_id == step.state_after.session_id and
                    step.state_before.session_id is not None):
                    
                    vuln = ContextVulnerability(
                        name="Session Fixation Risk",
                        vulnerability_type="session_fixation",
                        severity="MEDIUM",
                        workflow_steps=[step.name],
                        state_changes=[],
                        description="Session ID not regenerated after login",
                        exploit_chain="Pre-login session maintained post-authentication",
                        affected_parameter="session",
                        proof_of_concept={
                            'session_before': step.state_before.session_id,
                            'session_after': step.state_after.session_id
                        }
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def get_workflow_summary(self) -> Dict:
        """Get summary of tracked workflow."""
        return {
            'total_steps': len(self.current_workflow),
            'steps': [s.name for s in self.current_workflow],
            'transitions': len(self.transitions),
            'suspicious_transitions': sum(1 for t in self.transitions if t.is_suspicious),
            'vulnerabilities_found': len(self.vulnerabilities),
            'state_changes': [
                {
                    'from': t.from_step,
                    'to': t.to_step,
                    'changes': {k: {'from': v[0], 'to': v[1]} for k, v in t.changes.items()},
                    'suspicious': t.is_suspicious,
                    'reason': t.suspicion_reason
                }
                for t in self.transitions
            ]
        }
    
    def simulate_hpp_attack(self, step_index: int, param_name: str, 
                           original_value: str, injected_value: str) -> Dict:
        """
        Simulate an HPP attack at a specific workflow step.
        
        Args:
            step_index: Which step to attack
            param_name: Parameter to pollute
            original_value: Original parameter value
            injected_value: Injected second value
            
        Returns:
            Simulation result
        """
        if step_index >= len(self.current_workflow):
            return {'error': 'Invalid step index'}
        
        step = self.current_workflow[step_index]
        
        # Create attack scenario
        attack_scenario = {
            'target_step': step.name,
            'target_endpoint': step.endpoint,
            'original_request': {
                'params': step.params,
                'data': step.data
            },
            'hpp_attack': {
                'parameter': param_name,
                'values': [original_value, injected_value],
                'payload': f'?{param_name}={original_value}&{param_name}={injected_value}'
            },
            'state_before_attack': step.state_before.to_dict() if step.state_before else None,
            'potential_impact': self._assess_hpp_impact(step, param_name, injected_value)
        }
        
        return attack_scenario
    
    def _assess_hpp_impact(self, step: WorkflowStep, param_name: str, 
                          injected_value: str) -> Dict:
        """Assess potential impact of HPP attack."""
        impact = {
            'risk_level': 'LOW',
            'potential_effects': [],
            'requires_further_testing': True
        }
        
        param_lower = param_name.lower()
        
        # Check parameter sensitivity
        if any(x in param_lower for x in ['user', 'uid', 'id', 'account']):
            impact['risk_level'] = 'HIGH'
            impact['potential_effects'].append('Unauthorized data access')
            impact['potential_effects'].append('Identity confusion')
            
        if any(x in param_lower for x in ['role', 'admin', 'permission', 'access']):
            impact['risk_level'] = 'CRITICAL'
            impact['potential_effects'].append('Privilege escalation')
            impact['potential_effects'].append('Authorization bypass')
            
        if any(x in param_lower for x in ['price', 'amount', 'total', 'cost']):
            impact['risk_level'] = 'HIGH'
            impact['potential_effects'].append('Financial manipulation')
            impact['potential_effects'].append('Business logic bypass')
        
        return impact
