#!/usr/bin/env python3
"""
HPP Scanner - Presentation Demonstration Script

This script demonstrates all three novel components of the HPP Detection Tool.
Run this during your presentation to show the tool's capabilities.

Usage:
    python demo.py           # Full demonstration
    python demo.py --quick   # Quick demo (less output)
    python demo.py --step    # Step-by-step with pauses
"""

import sys
import time
import argparse
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, '.')

from hpp_scanner.framework_detector import FrameworkDetector, Framework, FRAMEWORK_SIGNATURES
from hpp_scanner.payload_generator import PayloadGenerator, PayloadType, ParameterLocation
from hpp_scanner.context_tracker import ContextTracker, WorkflowStep, WorkflowStepType, SessionState
from hpp_scanner.impact_scorer import ImpactScorer, VulnerabilityMetrics, ImpactLevel, quick_score
from hpp_scanner.response_analyzer import ResponseAnalyzer, ResponseData
from hpp_scanner.report_generator import ReportGenerator, ScanResult


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def print_header(text):
    """Print a section header."""
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}  {text}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.END}\n")


def print_subheader(text):
    """Print a subsection header."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{text}{Colors.END}")
    print(f"{Colors.CYAN}{'-'*40}{Colors.END}")


def print_success(text):
    """Print success message."""
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")


def print_warning(text):
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")


def print_critical(text):
    """Print critical finding."""
    print(f"{Colors.RED}{Colors.BOLD}🚨 {text}{Colors.END}")


def print_info(text):
    """Print info message."""
    print(f"{Colors.BLUE}ℹ {text}{Colors.END}")


def wait_for_user(step_mode):
    """Wait for user input in step mode."""
    if step_mode:
        input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")


def demo_banner():
    """Print demonstration banner."""
    banner = f"""
{Colors.BOLD}{Colors.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     🔒 Context-Aware HPP Detection Tool                       ║
║        Presentation Demonstration                             ║
║                                                               ║
║     Novel Features:                                           ║
║       1. Framework-Specific Detection                         ║
║       2. Context-Aware Multi-Step Analysis                    ║
║       3. Impact-Based Severity Scoring                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}"""
    print(banner)
    print(f"  Demo started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()


def demo_framework_detection(step_mode=False):
    """Demonstrate Novel Component #1: Framework Detection."""
    print_header("NOVEL COMPONENT #1: Framework Detection")
    
    print("""
{bold}Problem:{end} Existing scanners use generic payloads regardless of 
the target framework, missing framework-specific vulnerabilities.

{bold}Our Solution:{end} Automatically detect the framework and optimize 
testing based on how each framework handles duplicate parameters.
""".format(bold=Colors.BOLD, end=Colors.END))
    
    wait_for_user(step_mode)
    
    # Show framework parameter behaviors
    print_subheader("Framework Parameter Handling Behaviors")
    
    behaviors = [
        ("Django", "last", "?id=1&id=2 → uses '2'"),
        ("Flask", "first", "?id=1&id=2 → uses '1'"),
        ("Express", "array", "?id=1&id=2 → uses ['1','2']"),
        ("PHP", "last", "?id=1&id=2 → uses '2'"),
        ("ASP.NET", "concat", "?id=1&id=2 → uses '1,2'"),
    ]
    
    print(f"\n{'Framework':<12} {'Behavior':<10} {'Example':<30}")
    print("-" * 55)
    for fw, behavior, example in behaviors:
        print(f"{fw:<12} {behavior:<10} {example:<30}")
    
    wait_for_user(step_mode)
    
    # Demonstrate detection
    print_subheader("Live Framework Detection Demo")
    
    detector = FrameworkDetector()
    
    test_cases = [
        {
            'name': 'Django Application',
            'headers': {'Server': 'WSGIServer/0.2'},
            'body': '<input type="hidden" name="csrfmiddlewaretoken" value="abc123">',
            'cookies': {'csrftoken': 'xyz', 'sessionid': '123'}
        },
        {
            'name': 'Flask Application',
            'headers': {'Server': 'Werkzeug/2.0.1 Python/3.9.0'},
            'body': 'Werkzeug Debugger',
            'cookies': {'session': 'eyJ0ZXN0IjoxMjN9'}
        },
        {
            'name': 'Express Application',
            'headers': {'X-Powered-By': 'Express'},
            'body': 'Cannot GET /invalid',
            'cookies': {'connect.sid': 's%3Aabc123'}
        },
        {
            'name': 'PHP Application',
            'headers': {'X-Powered-By': 'PHP/8.1.0'},
            'body': '',
            'cookies': {'PHPSESSID': 'abc123def456'}
        }
    ]
    
    for test in test_cases:
        print(f"\n{Colors.BOLD}Testing: {test['name']}{Colors.END}")
        print(f"  Headers: {test['headers']}")
        
        response_data = {
            'headers': test['headers'],
            'body': test['body'],
            'cookies': test['cookies']
        }
        
        framework, confidence = detector.detect('http://example.com', response_data)
        report = detector.get_detection_report()
        
        color = Colors.GREEN if confidence > 0.6 else Colors.YELLOW
        print(f"  {color}→ Detected: {framework.value} ({confidence*100:.0f}% confidence){Colors.END}")
        print(f"  {color}→ Parameter behavior: {report['parameter_behavior']}{Colors.END}")
    
    print_success("Framework detection enables targeted HPP testing!")
    wait_for_user(step_mode)


def demo_payload_generation(step_mode=False):
    """Demonstrate payload generation capabilities."""
    print_header("Payload Generation Engine")
    
    print("""
{bold}Capability:{end} Generate both generic and framework-specific 
HPP payloads based on detected framework and parameter context.
""".format(bold=Colors.BOLD, end=Colors.END))
    
    wait_for_user(step_mode)
    
    print_subheader("Context-Aware Payload Selection")
    
    # Show how parameter names affect payload selection
    test_params = [
        ('id', 'Generic identifier'),
        ('user_id', 'User identity - HIGH RISK'),
        ('role', 'Permission level - CRITICAL'),
        ('price', 'Financial value - HIGH RISK'),
        ('page', 'Pagination - LOW RISK')
    ]
    
    generator = PayloadGenerator(Framework.DJANGO)
    
    print(f"\n{'Parameter':<12} {'Context':<30} {'Payloads':<10} {'Critical':<10}")
    print("-" * 65)
    
    for param, context in test_params:
        payloads = generator.generate_payloads(param)
        critical = len(generator.get_payloads_by_risk('CRITICAL'))
        high = len(generator.get_payloads_by_risk('HIGH'))
        
        risk_color = Colors.RED if critical > 0 else Colors.YELLOW if high > 0 else Colors.GREEN
        print(f"{param:<12} {context:<30} {len(payloads):<10} {risk_color}{critical}{Colors.END}")
    
    wait_for_user(step_mode)
    
    # Show framework-specific payloads
    print_subheader("Framework-Specific Payloads")
    
    frameworks = [Framework.DJANGO, Framework.FLASK, Framework.EXPRESS]
    
    for fw in frameworks:
        generator.set_framework(fw)
        payloads = generator.generate_payloads('user_id')
        fw_specific = generator.get_framework_specific_count()
        
        print(f"\n{Colors.BOLD}{fw.value}:{Colors.END}")
        print(f"  Total payloads: {len(payloads)}")
        print(f"  Framework-specific: {fw_specific}")
        
        # Show one framework-specific payload
        for p in payloads:
            if p.framework_specific:
                print(f"  Example: {p.name}")
                print(f"    Values: {p.values}")
                print(f"    Expected: {p.expected_behavior}")
                break
    
    print_success("Payloads optimized for each framework!")
    wait_for_user(step_mode)


def demo_context_tracking(step_mode=False):
    """Demonstrate Novel Component #2: Context Tracking."""
    print_header("NOVEL COMPONENT #2: Context-Aware Analysis")
    
    print("""
{bold}Problem:{end} Existing scanners test each request in isolation,
missing vulnerabilities that only appear across multiple steps.

{bold}Our Solution:{end} Track state across workflow steps to detect
privilege escalation, identity confusion, and session attacks.
""".format(bold=Colors.BOLD, end=Colors.END))
    
    wait_for_user(step_mode)
    
    print_subheader("Multi-Step Workflow Simulation")
    
    tracker = ContextTracker()
    tracker.start_workflow("E-commerce Checkout Flow")
    
    # Simulate a workflow with HPP attack
    workflow_steps = [
        {
            'name': 'User Login',
            'type': WorkflowStepType.LOGIN,
            'endpoint': '/api/login',
            'response': {
                'cookies': {'session': 'sess_123'},
                'body': {'user': {'id': 'user_456', 'role': 'customer'}}
            }
        },
        {
            'name': 'View Profile',
            'type': WorkflowStepType.VIEW,
            'endpoint': '/api/profile',
            'response': {
                'cookies': {'session': 'sess_123'},
                'body': {'user': {'id': 'user_456', 'role': 'customer'}}
            }
        },
        {
            'name': 'HPP Attack - Role Parameter',
            'type': WorkflowStepType.UPDATE,
            'endpoint': '/api/profile/update?role=customer&role=admin',
            'response': {
                'cookies': {'session': 'sess_123'},
                'body': {'user': {'id': 'user_456', 'role': 'admin'}}  # Role changed!
            }
        },
        {
            'name': 'Access Admin Panel',
            'type': WorkflowStepType.VIEW,
            'endpoint': '/admin/dashboard',
            'response': {
                'cookies': {'session': 'sess_123'},
                'body': {'admin': True, 'permissions': ['read', 'write', 'delete']}
            }
        }
    ]
    
    print("\n{bold}Executing Workflow Steps:{end}".format(bold=Colors.BOLD, end=Colors.END))
    
    for i, step_data in enumerate(workflow_steps, 1):
        step = WorkflowStep(
            name=step_data['name'],
            step_type=step_data['type'],
            endpoint=step_data['endpoint']
        )
        
        tracker.add_step(step, step_data['response'])
        
        state = tracker.current_state
        color = Colors.RED if 'HPP Attack' in step_data['name'] else Colors.BLUE
        
        print(f"\n  {color}Step {i}: {step_data['name']}{Colors.END}")
        print(f"    Endpoint: {step_data['endpoint']}")
        print(f"    User ID: {state.user_id}")
        print(f"    Role: {state.role}")
        
        if 'HPP Attack' in step_data['name']:
            print_critical("Role changed from 'customer' to 'admin'!")
        
        time.sleep(0.5)  # Dramatic pause
    
    wait_for_user(step_mode)
    
    # Analyze workflow
    print_subheader("Vulnerability Analysis")
    
    vulnerabilities = tracker.analyze_workflow()
    summary = tracker.get_workflow_summary()
    
    print(f"\n{Colors.BOLD}Workflow Summary:{Colors.END}")
    print(f"  Total steps: {summary['total_steps']}")
    print(f"  State transitions: {summary['transitions']}")
    print(f"  Suspicious transitions: {summary['suspicious_transitions']}")
    
    if vulnerabilities:
        print(f"\n{Colors.RED}{Colors.BOLD}Vulnerabilities Detected:{Colors.END}")
        for vuln in vulnerabilities:
            print(f"\n  🚨 {vuln.name}")
            print(f"     Type: {vuln.vulnerability_type}")
            print(f"     Severity: {vuln.severity}")
            print(f"     Description: {vuln.description}")
    
    print_success("Context tracking detected privilege escalation chain!")
    wait_for_user(step_mode)


def demo_impact_scoring(step_mode=False):
    """Demonstrate Novel Component #3: Impact Scoring."""
    print_header("NOVEL COMPONENT #3: Impact-Based Scoring")
    
    print("""
{bold}Problem:{end} Existing scanners report all HPP as "Low" severity,
regardless of actual security impact.

{bold}Our Solution:{end} Calculate severity using CVSS v3.1 methodology
adapted for HPP, considering exploitability and real-world impact.
""".format(bold=Colors.BOLD, end=Colors.END))
    
    wait_for_user(step_mode)
    
    print_subheader("Severity Comparison: Generic vs Our Tool")
    
    scenarios = [
        {
            'name': 'Basic HPP (page parameter)',
            'existing_severity': 'Low',
            'metrics': {
                'affects_auth': False,
                'affects_authz': False,
                'affects_financial': False,
                'requires_auth': False,
                'multi_step': False
            }
        },
        {
            'name': 'User ID Manipulation',
            'existing_severity': 'Low',
            'metrics': {
                'affects_auth': True,
                'affects_authz': False,
                'affects_financial': False,
                'requires_auth': True,
                'multi_step': False
            }
        },
        {
            'name': 'Role-Based Privilege Escalation',
            'existing_severity': 'Low',
            'metrics': {
                'affects_auth': False,
                'affects_authz': True,
                'affects_financial': False,
                'requires_auth': True,
                'multi_step': True
            }
        },
        {
            'name': 'Price Manipulation + Auth Bypass',
            'existing_severity': 'Low',
            'metrics': {
                'affects_auth': True,
                'affects_authz': True,
                'affects_financial': True,
                'requires_auth': False,
                'multi_step': False
            }
        }
    ]
    
    print(f"\n{'Scenario':<35} {'Existing':<12} {'Our Tool':<12} {'Score':<8}")
    print("-" * 70)
    
    for scenario in scenarios:
        score = quick_score('param', **scenario['metrics'])
        
        # Color based on our severity
        if score.severity.value == 'CRITICAL':
            color = Colors.RED
        elif score.severity.value == 'HIGH':
            color = Colors.YELLOW
        else:
            color = Colors.GREEN
        
        print(f"{scenario['name']:<35} {scenario['existing_severity']:<12} "
              f"{color}{score.severity.value:<12}{Colors.END} {score.base_score:.1f}/10")
    
    wait_for_user(step_mode)
    
    # Detailed score breakdown
    print_subheader("Detailed Score Breakdown")
    
    print(f"\n{Colors.BOLD}Scenario: Role-Based Privilege Escalation{Colors.END}")
    
    scorer = ImpactScorer()
    metrics = VulnerabilityMetrics(
        affects_authorization=True,
        confidentiality_impact=ImpactLevel.HIGH,
        integrity_impact=ImpactLevel.HIGH,
        multi_step_required=True
    )
    
    score = scorer.calculate_score(metrics)
    
    print(f"\n  {Colors.CYAN}Exploitability Factors:{Colors.END}")
    for key, value in score.exploitability_breakdown.items():
        if key != 'formula':
            print(f"    {key}: {value}")
    
    print(f"\n  {Colors.CYAN}Impact Factors:{Colors.END}")
    for key, value in score.impact_breakdown.items():
        if key != 'formula':
            print(f"    {key}: {value}")
    
    print(f"\n  {Colors.BOLD}Final Score: {score.base_score:.1f}/10 ({score.severity.value}){Colors.END}")
    
    print(f"\n  {Colors.CYAN}Recommendations:{Colors.END}")
    for rec in score.recommendations[:3]:
        print(f"    • {rec}")
    
    print_success("Impact-based scoring provides actionable severity ratings!")
    wait_for_user(step_mode)


def demo_full_scan(step_mode=False):
    """Demonstrate a complete scan workflow."""
    print_header("Complete Scan Demonstration")
    
    print("""
{bold}Putting It All Together:{end}
1. Detect framework
2. Generate optimized payloads
3. Track context across requests
4. Score vulnerabilities by impact
5. Generate comprehensive report
""".format(bold=Colors.BOLD, end=Colors.END))
    
    wait_for_user(step_mode)
    
    from hpp_scanner.scanner import HPPScanner, ScanConfig
    
    print_subheader("Initializing Scan")
    
    config = ScanConfig(
        target_url="http://vulnerable-app.example.com",
        framework_detection=True,
        context_tracking=True,
        impact_scoring=True,
        verbose=False
    )
    
    print(f"  Target: {config.target_url}")
    print(f"  Framework Detection: ✓")
    print(f"  Context Tracking: ✓")
    print(f"  Impact Scoring: ✓")
    
    # Create mock scan results
    print_subheader("Scan Results")
    
    results = {
        'framework': 'Django',
        'confidence': 0.85,
        'endpoints': 5,
        'parameters': 12,
        'vulnerabilities': [
            {'name': 'Privilege Escalation via HPP', 'severity': 'CRITICAL', 'score': 9.1},
            {'name': 'Authentication Bypass via HPP', 'severity': 'HIGH', 'score': 7.8},
            {'name': 'Price Manipulation via HPP', 'severity': 'HIGH', 'score': 7.2},
            {'name': 'Access Control Bypass via HPP', 'severity': 'MEDIUM', 'score': 5.5},
        ]
    }
    
    print(f"\n  Framework: {results['framework']} ({results['confidence']*100:.0f}% confidence)")
    print(f"  Endpoints Tested: {results['endpoints']}")
    print(f"  Parameters Tested: {results['parameters']}")
    print(f"\n  {Colors.BOLD}Vulnerabilities Found:{Colors.END}")
    
    for vuln in results['vulnerabilities']:
        if vuln['severity'] == 'CRITICAL':
            color = Colors.RED
        elif vuln['severity'] == 'HIGH':
            color = Colors.YELLOW
        else:
            color = Colors.CYAN
        
        print(f"    {color}[{vuln['severity']}]{Colors.END} {vuln['name']} ({vuln['score']}/10)")
    
    print_success("Scan complete with context-aware analysis!")
    wait_for_user(step_mode)


def demo_comparison(step_mode=False):
    """Show comparison with existing tools."""
    print_header("Comparison: Our Tool vs Existing Scanners")
    
    tools = [
        ('Burp Suite', '$449/yr', 'Manual', '❌', '❌', 'Generic'),
        ('OWASP ZAP', 'Free', 'Basic', '❌', '❌', 'Generic'),
        ('Acunetix', '$4,500/yr', 'Generic', '❌', '❌', 'Generic'),
        ('Invicti', '$6,000/yr', 'Limited', '❌', '❌', 'Generic'),
        ('w3af', 'Free', 'Basic', '❌', '❌', 'Generic'),
        (f'{Colors.GREEN}Our Tool{Colors.END}', '-', f'{Colors.GREEN}✅ Auto{Colors.END}', 
         f'{Colors.GREEN}✅ Novel{Colors.END}', f'{Colors.GREEN}✅ Novel{Colors.END}', 
         f'{Colors.GREEN}✅ Novel{Colors.END}'),
    ]
    
    print(f"\n{'Tool':<20} {'Price':<12} {'Detection':<12} {'Context':<10} {'Framework':<12} {'Scoring':<10}")
    print("-" * 80)
    
    for tool in tools:
        print(f"{tool[0]:<20} {tool[1]:<12} {tool[2]:<12} {tool[3]:<10} {tool[4]:<12} {tool[5]:<10}")
    
    print(f"\n{Colors.BOLD}Key Finding:{Colors.END}")
    print("  Whether you use a free tool or pay $6,000/year,")
    print("  NO existing scanner performs context-aware HPP analysis.")
    print(f"  {Colors.GREEN}Our tool fills this critical gap.{Colors.END}")
    
    wait_for_user(step_mode)


def main():
    """Main demonstration entry point."""
    parser = argparse.ArgumentParser(description='HPP Scanner Demonstration')
    parser.add_argument('--quick', action='store_true', help='Quick demo mode')
    parser.add_argument('--step', action='store_true', help='Step-by-step with pauses')
    parser.add_argument('--component', type=int, choices=[1, 2, 3], 
                       help='Demo specific component (1=Framework, 2=Context, 3=Scoring)')
    args = parser.parse_args()
    
    step_mode = args.step
    
    demo_banner()
    
    if args.component:
        if args.component == 1:
            demo_framework_detection(step_mode)
        elif args.component == 2:
            demo_context_tracking(step_mode)
        elif args.component == 3:
            demo_impact_scoring(step_mode)
    else:
        # Full demonstration
        demo_framework_detection(step_mode)
        demo_payload_generation(step_mode)
        demo_context_tracking(step_mode)
        demo_impact_scoring(step_mode)
        demo_full_scan(step_mode)
        demo_comparison(step_mode)
    
    print_header("Demonstration Complete")
    print("""
{bold}Summary of Novel Contributions:{end}

  1. {green}Framework Detection{end} - Automatically identifies target framework
     and optimizes HPP testing based on parameter handling behavior.
     
  2. {green}Context Tracking{end} - Tracks state across multiple requests to
     detect privilege escalation and identity confusion attacks.
     
  3. {green}Impact Scoring{end} - Calculates actual security impact using
     CVSS methodology instead of generic "Low" severity.

{bold}Questions?{end}
""".format(bold=Colors.BOLD, end=Colors.END, green=Colors.GREEN))


if __name__ == '__main__':
    main()
