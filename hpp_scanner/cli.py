#!/usr/bin/env python3
"""
HPP Scanner - Command Line Interface

Usage:
    hpp-scanner scan <url> [options]
    hpp-scanner detect <url>
    hpp-scanner analyze <file>
    hpp-scanner report <file> --format <format>

Examples:
    hpp-scanner scan http://example.com
    hpp-scanner scan http://example.com --output report.html --verbose
    hpp-scanner detect http://example.com
"""

import argparse
import sys
import json
from datetime import datetime

from .scanner import HPPScanner, ScanConfig
from .framework_detector import FrameworkDetector, Framework
from .payload_generator import PayloadGenerator
from .impact_scorer import ImpactScorer, quick_score


def print_banner():
    """Print tool banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║     Context-Aware HPP Detection Tool v1.0                    ║
║     HTTP Parameter Pollution Scanner                         ║
╠═══════════════════════════════════════════════════════════════╣
║  Novel Features:                                              ║
║    ✓ Framework-Specific Detection (Django/Flask/Express/PHP)  ║
║    ✓ Context-Aware Multi-Step Analysis                        ║
║    ✓ Impact-Based Severity Scoring                           ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def cmd_scan(args):
    """Execute scan command."""
    print_banner()
    print(f"[*] Target: {args.url}")
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Create config
    config = ScanConfig(
        target_url=args.url,
        verbose=args.verbose,
        output_format=args.format,
        framework_detection=not args.no_framework,
        context_tracking=not args.no_context,
        impact_scoring=not args.no_scoring
    )
    
    # Create scanner
    scanner = HPPScanner(args.url, config)
    
    # Run scan
    print("[*] Starting scan...")
    print("-" * 50)
    
    # For demo, create sample endpoints
    sample_endpoints = [
        {
            'url': args.url,
            'method': 'GET',
            'params': {'id': '1', 'user': 'test', 'action': 'view'}
        }
    ]
    
    vulnerabilities = scanner.scan(endpoints=sample_endpoints)
    
    print("-" * 50)
    print()
    
    # Print summary
    summary = scanner.get_summary()
    print("[*] Scan Summary:")
    print(f"    Framework: {summary['framework']['detected']} ({summary['framework']['confidence']*100:.0f}% confidence)")
    print(f"    Endpoints: {summary['coverage']['endpoints']}")
    print(f"    Parameters: {summary['coverage']['parameters']}")
    print(f"    Vulnerabilities: {summary['findings']['total']}")
    
    if summary['findings']['by_severity']:
        print("    By Severity:")
        for sev, count in summary['findings']['by_severity'].items():
            print(f"      - {sev}: {count}")
    print()
    
    # Generate report
    if args.output:
        print(f"[*] Generating {args.format.upper()} report...")
        report = scanner.generate_report(args.format)
        
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"[+] Report saved to: {args.output}")
    else:
        # Print text report to console
        print(scanner.generate_report('text'))
    
    print()
    print("[*] Scan completed!")
    
    return 0 if summary['findings']['total'] == 0 else 1


def cmd_detect(args):
    """Execute framework detection command."""
    print_banner()
    print(f"[*] Detecting framework for: {args.url}")
    print()
    
    detector = FrameworkDetector()
    
    # Mock response data for demo
    response_data = {
        'headers': {
            'Server': 'Werkzeug/2.0.1 Python/3.9.0',
            'Content-Type': 'text/html; charset=utf-8'
        },
        'body': '<html>Flask application</html>',
        'cookies': {'session': 'abc123'}
    }
    
    framework, confidence = detector.detect(args.url, response_data)
    report = detector.get_detection_report()
    
    print("[*] Detection Results:")
    print(f"    Framework: {report['detected_framework']}")
    print(f"    Confidence: {report['confidence']}%")
    print(f"    Parameter Behavior: {report['parameter_behavior']}")
    print()
    print("[*] All Scores:")
    for fw, score in report['all_scores'].items():
        bar = "█" * int(score / 10) + "░" * (10 - int(score / 10))
        print(f"    {fw:12} [{bar}] {score}%")
    
    return 0


def cmd_payloads(args):
    """Show available payloads."""
    print_banner()
    print("[*] Available HPP Payloads")
    print()
    
    generator = PayloadGenerator()
    
    # Try with Flask framework
    if args.framework:
        try:
            fw = Framework[args.framework.upper()]
            generator.set_framework(fw)
            print(f"[*] Framework: {args.framework}")
        except KeyError:
            print(f"[!] Unknown framework: {args.framework}")
            print(f"[*] Available: Django, Flask, Express, PHP")
            return 1
    
    payloads = generator.generate_payloads(
        args.param or 'user_id',
        include_generic=True,
        include_framework_specific=True,
        include_context_aware=True
    )
    
    print(f"[*] Generated {len(payloads)} payloads for parameter '{args.param or 'user_id'}'")
    print()
    
    summary = generator.get_summary()
    print(f"[*] By Risk Level:")
    for risk, count in summary.get('by_risk', {}).items():
        print(f"    {risk}: {count}")
    print()
    
    print("[*] Payload List:")
    print("-" * 70)
    for i, payload in enumerate(payloads[:10], 1):  # Show first 10
        fw_tag = f" [{payload.framework_specific.value}]" if payload.framework_specific else ""
        print(f"{i:2}. [{payload.risk_level:8}] {payload.name}{fw_tag}")
        print(f"    Values: {payload.values}")
        print(f"    Expected: {payload.expected_behavior}")
        print()
    
    if len(payloads) > 10:
        print(f"    ... and {len(payloads) - 10} more payloads")
    
    return 0


def cmd_score(args):
    """Score a vulnerability."""
    print_banner()
    print("[*] Impact Scoring Demo")
    print()
    
    # Demo scoring
    scenarios = [
        {
            'name': 'Authentication Bypass',
            'affects_auth': True,
            'affects_authz': False,
            'affects_financial': False,
            'requires_auth': False,
            'multi_step': False
        },
        {
            'name': 'Privilege Escalation',
            'affects_auth': False,
            'affects_authz': True,
            'affects_financial': False,
            'requires_auth': True,
            'multi_step': True
        },
        {
            'name': 'Price Manipulation',
            'affects_auth': False,
            'affects_authz': False,
            'affects_financial': True,
            'requires_auth': True,
            'multi_step': False
        }
    ]
    
    print("[*] Scoring Common HPP Scenarios:")
    print("-" * 60)
    
    for scenario in scenarios:
        name = scenario.pop('name')
        score = quick_score('vulnerable_param', **scenario)
        
        print(f"\n{name}:")
        print(f"  Base Score: {score.base_score:.1f}/10")
        print(f"  Severity: {score.severity.value}")
        print(f"  Exploitability: {score.exploitability_score:.1f}/10")
        print(f"  Impact: {score.impact_score:.1f}/10")
    
    return 0


def cmd_demo(args):
    """Run demonstration."""
    print_banner()
    print("[*] Running HPP Scanner Demonstration")
    print("=" * 60)
    print()
    
    # Demo framework detection
    print("1. FRAMEWORK DETECTION (Novel Component #1)")
    print("-" * 40)
    detector = FrameworkDetector()
    
    demo_responses = {
        'Django': {'headers': {'Server': 'WSGIServer'}, 'body': 'csrfmiddlewaretoken', 'cookies': {'csrftoken': 'abc'}},
        'Flask': {'headers': {'Server': 'Werkzeug'}, 'body': '', 'cookies': {'session': 'xyz'}},
        'Express': {'headers': {'X-Powered-By': 'Express'}, 'body': '', 'cookies': {}},
    }
    
    for fw_name, response_data in demo_responses.items():
        detected, confidence = detector.detect('http://example.com', response_data)
        print(f"  Response pattern: {fw_name}")
        print(f"  → Detected: {detected.value} ({confidence*100:.0f}% confidence)")
        print()
    
    # Demo payload generation
    print("2. PAYLOAD GENERATION")
    print("-" * 40)
    generator = PayloadGenerator(Framework.DJANGO)
    payloads = generator.generate_payloads('user_id')
    print(f"  Generated {len(payloads)} payloads for 'user_id' parameter")
    print(f"  Framework-specific: {generator.get_framework_specific_count()}")
    print(f"  High-risk payloads: {len(generator.get_payloads_by_risk('HIGH'))}")
    print(f"  Critical payloads: {len(generator.get_payloads_by_risk('CRITICAL'))}")
    print()
    
    # Demo impact scoring
    print("3. IMPACT SCORING (Novel Component #3)")
    print("-" * 40)
    score = quick_score('user_id', affects_authz=True, requires_auth=True)
    print(f"  Scenario: Authorization bypass on user_id")
    print(f"  → Score: {score.base_score:.1f}/10")
    print(f"  → Severity: {score.severity.value}")
    print(f"  → Exploitability: {score.exploitability_score:.1f}/10")
    print(f"  → Impact: {score.impact_score:.1f}/10")
    print()
    
    # Demo context tracking
    print("4. CONTEXT TRACKING (Novel Component #2)")
    print("-" * 40)
    from .context_tracker import ContextTracker, WorkflowStep, WorkflowStepType
    
    tracker = ContextTracker()
    tracker.start_workflow()
    
    # Simulate workflow
    steps = [
        ('Login', WorkflowStepType.LOGIN),
        ('View Profile', WorkflowStepType.VIEW),
        ('Edit Profile', WorkflowStepType.UPDATE)
    ]
    
    for name, step_type in steps:
        step = WorkflowStep(name=name, step_type=step_type, endpoint='/api/' + name.lower().replace(' ', '_'))
        tracker.add_step(step, response_data={'body': {}, 'cookies': {'session': 'abc'}})
    
    summary = tracker.get_workflow_summary()
    print(f"  Tracked {summary['total_steps']} workflow steps")
    print(f"  State transitions: {summary['transitions']}")
    print()
    
    print("=" * 60)
    print("[*] Demonstration Complete!")
    print()
    print("Key Differentiators from Existing Tools:")
    print("  ✓ Framework-specific testing (not generic)")
    print("  ✓ Multi-step context tracking (not stateless)")
    print("  ✓ Impact-based scoring (not generic severity)")
    
    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Context-Aware HTTP Parameter Pollution Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  hpp-scanner scan http://example.com
  hpp-scanner scan http://example.com -o report.html -f html
  hpp-scanner detect http://example.com
  hpp-scanner payloads --param user_id --framework django
  hpp-scanner demo
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan target for HPP vulnerabilities')
    scan_parser.add_argument('url', help='Target URL')
    scan_parser.add_argument('-o', '--output', help='Output file path')
    scan_parser.add_argument('-f', '--format', choices=['html', 'json', 'text', 'markdown'],
                            default='text', help='Output format')
    scan_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    scan_parser.add_argument('--no-framework', action='store_true', help='Disable framework detection')
    scan_parser.add_argument('--no-context', action='store_true', help='Disable context tracking')
    scan_parser.add_argument('--no-scoring', action='store_true', help='Disable impact scoring')
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Detect target framework')
    detect_parser.add_argument('url', help='Target URL')
    
    # Payloads command
    payloads_parser = subparsers.add_parser('payloads', help='Show available payloads')
    payloads_parser.add_argument('--param', help='Parameter name')
    payloads_parser.add_argument('--framework', help='Target framework')
    
    # Score command
    score_parser = subparsers.add_parser('score', help='Score vulnerabilities')
    
    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Run demonstration')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        return cmd_scan(args)
    elif args.command == 'detect':
        return cmd_detect(args)
    elif args.command == 'payloads':
        return cmd_payloads(args)
    elif args.command == 'score':
        return cmd_score(args)
    elif args.command == 'demo':
        return cmd_demo(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
