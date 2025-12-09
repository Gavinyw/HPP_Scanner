#!/usr/bin/env python3
"""
Simple script to run HPP Scanner on the vulnerable Flask app.

Usage:
    python run_scanner.py
"""

from hpp_scanner.scanner import HPPScanner, ScanConfig

def main():
    print("=" * 70)
    print("  HPP Scanner - Testing Vulnerable Flask App")
    print("=" * 70)
    print()
    print("Target: http://127.0.0.1:5000/checkout")
    print()
    print("Make sure the Flask app is running first:")
    print("  python vulnerable_flask_app.py")
    print()
    print("=" * 70)
    print()

    # Configure scanner
    config = ScanConfig(
        target_url='http://127.0.0.1:5000/checkout',
        verbose=True,
        framework_detection=True,
        context_tracking=True,
        impact_scoring=True
    )

    # Create scanner
    scanner = HPPScanner('http://127.0.0.1:5000/checkout', config)

    # Define test endpoints
    endpoints = [
        {
            'url': 'http://127.0.0.1:5000/checkout',
            'method': 'GET',
            'params': {'item': 'laptop', 'price': '999', 'quantity': '1'}
        }
    ]

    # Run scan
    vulnerabilities = scanner.scan(endpoints=endpoints)

    # Show results
    print()
    print("=" * 70)
    print(f"  SCAN COMPLETE - Found {len(vulnerabilities)} vulnerabilities")
    print("=" * 70)
    print()

    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i}. {vuln.name}")
            print(f"   Parameter:  {vuln.parameter}")
            print(f"   Endpoint:   {vuln.endpoint}")
            print(f"   Method:     {vuln.method}")
            print(f"   Framework:  {vuln.framework}")
            print(f"   Severity:   {vuln.severity}")
            if vuln.score:
                score = vuln.score.get('base_score', 'N/A')
                print(f"   CVSS Score: {score}")
            print()
    else:
        print("[!] No vulnerabilities detected")
        print()

    # Summary
    summary = scanner.get_summary()
    print()
    print("=" * 70)
    print("  Scan Summary")
    print("=" * 70)
    print(f"Framework Detected:  {summary['framework']['detected']}")
    print(f"Confidence:          {summary['framework']['confidence']*100:.0f}%")
    print(f"Endpoints Tested:    {summary['coverage']['endpoints']}")
    print(f"Parameters Tested:   {summary['coverage']['parameters']}")
    print(f"Total Findings:      {summary['findings']['total']}")
    print(f"Scan Duration:       {summary['scan_duration']:.2f}s")
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        print()
        print("Make sure the Flask app is running:")
        print("  python vulnerable_flask_app.py")
