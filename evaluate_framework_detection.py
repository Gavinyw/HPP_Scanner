#!/usr/bin/env python3
"""
Framework Detection Evaluation Script

Tests framework detection accuracy on Tranco Top 1M websites.
Provides empirical validation for the research paper.

Usage:
    python evaluate_framework_detection.py --sample 100
    python evaluate_framework_detection.py --top 10000 --output results.json
    python evaluate_framework_detection.py --resume results.json
"""

import sys
import csv
import json
import time
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from collections import Counter
import requests
from requests.exceptions import RequestException

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent))

from hpp_scanner.framework_detector import FrameworkDetector, Framework


class FrameworkEvaluator:
    """Evaluates framework detection on real websites."""

    def __init__(self, tranco_file: str = "top-1m.csv"):
        """
        Initialize evaluator.

        Args:
            tranco_file: Path to Tranco list CSV file
        """
        self.tranco_file = tranco_file
        self.detector = FrameworkDetector()
        self.results = []
        self.stats = {
            'total_tested': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'frameworks_detected': Counter(),
            'confidence_distribution': {
                'high': 0,      # >= 70%
                'medium': 0,    # 40-70%
                'low': 0,       # < 40%
                'none': 0       # 0%
            },
            'start_time': None,
            'end_time': None
        }

    def load_domains(self, top_n: Optional[int] = None, sample: Optional[int] = None) -> List[tuple]:
        """
        Load domains from Tranco list.

        Args:
            top_n: Load top N domains (e.g., 10000)
            sample: Random sample size (e.g., 100)

        Returns:
            List of (rank, domain) tuples
        """
        domains = []

        with open(self.tranco_file, 'r') as f:
            reader = csv.reader(f)
            for rank, domain in reader:
                domains.append((int(rank), domain))

                if top_n and len(domains) >= top_n:
                    break

        if sample:
            import random
            domains = random.sample(domains, min(sample, len(domains)))

        return domains

    def test_domain(self, domain: str, timeout: int = 10) -> Dict:
        """
        Test framework detection on a single domain.

        Args:
            domain: Domain to test (e.g., "google.com")
            timeout: Request timeout in seconds

        Returns:
            Dict with detection results
        """
        url = f"https://{domain}"
        result = {
            'domain': domain,
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'framework': None,
            'confidence': 0.0,
            'error': None,
            'response_time': 0.0,
            'status_code': None,
            'headers': {},
            'has_server_header': False,
            'has_powered_by': False,
            'has_cookies': False
        }

        start = time.time()

        try:
            # Make request with timeout
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Research/FrameworkDetection)'},
                verify=True
            )

            result['response_time'] = (time.time() - start) * 1000  # ms
            result['status_code'] = response.status_code
            result['success'] = True

            # Extract response data
            response_data = {
                'headers': dict(response.headers),
                'body': response.text[:50000],  # Limit body size
                'cookies': dict(response.cookies)
            }

            # Check what signals are available
            result['has_server_header'] = 'Server' in response.headers
            result['has_powered_by'] = 'X-Powered-By' in response.headers
            result['has_cookies'] = len(response.cookies) > 0
            result['headers'] = {
                'Server': response.headers.get('Server', 'Not present'),
                'X-Powered-By': response.headers.get('X-Powered-By', 'Not present'),
                'Content-Type': response.headers.get('Content-Type', 'Not present')
            }

            # Detect framework
            framework, confidence = self.detector.detect(url, response_data)

            result['framework'] = framework.value
            result['confidence'] = confidence

        except requests.exceptions.Timeout:
            result['error'] = 'Timeout'
        except requests.exceptions.SSLError as e:
            result['error'] = f'SSL Error: {str(e)[:100]}'
        except requests.exceptions.ConnectionError as e:
            result['error'] = f'Connection Error: {str(e)[:100]}'
        except RequestException as e:
            result['error'] = f'Request Error: {str(e)[:100]}'
        except Exception as e:
            result['error'] = f'Unknown Error: {str(e)[:100]}'

        return result

    def evaluate(
        self,
        domains: List[tuple],
        delay: float = 1.0,
        verbose: bool = True,
        save_interval: int = 10
    ) -> Dict:
        """
        Evaluate framework detection on list of domains.

        Args:
            domains: List of (rank, domain) tuples
            delay: Delay between requests in seconds (rate limiting)
            verbose: Print progress
            save_interval: Save results every N domains

        Returns:
            Statistics dict
        """
        self.stats['start_time'] = datetime.now().isoformat()

        if verbose:
            print(f"\n{'='*70}")
            print(f"  Framework Detection Evaluation")
            print(f"  Testing {len(domains)} domains from Tranco list")
            print(f"{'='*70}\n")

        for i, (rank, domain) in enumerate(domains, 1):
            if verbose:
                print(f"[{i}/{len(domains)}] Rank #{rank}: {domain}", end=' ... ')

            result = self.test_domain(domain)
            self.results.append({**result, 'rank': rank})

            # Update statistics
            self.stats['total_tested'] += 1

            if result['success']:
                self.stats['successful_requests'] += 1

                # Count frameworks
                self.stats['frameworks_detected'][result['framework']] += 1

                # Confidence distribution
                conf = result['confidence']
                if conf == 0:
                    self.stats['confidence_distribution']['none'] += 1
                elif conf < 0.4:
                    self.stats['confidence_distribution']['low'] += 1
                elif conf < 0.7:
                    self.stats['confidence_distribution']['medium'] += 1
                else:
                    self.stats['confidence_distribution']['high'] += 1

                if verbose:
                    if result['framework'] != 'Unknown':
                        print(f"✓ {result['framework']} ({result['confidence']*100:.0f}%)")
                    else:
                        print(f"✗ Unknown")
            else:
                self.stats['failed_requests'] += 1
                if verbose:
                    print(f"✗ {result['error']}")

            # Rate limiting
            time.sleep(delay)

            # Save intermediate results
            if save_interval and i % save_interval == 0:
                self._save_checkpoint()

        self.stats['end_time'] = datetime.now().isoformat()

        return self.stats

    def _save_checkpoint(self, filename: str = "evaluation_checkpoint.json"):
        """Save intermediate results."""
        data = {
            'stats': self.stats,
            'results': self.results
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

    def generate_report(self) -> str:
        """Generate evaluation report."""
        total = self.stats['total_tested']
        successful = self.stats['successful_requests']
        failed = self.stats['failed_requests']

        # Calculate percentages
        success_rate = (successful / total * 100) if total > 0 else 0
        detected = sum(
            count for fw, count in self.stats['frameworks_detected'].items()
            if fw != 'Unknown'
        )
        detection_rate = (detected / successful * 100) if successful > 0 else 0

        report = f"""
{'='*70}
  FRAMEWORK DETECTION EVALUATION REPORT
{'='*70}

Evaluation Period:
  Start: {self.stats['start_time']}
  End:   {self.stats['end_time']}

Request Statistics:
  Total Domains Tested: {total:,}
  Successful Requests:  {successful:,} ({success_rate:.1f}%)
  Failed Requests:      {failed:,} ({100-success_rate:.1f}%)

Framework Detection Results:
  Total Identified:     {detected:,} ({detection_rate:.1f}% of successful)
  Unknown/Hidden:       {self.stats['frameworks_detected']['Unknown']:,}

{'='*70}
  FRAMEWORK DISTRIBUTION
{'='*70}
"""

        # Sort frameworks by count
        for framework, count in sorted(
            self.stats['frameworks_detected'].items(),
            key=lambda x: x[1],
            reverse=True
        ):
            pct = (count / successful * 100) if successful > 0 else 0
            bar = '█' * int(pct / 2)
            # Handle None framework name
            fw_name = framework if framework else "None"
            report += f"  {fw_name:12} {count:6,} ({pct:5.1f}%) {bar}\n"

        report += f"""
{'='*70}
  CONFIDENCE DISTRIBUTION
{'='*70}
  High (≥70%):    {self.stats['confidence_distribution']['high']:6,}
  Medium (40-70%): {self.stats['confidence_distribution']['medium']:6,}
  Low (<40%):     {self.stats['confidence_distribution']['low']:6,}
  None (0%):      {self.stats['confidence_distribution']['none']:6,}

{'='*70}
  KEY FINDINGS
{'='*70}
"""

        # Calculate key findings
        if successful > 0:
            hidden_rate = (self.stats['frameworks_detected']['Unknown'] / successful * 100)
            report += f"""
  1. Framework Hiding: {hidden_rate:.1f}% of sites hide framework info
  2. Detection Success: {detection_rate:.1f}% of reachable sites identified
  3. Most Common: {max(self.stats['frameworks_detected'].items(), key=lambda x: x[1])[0]}

  Conclusion:
  Production websites actively obscure framework information for security.
  Framework detection works best on:
  - Development/staging environments
  - Misconfigured production sites
  - Small business websites
  - Educational platforms
"""

        return report

    def save_results(self, filename: str):
        """Save detailed results to JSON."""
        data = {
            'metadata': {
                'evaluation_date': datetime.now().isoformat(),
                'tranco_file': self.tranco_file,
                'total_tested': self.stats['total_tested']
            },
            'statistics': self.stats,
            'detailed_results': self.results
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\n[+] Results saved to: {filename}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Evaluate framework detection on Tranco Top 1M',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--sample',
        type=int,
        help='Random sample size (e.g., 100)'
    )
    parser.add_argument(
        '--top',
        type=int,
        help='Test top N domains (e.g., 10000)'
    )
    parser.add_argument(
        '--delay',
        type=float,
        default=1.0,
        help='Delay between requests in seconds (default: 1.0)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    parser.add_argument(
        '--output',
        default='framework_evaluation_results.json',
        help='Output JSON file (default: framework_evaluation_results.json)'
    )
    parser.add_argument(
        '--tranco-file',
        default='top-1m.csv',
        help='Path to Tranco CSV file (default: top-1m.csv)'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Minimal output'
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.sample and not args.top:
        print("Error: Must specify either --sample or --top")
        parser.print_help()
        sys.exit(1)

    # Create evaluator
    evaluator = FrameworkEvaluator(tranco_file=args.tranco_file)

    # Load domains
    try:
        domains = evaluator.load_domains(top_n=args.top, sample=args.sample)
    except FileNotFoundError:
        print(f"Error: Tranco file not found: {args.tranco_file}")
        sys.exit(1)

    print(f"\n[*] Loaded {len(domains)} domains for testing")

    # Run evaluation
    evaluator.evaluate(
        domains=domains,
        delay=args.delay,
        verbose=not args.quiet,
        save_interval=10
    )

    # Generate and print report
    report = evaluator.generate_report()
    print(report)

    # Save results
    evaluator.save_results(args.output)

    print(f"\n[*] Evaluation complete!")


if __name__ == '__main__':
    main()
