#!/usr/bin/env python3
"""
Test framework detection on real websites from Tranco list.

This script evaluates:
1. Detection success rate
2. Confidence distribution
3. Framework breakdown
4. False positive analysis
"""

import csv
import time
import requests
from hpp_scanner.framework_detector import FrameworkDetector, Framework

def test_website(url, timeout=10):
    """
    Test framework detection on a single website.

    Returns:
        dict with detection results
    """
    detector = FrameworkDetector()

    # Add https:// prefix
    if not url.startswith('http'):
        test_url = f'https://{url}'
    else:
        test_url = url

    try:
        # Fetch homepage
        response = requests.get(
            test_url,
            timeout=timeout,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; HPP-Scanner/1.0)'},
            verify=True
        )

        # Prepare response data for detector
        response_data = {
            'headers': dict(response.headers),
            'body': response.text[:50000],  # Limit body size
            'cookies': dict(response.cookies)
        }

        # Detect with make_request function for active fingerprinting
        def make_request(url, method, params):
            try:
                if method == 'GET':
                    if isinstance(params, list):
                        # Handle duplicate params
                        from urllib.parse import quote
                        query_parts = [f"{quote(str(k))}={quote(str(v))}" for k, v in params]
                        query = '&'.join(query_parts)
                        full_url = f"{url}?{query}" if query else url
                    else:
                        full_url = url

                    resp = requests.get(full_url, timeout=5, allow_redirects=False, verify=True)

                    # Mock ResponseData
                    class ResponseData:
                        def __init__(self, status_code, headers, body, cookies, url):
                            self.status_code = status_code
                            self.headers = headers
                            self.body = body
                            self.cookies = cookies
                            self.url = url

                    return ResponseData(
                        status_code=resp.status_code,
                        headers=dict(resp.headers),
                        body=resp.text[:10000],
                        cookies=dict(resp.cookies),
                        url=resp.url
                    )
            except:
                # Mock failed response
                class ResponseData:
                    status_code = 0
                    headers = {}
                    body = ""
                    cookies = {}
                    url = url
                return ResponseData()

        # Run detection
        framework, confidence = detector.detect(test_url, response_data, make_request)

        return {
            'url': url,
            'status': 'success',
            'framework': framework.value,
            'confidence': confidence,
            'status_code': response.status_code,
            'all_scores': detector.detection_results
        }

    except requests.exceptions.Timeout:
        return {'url': url, 'status': 'timeout', 'framework': 'Unknown', 'confidence': 0.0}
    except requests.exceptions.ConnectionError:
        return {'url': url, 'status': 'connection_error', 'framework': 'Unknown', 'confidence': 0.0}
    except Exception as e:
        return {'url': url, 'status': f'error: {str(e)[:50]}', 'framework': 'Unknown', 'confidence': 0.0}


def main():
    print("=" * 80)
    print("  FRAMEWORK DETECTION EVALUATION ON REAL WEBSITES")
    print("=" * 80)
    print()

    # Read top 50 sites from Tranco list
    print("[*] Reading Tranco list...")
    sites = []
    with open('top-1m.csv', 'r') as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if i >= 50:  # Test top 50 only (to be quick)
                break
            if len(row) >= 2:
                sites.append(row[1])

    print(f"[*] Testing {len(sites)} websites...")
    print()

    results = []
    for i, site in enumerate(sites, 1):
        print(f"[{i}/{len(sites)}] Testing {site}...", end=' ', flush=True)

        result = test_website(site)
        results.append(result)

        if result['status'] == 'success':
            print(f"✓ {result['framework']} ({result['confidence']*100:.0f}%)")
        else:
            print(f"✗ {result['status']}")

        # Small delay to be polite
        time.sleep(0.5)

    # Analysis
    print()
    print("=" * 80)
    print("  RESULTS ANALYSIS")
    print("=" * 80)
    print()

    successful = [r for r in results if r['status'] == 'success']
    detected = [r for r in successful if r['framework'] != 'Unknown']
    high_conf = [r for r in detected if r['confidence'] >= 0.5]
    medium_conf = [r for r in detected if 0.3 <= r['confidence'] < 0.5]
    low_conf = [r for r in detected if r['confidence'] < 0.3]

    print(f"Total Sites Tested:     {len(results)}")
    print(f"Successfully Accessed:  {len(successful)} ({len(successful)/len(results)*100:.1f}%)")
    print(f"Framework Detected:     {len(detected)} ({len(detected)/len(successful)*100:.1f}% of accessible)")
    print(f"Marked as Unknown:      {len(successful) - len(detected)}")
    print()

    print("Confidence Distribution:")
    print(f"  High (≥50%):    {len(high_conf)} ({len(high_conf)/len(detected)*100:.1f}% of detected)")
    print(f"  Medium (30-50%): {len(medium_conf)} ({len(medium_conf)/len(detected)*100:.1f}% of detected)")
    print(f"  Low (<30%):     {len(low_conf)} ({len(low_conf)/len(detected)*100:.1f}% of detected)")
    print()

    # Framework breakdown
    framework_counts = {}
    for r in detected:
        fw = r['framework']
        framework_counts[fw] = framework_counts.get(fw, 0) + 1

    print("Framework Breakdown:")
    for fw, count in sorted(framework_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {fw:15s} {count:3d} ({count/len(detected)*100:.1f}%)")
    print()

    # Show high confidence detections
    print("High Confidence Detections (≥50%):")
    for r in sorted(high_conf, key=lambda x: x['confidence'], reverse=True)[:10]:
        print(f"  {r['url']:30s} → {r['framework']:10s} ({r['confidence']*100:.0f}%)")
    print()

    # Show potential false positives (low confidence)
    print("Potential False Positives (confidence <30%):")
    for r in sorted(low_conf, key=lambda x: x['confidence'])[:10]:
        print(f"  {r['url']:30s} → {r['framework']:10s} ({r['confidence']*100:.0f}%)")
    print()

    # Average confidence by framework
    print("Average Confidence by Framework:")
    for fw in framework_counts.keys():
        fw_results = [r for r in detected if r['framework'] == fw]
        avg_conf = sum(r['confidence'] for r in fw_results) / len(fw_results)
        print(f"  {fw:15s} {avg_conf*100:.1f}%")
    print()

    print("=" * 80)
    print("  RELIABILITY ASSESSMENT")
    print("=" * 80)
    print()

    print("Key Findings:")
    print()
    print("1. Detection Success Rate:")
    if len(detected) / len(successful) > 0.3:
        print(f"   ✓ GOOD: {len(detected)/len(successful)*100:.0f}% of sites had frameworks detected")
    else:
        print(f"   ⚠ LOW: Only {len(detected)/len(successful)*100:.0f}% detection rate")
    print()

    print("2. Confidence Distribution:")
    if len(high_conf) / len(detected) > 0.4:
        print(f"   ✓ RELIABLE: {len(high_conf)/len(detected)*100:.0f}% have high confidence")
    else:
        print(f"   ⚠ UNCERTAIN: Only {len(high_conf)/len(detected)*100:.0f}% have high confidence")
    print()

    print("3. False Positive Risk:")
    if len(low_conf) / len(detected) < 0.3:
        print(f"   ✓ LOW RISK: {len(low_conf)/len(detected)*100:.0f}% are low confidence")
    else:
        print(f"   ⚠ HIGH RISK: {len(low_conf)/len(detected)*100:.0f}% might be false positives")
    print()

    print("Recommendations:")
    print("  - Use confidence ≥50% for high-confidence scanning")
    print("  - Manually verify detections with confidence <30%")
    print("  - Most big sites strip headers → expect 30-50% confidence")
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
