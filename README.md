# HPP Scanner

A context-aware HTTP Parameter Pollution (HPP) vulnerability scanner with framework detection, multi-step context tracking, and CVSS-based impact scoring.

## What is HPP?

HTTP Parameter Pollution (HPP) occurs when an attacker sends multiple parameters with the same name. Different web frameworks handle duplicate parameters differently:

- **Flask/Python**: Uses FIRST value
- **Django/PHP**: Uses LAST value
- **Express/Node.js**: Creates ARRAY
- **ASP.NET**: CONCATENATES values

This inconsistency can lead to security vulnerabilities like privilege escalation, price manipulation, and authentication bypass.

## Installation

```bash
# Clone the repository
git clone https://github.com/Gavinyw/HPP_Scanner.git
cd HPP_Scanner

# Install the package
pip install -e .
```

## Quick Start

### 1. Run the Vulnerable Flask App

First, start the intentionally vulnerable Flask e-commerce application:

```bash
python vulnerable_flask_app.py
```

The app will start on `http://127.0.0.1:5000`

**What the app does:**
- Provides a demo e-commerce site with products
- Contains an intentional HPP vulnerability in the checkout endpoint
- Displays price manipulation attacks visually

**Try the attack manually:**
1. Open `http://127.0.0.1:5000` in your browser
2. Click "Buy Now" on the $999 laptop
3. Modify the URL to: `http://127.0.0.1:5000/checkout?item=laptop&price=1&price=999`
4. See the HPP attack succeed - charged $1 but displays $999!

### 2. Run the Scanner Against the Flask App

In a new terminal, run the scanner:

```bash
python run_scanner.py
```

**What this does:**
- Scans the vulnerable Flask checkout endpoint
- Automatically detects the Flask framework
- Tests HPP payloads (price manipulation, privilege escalation, etc.)
- Reports vulnerabilities with CVSS scores

**Expected output:**
```
====================================================================
  HPP Scanner - Testing Vulnerable Flask App
====================================================================

Target: http://127.0.0.1:5000/checkout
...
====================================================================
  SCAN COMPLETE - Found X vulnerabilities
====================================================================

1. Price Manipulation via HPP
   Parameter:  price
   Endpoint:   http://127.0.0.1:5000/checkout
   Method:     GET
   Framework:  Flask
   Severity:   HIGH
   CVSS Score: 7.5
```

### 3. Test Real-World Framework Detection

Test the framework detector on real websites from the Tranco top sites list:

```bash
python test_real_world_detection.py
```

**What this does:**
- Tests framework detection on the top 50 websites from the Tranco list
- Evaluates detection accuracy and confidence levels
- Shows which frameworks are most commonly detected
- Provides reliability assessment

**Expected output:**
```
====================================================================
  FRAMEWORK DETECTION EVALUATION ON REAL WEBSITES
====================================================================

[*] Testing 50 websites...

[1/50] Testing google.com... ✓ Unknown (0%)
[2/50] Testing facebook.com... ✓ PHP (65%)
...

====================================================================
  RESULTS ANALYSIS
====================================================================

Total Sites Tested:     50
Successfully Accessed:  45 (90.0%)
Framework Detected:     25 (55.6% of accessible)

Confidence Distribution:
  High (≥50%):    15 (60.0% of detected)
  Medium (30-50%): 7 (28.0% of detected)
  Low (<30%):     3 (12.0% of detected)

Framework Breakdown:
  PHP             10 (40.0%)
  Django           6 (24.0%)
  Express          5 (20.0%)
  Flask            4 (16.0%)
```

## Project Structure

```
HPP_Scanner/
├── hpp_scanner/              # Main package
│   ├── scanner.py           # Core scanner (integrates all components)
│   ├── framework_detector.py # Framework detection engine
│   ├── context_tracker.py   # Multi-step workflow analysis
│   ├── impact_scorer.py     # CVSS-based severity scoring
│   ├── payload_generator.py # HPP payload generation
│   └── ...
├── run_scanner.py           # Run scanner on Flask app
├── vulnerable_flask_app.py  # Demo vulnerable application
├── test_real_world_detection.py # Framework detection tests
├── setup.py                 # Package setup
└── README.md                # This file
```

## Advanced Usage

### Scan Custom Endpoints

```python
from hpp_scanner.scanner import HPPScanner, ScanConfig

config = ScanConfig(
    target_url='http://example.com',
    verbose=True,
    framework_detection=True,
    context_tracking=True,
    impact_scoring=True
)

scanner = HPPScanner('http://example.com', config)

endpoints = [
    {
        'url': 'http://example.com/checkout',
        'method': 'GET',
        'params': {'item': 'laptop', 'price': '999'}
    }
]

vulnerabilities = scanner.scan(endpoints=endpoints)

for vuln in vulnerabilities:
    print(f"{vuln.severity}: {vuln.name}")
    print(f"  Parameter: {vuln.parameter}")
    print(f"  Score: {vuln.score.get('base_score', 'N/A')}")
```

## Key Features

1. **Framework Detection**: Automatically identifies Django, Flask, Express, PHP, ASP.NET
2. **Context Tracking**: Detects vulnerabilities across multi-step workflows
3. **Impact Scoring**: CVSS v3.1-based severity calculation
4. **Payload Generation**: Framework-specific HPP payloads
5. **Multiple Report Formats**: HTML, JSON, Text, Markdown

## License

MIT License - For educational and authorized security testing only.

**WARNING**: This tool includes intentionally vulnerable applications. Never deploy the vulnerable Flask app in production environments.
