# Context-Aware HPP Detection Tool

**HTTP Parameter Pollution Scanner with Novel Detection Capabilities**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## Overview

A next-generation HTTP Parameter Pollution (HPP) vulnerability scanner that goes beyond basic detection to provide **context-aware analysis** and **impact-based severity scoring**.


## Novel Components

### 1. Framework Detection Engine
Automatically identifies the target web framework and optimizes testing:

```python
from hpp_scanner import FrameworkDetector

detector = FrameworkDetector()
framework, confidence = detector.detect(url, response_data)
# Output: Framework.DJANGO, 0.85
```

**Supported Frameworks:**
- Django (Python) - Uses **last** parameter
- Flask (Python) - Uses **first** parameter
- Express (Node.js) - Creates **array**
- PHP - Uses **last** parameter
- ASP.NET - **Concatenates** values

### 2. Context Tracking System
Tracks state across multi-step workflows to detect vulnerabilities that only appear in context:

```python
from hpp_scanner import ContextTracker, WorkflowStep

tracker = ContextTracker()
tracker.start_workflow()

# Track login -> profile -> admin flow
tracker.add_step(login_step, response_data)
tracker.add_step(profile_step, response_data)
tracker.add_step(admin_step, response_data)

# Detect privilege escalation chains
vulnerabilities = tracker.analyze_workflow()
```

**Detects:**
- Privilege escalation across requests
- Identity confusion attacks
- Session fixation via HPP
- Authorization bypass chains

### 3. Impact Scoring Algorithm
Calculates actual security impact using CVSS v3.1 methodology:

```python
from hpp_scanner import ImpactScorer, VulnerabilityMetrics

scorer = ImpactScorer()
metrics = VulnerabilityMetrics(
    affects_authorization=True,
    confidentiality_impact=ImpactLevel.HIGH
)
score = scorer.calculate_score(metrics)
# Output: 8.6/10 CRITICAL
```

**Scoring Factors:**
- Exploitability (Attack Vector, Complexity, Privileges)
- Impact (Confidentiality, Integrity, Availability)
- HPP-Specific Adjustments

## Installation

```bash
# Clone repository
git clone https://github.com/hpp-team/hpp-scanner.git
cd hpp-scanner

# Install package
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

## Quick Start

### Command Line

```bash
# Basic scan
hpp-scanner scan http://target.com

# Scan with HTML report
hpp-scanner scan http://target.com -o report.html -f html

# Framework detection only
hpp-scanner detect http://target.com

# View available payloads
hpp-scanner payloads --param user_id --framework django

# Run demonstration
hpp-scanner demo
```

### Python API

```python
from hpp_scanner import HPPScanner, ScanConfig

# Configure scan
config = ScanConfig(
    target_url="http://target.com",
    framework_detection=True,
    context_tracking=True,
    impact_scoring=True,
    verbose=True
)

# Create scanner and run
scanner = HPPScanner("http://target.com", config)
vulnerabilities = scanner.scan()

# Generate report
report = scanner.generate_report('html')
with open('report.html', 'w') as f:
    f.write(report)
```

## Architecture

```
hpp_scanner/
├── __init__.py           # Package exports
├── scanner.py            # Main scanner (integrates all components)
├── framework_detector.py # Novel #1: Framework detection
├── context_tracker.py    # Novel #2: Multi-step analysis
├── impact_scorer.py      # Novel #3: CVSS-based scoring
├── payload_generator.py  # HPP payload generation
├── response_analyzer.py  # Response comparison
├── report_generator.py   # Multi-format reports
└── cli.py               # Command-line interface
```

## Payload Types

The tool generates various HPP payloads:

| Type | Description | Risk |
|------|-------------|------|
| `BASIC_DUPLICATE` | Basic parameter duplication | LOW |
| `PRIVILEGE_ESCALATION` | Role/permission elevation | CRITICAL |
| `AUTH_BYPASS` | Authentication bypass | CRITICAL |
| `PRICE_MANIPULATION` | Financial value tampering | HIGH |
| `ACCESS_CONTROL` | Resource access bypass | HIGH |
| `WAF_BYPASS` | WAF evasion via HPP | HIGH |
| `ARRAY_INJECTION` | Array handling exploitation | MEDIUM |

## Report Formats

- **HTML** - Rich formatted report with styling
- **JSON** - Machine-readable for automation
- **Text** - Console-friendly output
- **Markdown** - Documentation-friendly

## Example Output

```
============================================================
  HPP VULNERABILITY SCAN REPORT
============================================================

Target: http://example.com
Framework: Django (85% confidence)
Endpoints: 5
Parameters: 12

------------------------------------------------------------
VULNERABILITIES FOUND
------------------------------------------------------------
CRITICAL: 1
HIGH: 2
MEDIUM: 3
LOW: 1

[CRITICAL] #1: Privilege Escalation via HPP
  Parameter: role
  Endpoint: /api/user/update
  Score: 9.1/10
  Description: HPP enabled role change: user -> admin
```

## Comparison with Existing Tools

### vs. Burp Suite
- Burp: Manual HPP testing only
- Our Tool: Automated with framework optimization

### vs. OWASP ZAP
- ZAP: Basic HPP rule, generic "Low" severity
- Our Tool: Context-aware, calculated severity

### vs. Acunetix
- Acunetix: Generic parameter tampering
- Our Tool: HPP-specific with impact analysis

### vs. Invicti (Netsparker)
- Invicti: Proof-based but single-request
- Our Tool: Multi-step workflow analysis

### vs. w3af
- w3af: Basic audit.hpp plugin
- Our Tool: Framework-specific payloads

## Research Background

This tool addresses gaps identified in our analysis of:
- 5 major security scanners (3 commercial + 2 open-source)
- 20+ research papers on HPP
- Community knowledge from security forums

**Key Finding:** No existing tool performs context-aware HPP analysis that maps parameter pollution to actual security impacts.

## Future Work

- [ ] CI/CD pipeline integration
- [ ] REST API for scanning service
- [ ] Machine learning for payload optimization
- [ ] Browser extension for manual testing
- [ ] Cloud-hosted scanning service

## Team

- Member 1: Detection Engine & Framework Analysis
- Member 2: Context Tracking & Impact Scoring

## License

MIT License - See LICENSE file for details.

## References

1. HTTP Parameter Pollution (OWASP)
2. CVSS v3.1 Specification (FIRST)
3. Web Application Security Testing Guide

---

**Built for academic research and authorized security testing only.**
