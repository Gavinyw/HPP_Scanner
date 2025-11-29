"""
Report Generator

Generates comprehensive HPP vulnerability reports:
- HTML reports with visualizations
- JSON reports for automation
- Text reports for console output
- Executive summaries
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import json
import html


@dataclass
class ScanResult:
    """Represents a complete scan result"""
    target_url: str
    scan_time: datetime
    framework_detected: str
    framework_confidence: float
    total_endpoints: int
    total_parameters: int
    vulnerabilities: List[Dict]
    scan_duration: float  # seconds
    
    def to_dict(self) -> Dict:
        return {
            'target_url': self.target_url,
            'scan_time': self.scan_time.isoformat(),
            'framework': {
                'detected': self.framework_detected,
                'confidence': self.framework_confidence
            },
            'coverage': {
                'endpoints': self.total_endpoints,
                'parameters': self.total_parameters
            },
            'vulnerabilities': self.vulnerabilities,
            'scan_duration_seconds': self.scan_duration
        }


class ReportGenerator:
    """
    Generates vulnerability reports in multiple formats.
    
    Supports:
    - HTML: Rich formatted reports with styling
    - JSON: Machine-readable for automation
    - Text: Console-friendly output
    - Markdown: Documentation-friendly
    """
    
    # HTML template for reports
    HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HPP Vulnerability Report - {target}</title>
    <style>
        :root {{
            --primary: #1A237E;
            --danger: #E53935;
            --warning: #FF9800;
            --success: #4CAF50;
            --info: #00ACC1;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{
            background: var(--primary);
            color: white;
            padding: 30px;
            margin-bottom: 30px;
        }}
        header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        header .subtitle {{ opacity: 0.9; }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .card h3 {{ color: var(--primary); margin-bottom: 10px; }}
        .card .value {{ font-size: 2em; font-weight: bold; }}
        .card.critical .value {{ color: var(--danger); }}
        .card.high .value {{ color: var(--warning); }}
        .card.medium .value {{ color: var(--info); }}
        
        .vulnerability {{
            background: white;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .vulnerability-header {{
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .vulnerability-header.critical {{ background: var(--danger); color: white; }}
        .vulnerability-header.high {{ background: var(--warning); color: white; }}
        .vulnerability-header.medium {{ background: var(--info); color: white; }}
        .vulnerability-header.low {{ background: #78909C; color: white; }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .vulnerability-body {{ padding: 20px; }}
        .vulnerability-body h4 {{ color: var(--primary); margin: 15px 0 10px 0; }}
        .vulnerability-body pre {{
            background: #f5f5f5;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9em;
        }}
        .vulnerability-body ul {{ margin-left: 20px; }}
        .vulnerability-body li {{ margin: 5px 0; }}
        
        .score-bar {{
            height: 8px;
            background: #eee;
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .score-bar-fill {{
            height: 100%;
            border-radius: 4px;
        }}
        .score-bar-fill.critical {{ background: var(--danger); }}
        .score-bar-fill.high {{ background: var(--warning); }}
        .score-bar-fill.medium {{ background: var(--info); }}
        .score-bar-fill.low {{ background: #78909C; }}
        
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: var(--primary); color: white; }}
        
        footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9em;
        }}
        
        @media print {{
            body {{ background: white; }}
            .vulnerability {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔒 HPP Vulnerability Report</h1>
            <p class="subtitle">Context-Aware HTTP Parameter Pollution Detection</p>
        </div>
    </header>
    
    <div class="container">
        {content}
    </div>
    
    <footer>
        <p>Generated by Context-Aware HPP Detection Tool</p>
        <p>Report generated: {timestamp}</p>
    </footer>
</body>
</html>'''
    
    def __init__(self):
        """Initialize report generator."""
        self.reports_generated: List[str] = []
        
    def generate_html_report(self, scan_result: ScanResult) -> str:
        """
        Generate HTML report.
        
        Args:
            scan_result: Complete scan results
            
        Returns:
            HTML report string
        """
        content_parts = []
        
        # Summary section
        content_parts.append(self._generate_summary_section(scan_result))
        
        # Framework detection section
        content_parts.append(self._generate_framework_section(scan_result))
        
        # Vulnerabilities section
        content_parts.append(self._generate_vulnerabilities_section(scan_result))
        
        # Recommendations section
        content_parts.append(self._generate_recommendations_section(scan_result))
        
        content = '\n'.join(content_parts)
        
        report = self.HTML_TEMPLATE.format(
            target=html.escape(scan_result.target_url),
            content=content,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        self.reports_generated.append(f"HTML report for {scan_result.target_url}")
        return report
    
    def _generate_summary_section(self, scan_result: ScanResult) -> str:
        """Generate summary cards HTML."""
        vulns = scan_result.vulnerabilities
        
        critical_count = sum(1 for v in vulns if v.get('severity') == 'CRITICAL')
        high_count = sum(1 for v in vulns if v.get('severity') == 'HIGH')
        medium_count = sum(1 for v in vulns if v.get('severity') == 'MEDIUM')
        low_count = sum(1 for v in vulns if v.get('severity') == 'LOW')
        
        return f'''
        <h2>📊 Scan Summary</h2>
        <div class="summary-cards">
            <div class="card">
                <h3>Target</h3>
                <p style="word-break: break-all;">{html.escape(scan_result.target_url)}</p>
                <p style="color: #666; font-size: 0.9em;">Scanned: {scan_result.scan_time.strftime('%Y-%m-%d %H:%M')}</p>
            </div>
            <div class="card critical">
                <h3>Critical</h3>
                <div class="value">{critical_count}</div>
            </div>
            <div class="card high">
                <h3>High</h3>
                <div class="value">{high_count}</div>
            </div>
            <div class="card medium">
                <h3>Medium</h3>
                <div class="value">{medium_count}</div>
            </div>
            <div class="card">
                <h3>Low/Info</h3>
                <div class="value">{low_count}</div>
            </div>
            <div class="card">
                <h3>Coverage</h3>
                <p>{scan_result.total_endpoints} endpoints</p>
                <p>{scan_result.total_parameters} parameters</p>
            </div>
        </div>
        '''
    
    def _generate_framework_section(self, scan_result: ScanResult) -> str:
        """Generate framework detection section."""
        confidence_pct = scan_result.framework_confidence * 100
        
        return f'''
        <div class="card" style="margin-bottom: 30px;">
            <h3>🔍 Framework Detection</h3>
            <table>
                <tr>
                    <th>Detected Framework</th>
                    <td><strong>{html.escape(scan_result.framework_detected)}</strong></td>
                </tr>
                <tr>
                    <th>Confidence</th>
                    <td>
                        {confidence_pct:.0f}%
                        <div class="score-bar">
                            <div class="score-bar-fill {'high' if confidence_pct > 70 else 'medium'}" 
                                 style="width: {confidence_pct}%"></div>
                        </div>
                    </td>
                </tr>
                <tr>
                    <th>Parameter Behavior</th>
                    <td>Uses <strong>{'last' if 'Django' in scan_result.framework_detected or 'PHP' in scan_result.framework_detected else 'first' if 'Flask' in scan_result.framework_detected else 'array'}</strong> parameter value</td>
                </tr>
            </table>
        </div>
        '''
    
    def _generate_vulnerabilities_section(self, scan_result: ScanResult) -> str:
        """Generate vulnerabilities section."""
        if not scan_result.vulnerabilities:
            return '''
            <div class="card" style="background: #E8F5E9; border-left: 4px solid #4CAF50;">
                <h3>✅ No Vulnerabilities Found</h3>
                <p>No HTTP Parameter Pollution vulnerabilities were detected during this scan.</p>
            </div>
            '''
        
        html_parts = ['<h2>🚨 Vulnerabilities Found</h2>']
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFORMATIONAL': 4}
        sorted_vulns = sorted(
            scan_result.vulnerabilities,
            key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4)
        )
        
        for i, vuln in enumerate(sorted_vulns, 1):
            severity = vuln.get('severity', 'LOW').lower()
            score = vuln.get('score', {})
            
            html_parts.append(f'''
            <div class="vulnerability">
                <div class="vulnerability-header {severity}">
                    <span><strong>#{i}</strong> {html.escape(vuln.get('name', 'Unknown Vulnerability'))}</span>
                    <span class="severity-badge">{vuln.get('severity', 'LOW')} ({score.get('base_score', 0)}/10)</span>
                </div>
                <div class="vulnerability-body">
                    <h4>Description</h4>
                    <p>{html.escape(vuln.get('description', 'No description available.'))}</p>
                    
                    <h4>Affected Parameter</h4>
                    <p><code>{html.escape(vuln.get('parameter', 'Unknown'))}</code> at <code>{html.escape(vuln.get('endpoint', 'Unknown'))}</code></p>
                    
                    <h4>Score Breakdown</h4>
                    <div class="score-bar">
                        <div class="score-bar-fill {severity}" style="width: {score.get('base_score', 0) * 10}%"></div>
                    </div>
                    <table>
                        <tr><th>Exploitability</th><td>{score.get('exploitability_score', 0)}/10</td></tr>
                        <tr><th>Impact</th><td>{score.get('impact_score', 0)}/10</td></tr>
                    </table>
                    
                    <h4>Exploit Chain</h4>
                    <pre>{html.escape(vuln.get('exploit_chain', 'N/A'))}</pre>
                    
                    <h4>Recommendations</h4>
                    <ul>
                        {"".join(f"<li>{html.escape(r)}</li>" for r in score.get('recommendations', ['Validate input parameters']))}
                    </ul>
                </div>
            </div>
            ''')
        
        return '\n'.join(html_parts)
    
    def _generate_recommendations_section(self, scan_result: ScanResult) -> str:
        """Generate general recommendations section."""
        return '''
        <div class="card" style="margin-top: 30px;">
            <h3>📋 General Recommendations</h3>
            <ol>
                <li><strong>Input Validation:</strong> Validate and sanitize all input parameters. Reject requests with duplicate parameter names.</li>
                <li><strong>Framework Configuration:</strong> Configure your framework to handle duplicate parameters consistently.</li>
                <li><strong>Security Headers:</strong> Implement security headers and consider a Web Application Firewall (WAF).</li>
                <li><strong>Access Control:</strong> Implement server-side access control that doesn't rely on parameter values.</li>
                <li><strong>Audit Logging:</strong> Log all parameter pollution attempts for security monitoring.</li>
            </ol>
        </div>
        '''
    
    def generate_json_report(self, scan_result: ScanResult) -> str:
        """
        Generate JSON report.
        
        Args:
            scan_result: Complete scan results
            
        Returns:
            JSON report string
        """
        report_data = {
            'report_metadata': {
                'generator': 'Context-Aware HPP Detection Tool',
                'version': '1.0.0',
                'generated_at': datetime.now().isoformat()
            },
            'scan_result': scan_result.to_dict(),
            'summary': {
                'total_vulnerabilities': len(scan_result.vulnerabilities),
                'by_severity': self._count_by_severity(scan_result.vulnerabilities),
                'risk_score': self._calculate_risk_score(scan_result.vulnerabilities)
            }
        }
        
        self.reports_generated.append(f"JSON report for {scan_result.target_url}")
        return json.dumps(report_data, indent=2)
    
    def generate_text_report(self, scan_result: ScanResult) -> str:
        """
        Generate plain text report for console output.
        
        Args:
            scan_result: Complete scan results
            
        Returns:
            Text report string
        """
        lines = []
        lines.append("=" * 60)
        lines.append("  HPP VULNERABILITY SCAN REPORT")
        lines.append("  Context-Aware HTTP Parameter Pollution Detection")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Target: {scan_result.target_url}")
        lines.append(f"Scan Time: {scan_result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Duration: {scan_result.scan_duration:.2f} seconds")
        lines.append("")
        lines.append("-" * 60)
        lines.append("FRAMEWORK DETECTION")
        lines.append("-" * 60)
        lines.append(f"Framework: {scan_result.framework_detected}")
        lines.append(f"Confidence: {scan_result.framework_confidence * 100:.0f}%")
        lines.append("")
        lines.append("-" * 60)
        lines.append("SCAN COVERAGE")
        lines.append("-" * 60)
        lines.append(f"Endpoints Tested: {scan_result.total_endpoints}")
        lines.append(f"Parameters Tested: {scan_result.total_parameters}")
        lines.append("")
        lines.append("-" * 60)
        lines.append("VULNERABILITIES FOUND")
        lines.append("-" * 60)
        
        severity_counts = self._count_by_severity(scan_result.vulnerabilities)
        lines.append(f"CRITICAL: {severity_counts.get('CRITICAL', 0)}")
        lines.append(f"HIGH: {severity_counts.get('HIGH', 0)}")
        lines.append(f"MEDIUM: {severity_counts.get('MEDIUM', 0)}")
        lines.append(f"LOW: {severity_counts.get('LOW', 0)}")
        lines.append("")
        
        if scan_result.vulnerabilities:
            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                lines.append(f"[{vuln.get('severity', 'LOW')}] #{i}: {vuln.get('name', 'Unknown')}")
                lines.append(f"  Parameter: {vuln.get('parameter', 'Unknown')}")
                lines.append(f"  Endpoint: {vuln.get('endpoint', 'Unknown')}")
                lines.append(f"  Score: {vuln.get('score', {}).get('base_score', 0)}/10")
                lines.append(f"  Description: {vuln.get('description', 'N/A')[:100]}...")
                lines.append("")
        else:
            lines.append("No vulnerabilities found.")
            lines.append("")
        
        lines.append("=" * 60)
        lines.append("Report generated by HPP Detection Tool")
        lines.append("=" * 60)
        
        self.reports_generated.append(f"Text report for {scan_result.target_url}")
        return '\n'.join(lines)
    
    def generate_markdown_report(self, scan_result: ScanResult) -> str:
        """
        Generate Markdown report.
        
        Args:
            scan_result: Complete scan results
            
        Returns:
            Markdown report string
        """
        lines = []
        lines.append("# HPP Vulnerability Scan Report")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Target:** `{scan_result.target_url}`")
        lines.append(f"- **Scan Time:** {scan_result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"- **Framework:** {scan_result.framework_detected} ({scan_result.framework_confidence * 100:.0f}% confidence)")
        lines.append(f"- **Total Vulnerabilities:** {len(scan_result.vulnerabilities)}")
        lines.append("")
        
        severity_counts = self._count_by_severity(scan_result.vulnerabilities)
        lines.append("### Findings by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            lines.append(f"| {sev} | {severity_counts.get(sev, 0)} |")
        lines.append("")
        
        if scan_result.vulnerabilities:
            lines.append("## Vulnerability Details")
            lines.append("")
            
            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                lines.append(f"### {i}. {vuln.get('name', 'Unknown')}")
                lines.append("")
                lines.append(f"**Severity:** {vuln.get('severity', 'LOW')} ({vuln.get('score', {}).get('base_score', 0)}/10)")
                lines.append("")
                lines.append(f"**Parameter:** `{vuln.get('parameter', 'Unknown')}`")
                lines.append("")
                lines.append(f"**Endpoint:** `{vuln.get('endpoint', 'Unknown')}`")
                lines.append("")
                lines.append("**Description:**")
                lines.append(vuln.get('description', 'N/A'))
                lines.append("")
                lines.append("**Exploit Chain:**")
                lines.append("```")
                lines.append(vuln.get('exploit_chain', 'N/A'))
                lines.append("```")
                lines.append("")
                lines.append("**Recommendations:**")
                for rec in vuln.get('score', {}).get('recommendations', ['Validate input']):
                    lines.append(f"- {rec}")
                lines.append("")
                lines.append("---")
                lines.append("")
        
        lines.append("## Recommendations")
        lines.append("")
        lines.append("1. Validate and sanitize all input parameters")
        lines.append("2. Configure framework to handle duplicate parameters consistently")
        lines.append("3. Implement server-side access control")
        lines.append("4. Consider implementing a Web Application Firewall (WAF)")
        lines.append("")
        lines.append("---")
        lines.append("*Report generated by Context-Aware HPP Detection Tool*")
        
        self.reports_generated.append(f"Markdown report for {scan_result.target_url}")
        return '\n'.join(lines)
    
    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'LOW')
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score."""
        if not vulnerabilities:
            return 0.0
        
        weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
        total_weight = sum(weights.get(v.get('severity', 'LOW'), 1) for v in vulnerabilities)
        max_weight = len(vulnerabilities) * 10
        
        return round((total_weight / max_weight) * 10, 1) if max_weight > 0 else 0.0
