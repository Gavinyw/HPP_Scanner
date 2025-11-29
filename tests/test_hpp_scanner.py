#!/usr/bin/env python3
"""
HPP Scanner - Unit Tests

Run tests:
    python -m pytest tests/ -v
    python tests/test_hpp_scanner.py
"""

import sys
import unittest
from datetime import datetime

# Add parent directory
sys.path.insert(0, '.')

from hpp_scanner.framework_detector import FrameworkDetector, Framework
from hpp_scanner.payload_generator import PayloadGenerator, PayloadType, ParameterLocation
from hpp_scanner.context_tracker import ContextTracker, WorkflowStep, WorkflowStepType
from hpp_scanner.impact_scorer import ImpactScorer, VulnerabilityMetrics, ImpactLevel, Severity
from hpp_scanner.response_analyzer import ResponseAnalyzer, ResponseData


class TestFrameworkDetector(unittest.TestCase):
    """Tests for Framework Detection (Novel Component #1)"""
    
    def setUp(self):
        self.detector = FrameworkDetector()
    
    def test_detect_django(self):
        """Test Django framework detection."""
        response_data = {
            'headers': {'Server': 'WSGIServer/0.2'},
            'body': 'csrfmiddlewaretoken',
            'cookies': {'csrftoken': 'abc123'}
        }
        framework, confidence = self.detector.detect('http://test.com', response_data)
        self.assertEqual(framework, Framework.DJANGO)
        self.assertGreater(confidence, 0.3)
    
    def test_detect_flask(self):
        """Test Flask framework detection."""
        response_data = {
            'headers': {'Server': 'Werkzeug/2.0.1'},
            'body': '',
            'cookies': {'session': 'xyz'}
        }
        framework, confidence = self.detector.detect('http://test.com', response_data)
        self.assertEqual(framework, Framework.FLASK)
    
    def test_detect_express(self):
        """Test Express framework detection."""
        response_data = {
            'headers': {'X-Powered-By': 'Express'},
            'body': 'Cannot GET /test',
            'cookies': {}
        }
        framework, confidence = self.detector.detect('http://test.com', response_data)
        self.assertEqual(framework, Framework.EXPRESS)
    
    def test_detect_php(self):
        """Test PHP framework detection."""
        response_data = {
            'headers': {'X-Powered-By': 'PHP/8.1.0'},
            'body': '',
            'cookies': {'PHPSESSID': 'abc'}
        }
        framework, confidence = self.detector.detect('http://test.com', response_data)
        self.assertEqual(framework, Framework.PHP)
    
    def test_parameter_behavior(self):
        """Test parameter behavior detection."""
        # Django uses last parameter
        response_data = {
            'headers': {'Server': 'WSGIServer'},
            'body': 'csrftoken',
            'cookies': {}
        }
        self.detector.detect('http://test.com', response_data)
        self.assertEqual(self.detector.get_parameter_behavior(), 'last')


class TestPayloadGenerator(unittest.TestCase):
    """Tests for Payload Generation"""
    
    def setUp(self):
        self.generator = PayloadGenerator()
    
    def test_generate_payloads(self):
        """Test payload generation for a parameter."""
        payloads = self.generator.generate_payloads('user_id')
        self.assertGreater(len(payloads), 0)
    
    def test_framework_specific_payloads(self):
        """Test framework-specific payload generation."""
        self.generator.set_framework(Framework.DJANGO)
        payloads = self.generator.generate_payloads('test')
        fw_specific = self.generator.get_framework_specific_count()
        self.assertGreater(fw_specific, 0)
    
    def test_context_aware_risk_elevation(self):
        """Test that security-sensitive parameters get elevated risk."""
        payloads = self.generator.generate_payloads('admin_role')
        high_risk = self.generator.get_payloads_by_risk('HIGH')
        critical_risk = self.generator.get_payloads_by_risk('CRITICAL')
        self.assertGreater(len(high_risk) + len(critical_risk), 0)
    
    def test_payload_types(self):
        """Test different payload types are generated."""
        payloads = self.generator.generate_payloads('test')
        types_found = set(p.payload_type for p in payloads)
        self.assertIn(PayloadType.BASIC_DUPLICATE, types_found)


class TestContextTracker(unittest.TestCase):
    """Tests for Context Tracking (Novel Component #2)"""
    
    def setUp(self):
        self.tracker = ContextTracker()
    
    def test_workflow_tracking(self):
        """Test basic workflow tracking."""
        self.tracker.start_workflow()
        
        step1 = WorkflowStep(
            name='Login',
            step_type=WorkflowStepType.LOGIN,
            endpoint='/login'
        )
        self.tracker.add_step(step1, {'cookies': {'session': '123'}})
        
        step2 = WorkflowStep(
            name='View',
            step_type=WorkflowStepType.VIEW,
            endpoint='/profile'
        )
        self.tracker.add_step(step2, {})
        
        summary = self.tracker.get_workflow_summary()
        self.assertEqual(summary['total_steps'], 2)
    
    def test_state_tracking(self):
        """Test session state tracking."""
        self.tracker.start_workflow()
        
        step = WorkflowStep(
            name='Login',
            step_type=WorkflowStepType.LOGIN,
            endpoint='/login'
        )
        response = {
            'cookies': {'session': 'abc123'},
            'body': {'user': {'id': '456', 'role': 'user'}}
        }
        self.tracker.add_step(step, response)
        
        self.assertEqual(self.tracker.current_state.user_id, '456')
        self.assertEqual(self.tracker.current_state.role, 'user')
    
    def test_privilege_escalation_detection(self):
        """Test detection of privilege escalation."""
        self.tracker.start_workflow()
        
        # Normal login
        step1 = WorkflowStep(name='Login', step_type=WorkflowStepType.LOGIN, endpoint='/login')
        self.tracker.add_step(step1, {'body': {'user': {'id': '1', 'role': 'user'}}})
        
        # Privilege escalation
        step2 = WorkflowStep(name='Exploit', step_type=WorkflowStepType.UPDATE, endpoint='/update')
        self.tracker.add_step(step2, {'body': {'user': {'id': '1', 'role': 'admin'}}})
        
        vulns = self.tracker.analyze_workflow()
        # Should detect role change
        self.assertGreater(len([t for t in self.tracker.transitions if t.is_suspicious]), 0)


class TestImpactScorer(unittest.TestCase):
    """Tests for Impact Scoring (Novel Component #3)"""
    
    def setUp(self):
        self.scorer = ImpactScorer()
    
    def test_basic_scoring(self):
        """Test basic vulnerability scoring."""
        metrics = VulnerabilityMetrics()
        score = self.scorer.calculate_score(metrics)
        
        self.assertGreaterEqual(score.base_score, 0)
        self.assertLessEqual(score.base_score, 10)
    
    def test_critical_severity(self):
        """Test that high-impact vulnerabilities get CRITICAL severity."""
        metrics = VulnerabilityMetrics(
            affects_authentication=True,
            affects_authorization=True,
            confidentiality_impact=ImpactLevel.HIGH,
            integrity_impact=ImpactLevel.HIGH
        )
        score = self.scorer.calculate_score(metrics)
        
        self.assertIn(score.severity, [Severity.CRITICAL, Severity.HIGH])
    
    def test_low_severity(self):
        """Test that low-impact vulnerabilities get appropriate severity."""
        metrics = VulnerabilityMetrics(
            confidentiality_impact=ImpactLevel.NONE,
            integrity_impact=ImpactLevel.NONE,
            availability_impact=ImpactLevel.NONE
        )
        score = self.scorer.calculate_score(metrics)
        
        self.assertIn(score.severity, [Severity.LOW, Severity.INFORMATIONAL])
    
    def test_score_from_vulnerability_data(self):
        """Test scoring from dictionary input."""
        vuln_data = {
            'parameter': 'role',
            'type': 'privilege_escalation',
            'requires_auth': True
        }
        score = self.scorer.score_from_vulnerability_data(vuln_data)
        
        self.assertIsNotNone(score)
        self.assertGreater(score.base_score, 0)
    
    def test_recommendations_generated(self):
        """Test that recommendations are generated."""
        metrics = VulnerabilityMetrics(affects_authentication=True)
        score = self.scorer.calculate_score(metrics)
        
        self.assertGreater(len(score.recommendations), 0)


class TestResponseAnalyzer(unittest.TestCase):
    """Tests for Response Analysis"""
    
    def setUp(self):
        self.analyzer = ResponseAnalyzer()
    
    def test_compare_identical_responses(self):
        """Test comparing identical responses."""
        response1 = ResponseData(
            status_code=200,
            headers={'Content-Type': 'text/html'},
            body='<html>Test</html>',
            cookies={},
            response_time=100.0
        )
        response2 = ResponseData(
            status_code=200,
            headers={'Content-Type': 'text/html'},
            body='<html>Test</html>',
            cookies={},
            response_time=110.0
        )
        
        result = self.analyzer.compare_responses(response1, response2)
        self.assertFalse(result.is_different)
    
    def test_detect_status_code_change(self):
        """Test detection of status code changes."""
        baseline = ResponseData(
            status_code=403,
            headers={},
            body='Forbidden',
            cookies={},
            response_time=100.0
        )
        test = ResponseData(
            status_code=200,
            headers={},
            body='Welcome',
            cookies={},
            response_time=100.0
        )
        
        result = self.analyzer.compare_responses(baseline, test)
        self.assertTrue(result.is_different)
        self.assertIn('status_code', result.differences)
    
    def test_vulnerability_indicators(self):
        """Test vulnerability indicator detection."""
        baseline = ResponseData(
            status_code=403,
            headers={},
            body='Access Denied',
            cookies={},
            response_time=100.0
        )
        test = ResponseData(
            status_code=200,
            headers={},
            body='Admin Dashboard',
            cookies={},
            response_time=100.0
        )
        
        result = self.analyzer.compare_responses(baseline, test)
        self.assertGreater(len(result.vulnerability_indicators), 0)


class TestIntegration(unittest.TestCase):
    """Integration tests for full workflow"""
    
    def test_full_detection_workflow(self):
        """Test complete detection workflow."""
        # 1. Detect framework
        detector = FrameworkDetector()
        framework, _ = detector.detect('http://test.com', {
            'headers': {'X-Powered-By': 'Express'},
            'body': '',
            'cookies': {}
        })
        
        # 2. Generate payloads
        generator = PayloadGenerator(framework)
        payloads = generator.generate_payloads('user_id')
        
        # 3. Track context
        tracker = ContextTracker()
        tracker.start_workflow()
        
        # 4. Score vulnerability
        scorer = ImpactScorer()
        score = scorer.score_from_vulnerability_data({
            'parameter': 'user_id',
            'type': 'auth_bypass'
        })
        
        # Verify all components work together
        self.assertEqual(framework, Framework.EXPRESS)
        self.assertGreater(len(payloads), 0)
        self.assertIsNotNone(score)


def run_tests():
    """Run all tests with output."""
    print("=" * 60)
    print("  HPP Scanner - Unit Tests")
    print("=" * 60)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestFrameworkDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestPayloadGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestContextTracker))
    suite.addTests(loader.loadTestsFromTestCase(TestImpactScorer))
    suite.addTests(loader.loadTestsFromTestCase(TestResponseAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 60)
    print(f"  Tests run: {result.testsRun}")
    print(f"  Failures: {len(result.failures)}")
    print(f"  Errors: {len(result.errors)}")
    print("=" * 60)
    
    return len(result.failures) + len(result.errors)


if __name__ == '__main__':
    sys.exit(run_tests())
