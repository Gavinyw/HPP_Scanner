"""
Context-Aware HTTP Parameter Pollution (HPP) Detection Tool

A novel security scanner that detects HPP vulnerabilities with:
- Framework-specific detection (Django, Flask, Express, PHP)
- Context-aware multi-step workflow analysis
- Impact-based severity scoring

Authors: HPP Detection Team
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "HPP Detection Team"

from .scanner import HPPScanner
from .framework_detector import FrameworkDetector
from .payload_generator import PayloadGenerator
from .context_tracker import ContextTracker
from .impact_scorer import ImpactScorer
from .response_analyzer import ResponseAnalyzer
from .report_generator import ReportGenerator

__all__ = [
    'HPPScanner',
    'FrameworkDetector',
    'PayloadGenerator',
    'ContextTracker',
    'ImpactScorer',
    'ResponseAnalyzer',
    'ReportGenerator'
]
