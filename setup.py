#!/usr/bin/env python3
"""
Setup script for HPP Scanner.

Installation:
    pip install -e .

Development installation:
    pip install -e ".[dev]"
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="hpp-scanner",
    version="1.0.0",
    author="HPP Detection Team",
    author_email="team@example.com",
    description="Context-Aware HTTP Parameter Pollution Detection Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hpp-team/hpp-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "hpp-scanner=hpp_scanner.cli:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/hpp-team/hpp-scanner/issues",
        "Source": "https://github.com/hpp-team/hpp-scanner",
        "Documentation": "https://hpp-scanner.readthedocs.io/",
    },
    keywords=[
        "security",
        "web security",
        "hpp",
        "parameter pollution",
        "vulnerability scanner",
        "penetration testing",
    ],
)
