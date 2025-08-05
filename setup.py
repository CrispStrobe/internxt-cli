#!/usr/bin/env python3

from setuptools import setup, find_packages
import os

# Read README file
readme_path = os.path.join(os.path.dirname(__file__), "readme.md")
try:
    with open(readme_path, "r", encoding="utf-8") as fh:
        long_description = fh.read()
except FileNotFoundError:
    long_description = "A Python CLI for Internxt encrypted cloud storage"

# Required dependencies - includes all needed packages
requirements = [
    "requests>=2.31.0",
    "cryptography>=41.0.0",
    "mnemonic>=0.20",          # ✅ Added missing mnemonic package
    "click>=8.1.0",
    "tqdm>=4.65.0",
    "keyring>=24.0.0",
    "Flask>=2.3.0",            # Optional for WebDAV
    "Werkzeug>=2.3.0"          # Optional for WebDAV
]

setup(
    name="internxt-python-cli",        # ✅ Changed name to avoid conflicts
    version="1.0.0",
    author="Internxt Python CLI",
    author_email="hello@internxt.com",
    description="A Python CLI for Internxt encrypted cloud storage",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/internxt/python-cli",
    packages=find_packages(include=['internxt_cli', 'internxt_cli.*']),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "inxt=cli:cli",              # ✅ Changed command name to "inxt" (shorter, no conflicts)
            "internxt-py=cli:cli",       # ✅ Alternative command name
        ],
    },
    include_package_data=True,
    zip_safe=False,
)