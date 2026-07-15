"""Honeypot detection library based on protocol quirks and emulation bugs."""

from honeypot_detector.scanner import Scanner
from honeypot_detector.fingerprints import DetectionResult

__version__ = "0.2.1"
__all__ = ["Scanner", "DetectionResult", "__version__"]
