"""
Детекторы для определения ПО и версий
"""

from .file_analyzer import FileAnalyzer
from .software_detector import SoftwareDetector

__all__ = [
    'FileAnalyzer',
    'SoftwareDetector',
]
