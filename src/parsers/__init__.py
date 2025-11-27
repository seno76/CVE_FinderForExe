"""
Парсеры данных из различных источников
"""

from .bdu_parser import BDUParser
from .data_loader import DataLoader

__all__ = [
    'BDUParser',
    'DataLoader',
]
