"""
Сканер файлов - проверяет отдельные файлы на наличие уязвимостей
"""

from pathlib import Path
from typing import List, Optional, Dict, Any

from ..core.data_structures import Vulnerability, VulnerabilityTree
from ..detectors.file_analyzer import FileAnalyzer
from ..detectors.software_detector import SoftwareDetector


class VulnerabilityFinding:
    """Результат проверки файла на уязвимости"""
    
    def __init__(self, file_path: str, software_name: Optional[str] = None, 
                 software_version: Optional[str] = None, vulnerabilities: List[Vulnerability] = None):
        self.file_path = file_path
        self.software_name = software_name
        self.software_version = software_version
        self.vulnerabilities = vulnerabilities or []
    
    def has_vulnerabilities(self) -> bool:
        """Есть ли уязвимости"""
        return len(self.vulnerabilities) > 0
    
    def to_dict(self) -> dict:
        """Преобразование в словарь"""
        return {
            'file_path': self.file_path,
            'software_name': self.software_name,
            'software_version': self.software_version,
            'vulnerabilities_count': len(self.vulnerabilities),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
        }


class FileScanner:
    """
    Сканер для проверки отдельных файлов на уязвимости
    """
    
    def __init__(self, vulnerability_tree: VulnerabilityTree):
        """
        Инициализация сканера
        
        Args:
            vulnerability_tree: Дерево уязвимостей для сравнения
        """
        self.tree = vulnerability_tree
        self.detector = SoftwareDetector()
        self.file_analyzer = FileAnalyzer()
    
    def scan_file(self, file_path: str) -> Optional[VulnerabilityFinding]:
        """
        Сканировать отдельный файл
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            VulnerabilityFinding или None
        """
        path = Path(file_path)
        
        # Проверь, существует ли файл
        if not path.exists():
            return None
        
        # Проверь, нужно ли игнорировать файл
        if self.file_analyzer.is_safe_to_ignore(file_path):
            return None
        
        # Проверь, исполняемый ли файл
        if not self.file_analyzer.is_executable(file_path):
            return None
        
        # Определи ПО и версию
        # Приоритет 1: Для .exe файлов попробуй извлечь из PE метаданных
        software_name = None
        software_version = None
        
        if file_path.lower().endswith('.exe'):
            pe_result = self.detector.detect_from_pe_metadata(file_path)
            if pe_result:
                software_name, software_version = pe_result
        
        # Приоритет 2: Если не получилось из PE, определи по пути
        if not software_name:
            detection = self.detector.detect_from_file(file_path)
            if detection:
                software_name, software_version = detection
        
        # Если не определили ПО, верни пустой результат
        if not software_name:
            return VulnerabilityFinding(file_path=file_path)
        
        # Найди уязвимости
        vulnerabilities = self.tree.find_vulnerabilities(software_name, software_version)
        
        return VulnerabilityFinding(
            file_path=file_path,
            software_name=software_name,
            software_version=software_version or 'unknown',
            vulnerabilities=vulnerabilities
        )
    
    def get_statistics(self) -> dict:
        """Получить статистику сканирования"""
        return {
            'software_in_tree': len(self.tree.root),
            'total_vulnerabilities': sum(
                len(v.vulnerabilities) 
                for sw in self.tree.root.values() 
                for v in sw.versions.values()
            ),
        }
