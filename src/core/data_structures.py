"""
Основные структуры данных для представления уязвимостей
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class SeverityLevel(Enum):
    """Уровни опасности уязвимости"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class Vulnerability:
    """
    Представление уязвимости
    """
    bdu_id: str  # ID БДУ (BDU:2014-00001)
    cve_id: Optional[str] = None  # ID CVE (CVE-2011-4859)
    name: str = ""  # Название уязвимости
    description: str = ""  # Полное описание
    severity: SeverityLevel = SeverityLevel.UNKNOWN  # Уровень опасности
    cvss_2_0: Optional[float] = None  # CVSS 2.0 оценка
    cvss_3_0: Optional[float] = None  # CVSS 3.0 оценка
    cvss_4_0: Optional[float] = None  # CVSS 4.0 оценка
    vulnerability_class: str = ""  # Класс уязвимости (архитектуры, кода и т.д.)
    cwe_id: Optional[str] = None  # CWE ID
    cwe_description: str = ""  # Описание ошибки CWE
    published_date: Optional[str] = None  # Дата публикации
    exploit_available: bool = False  # Доступен ли эксплойт
    additional_info: Dict[str, Any] = field(default_factory=dict)  # Дополнительная информация

    def to_dict(self) -> dict:
        """Преобразование в словарь"""
        return {
            'bdu_id': self.bdu_id,
            'cve_id': self.cve_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity.value,
            'cvss_2_0': self.cvss_2_0,
            'cvss_3_0': self.cvss_3_0,
            'cvss_4_0': self.cvss_4_0,
            'vulnerability_class': self.vulnerability_class,
            'cwe_id': self.cwe_id,
            'cwe_description': self.cwe_description,
            'published_date': self.published_date,
            'exploit_available': self.exploit_available,
        }


@dataclass
class SoftwareVersion:
    """
    Версия ПО с уязвимостями
    """
    version: str  # Версия (2.4.41, 12, от 8.4.0 до 8.4.16 включительно и т.д.)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)  # Список уязвимостей

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Добавить уязвимость"""
        if vuln not in self.vulnerabilities:
            self.vulnerabilities.append(vuln)

    def get_vulnerabilities_by_severity(self, severity: SeverityLevel) -> List[Vulnerability]:
        """Получить уязвимости по уровню опасности"""
        return [v for v in self.vulnerabilities if v.severity == severity]

    def to_dict(self) -> dict:
        """Преобразование в словарь"""
        return {
            'version': self.version,
            'vulnerabilities_count': len(self.vulnerabilities),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
        }


@dataclass
class Software:
    """
    ПО (продукт) с его версиями и уязвимостями
    """
    name: str  # Название ПО (Firefox, Apache и т.д.)
    vendor: str = ""  # Вендор (Mozilla Corp., Apache Software Foundation и т.д.)
    versions: Dict[str, SoftwareVersion] = field(default_factory=dict)  # Словарь версий
    software_type: str = ""  # Тип ПО (браузер, веб-сервер, СУБД и т.д.)

    def add_version(self, version_str: str) -> SoftwareVersion:
        """Добавить или получить версию"""
        if version_str not in self.versions:
            self.versions[version_str] = SoftwareVersion(version=version_str)
        return self.versions[version_str]

    def get_version(self, version_str: str) -> Optional[SoftwareVersion]:
        """Получить версию"""
        return self.versions.get(version_str)

    def get_all_vulnerabilities(self) -> List[Vulnerability]:
        """Получить все уязвимости для всех версий"""
        all_vulns = []
        for version in self.versions.values():
            all_vulns.extend(version.vulnerabilities)
        return all_vulns

    def get_critical_vulnerabilities_count(self) -> int:
        """Количество критических уязвимостей"""
        count = 0
        for version in self.versions.values():
            count += len(version.get_vulnerabilities_by_severity(SeverityLevel.CRITICAL))
        return count

    def to_dict(self) -> dict:
        """Преобразование в словарь"""
        return {
            'name': self.name,
            'vendor': self.vendor,
            'software_type': self.software_type,
            'versions_count': len(self.versions),
            'versions': {v_str: v.to_dict() for v_str, v in self.versions.items()},
        }


class VulnerabilityTree:
    """
    4-уровневое дерево уязвимостей
    Уровень 1: Корень
    Уровень 2: ПО (Software)
    Уровень 3: Версия (SoftwareVersion)
    Уровень 4: Уязвимость (Vulnerability)
    """

    def __init__(self):
        """Инициализация дерева"""
        self.root: Dict[str, Software] = {}  # Словарь ПО (ключ - название, значение - Software)

    def add_software(self, name: str, vendor: str = "", software_type: str = "") -> Software:
        """
        Добавить или получить ПО
        
        Args:
            name: Название ПО
            vendor: Вендор
            software_type: Тип ПО
            
        Returns:
            Объект Software
        """
        if name not in self.root:
            self.root[name] = Software(name=name, vendor=vendor, software_type=software_type)
        return self.root[name]

    def get_software(self, name: str) -> Optional[Software]:
        """Получить ПО по названию"""
        return self.root.get(name)

    def add_vulnerability(self, software_name: str, version_str: str, vulnerability: Vulnerability,
                         vendor: str = "", software_type: str = "") -> None:
        """
        Добавить уязвимость в дерево
        
        Args:
            software_name: Название ПО
            version_str: Версия ПО
            vulnerability: Уязвимость
            vendor: Вендор (если новое ПО)
            software_type: Тип ПО (если новое ПО)
        """
        software = self.add_software(software_name, vendor, software_type)
        version = software.add_version(version_str)
        version.add_vulnerability(vulnerability)

    def find_vulnerabilities(self, software_name: str, version: Optional[str] = None) -> List[Vulnerability]:
        """
        Найти уязвимости для ПО и версии
        Поддерживает поиск в диапазонах версий (например, "от 8.4.0 до 8.4.16")
        
        Args:
            software_name: Название ПО
            version: Версия (если None, ищет для всех версий)
            
        Returns:
            Список уязвимостей
        """
        software = self.get_software(software_name)
        if not software:
            return []

        if version is None:
            # Вернуть все уязвимости для всех версий
            return software.get_all_vulnerabilities()
        else:
            # Сначала попробуй точное совпадение
            soft_version = software.get_version(version)
            if soft_version:
                return soft_version.vulnerabilities
            
            # Если точного совпадения нет, ищи в диапазонах
            return self._find_vulnerabilities_in_ranges(software, version)

    def _find_vulnerabilities_in_ranges(self, software, target_version: str) -> List[Vulnerability]:
        """
        Найти уязвимости для версии в диапазонах
        Проверяет версии, которые описывают диапазоны (например, "от 8.4.0 до 8.4.16")
        
        Args:
            software: Объект Software
            target_version: Целевая версия для поиска
            
        Returns:
            Список найденных уязвимостей
        """
        import re
        
        vulnerabilities = []
        
        try:
            # Попытаемся преобразовать версию в числовой формат для сравнения
            target_parts = self._parse_version(target_version)
            if not target_parts:
                return []
            
            # Ищи в версиях, которые содержат диапазоны
            for version_str, soft_version in software.versions.items():
                # Проверь, является ли это диапазоном
                if 'от' in version_str.lower() or 'до' in version_str.lower() or '-' in version_str:
                    # Извлеки граничные версии
                    start_version, end_version = self._parse_version_range(version_str)
                    
                    if start_version and end_version:
                        start_parts = self._parse_version(start_version)
                        end_parts = self._parse_version(end_version)
                        
                        if start_parts and end_parts:
                            # Сравни версии
                            if self._compare_versions(start_parts, target_parts) <= 0 and \
                               self._compare_versions(target_parts, end_parts) <= 0:
                                vulnerabilities.extend(soft_version.vulnerabilities)
                                continue
                
                # Также проверь точное совпадение (например, "12 (Firefox)")
                if target_version in version_str or version_str.startswith(target_version):
                    vulnerabilities.extend(soft_version.vulnerabilities)
        
        except Exception:
            pass
        
        return vulnerabilities

    @staticmethod
    def _parse_version(version_str: str) -> Optional[tuple]:
        """
        Парсить версию в список целых чисел для сравнения
        Например: "8.4.0" -> (8, 4, 0)
        
        Returns:
            Кортеж чисел или None
        """
        import re
        
        # Извлеки все числа из строки
        numbers = re.findall(r'\d+', version_str)
        if numbers:
            try:
                return tuple(int(n) for n in numbers)
            except ValueError:
                return None
        return None

    @staticmethod
    def _parse_version_range(version_str: str) -> tuple:
        """
        Извлечь начальную и конечную версию из строки диапазона
        Примеры:
        - "от 8.4.0 до 8.4.16 включительно" -> ("8.4.0", "8.4.16")
        - "от 9.0 до 9.15 включительно" -> ("9.0", "9.15")
        - "9.0.0 - 9.0.16" -> ("9.0.0", "9.0.16")
        
        Returns:
            Кортеж (start_version, end_version) или (None, None)
        """
        import re
        
        version_str_lower = version_str.lower()
        
        # Паттерн: "от X до Y"
        match = re.search(r'от\s+([\d.]+)\s+до\s+([\d.]+)', version_str_lower)
        if match:
            return (match.group(1), match.group(2))
        
        # Паттерн: "X - Y"
        match = re.search(r'([\d.]+)\s*-\s*([\d.]+)', version_str)
        if match:
            return (match.group(1), match.group(2))
        
        # Паттерн: "от X" (всё после X)
        match = re.search(r'от\s+([\d.]+)', version_str_lower)
        if match:
            return (match.group(1), "999.999.999")  # Очень большая версия как конец диапазона
        
        # Паттерн: "до X" (всё до X)
        match = re.search(r'до\s+([\d.]+)', version_str_lower)
        if match:
            return ("0.0.0", match.group(1))
        
        return (None, None)

    @staticmethod
    def _compare_versions(version1: tuple, version2: tuple) -> int:
        """
        Сравнить две версии (представленные как кортежи чисел)
        
        Returns:
            -1 если version1 < version2
            0 если version1 == version2
            1 если version1 > version2
        """
        for v1, v2 in zip(version1, version2):
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
        
        # Если одна версия является префиксом другой
        if len(version1) < len(version2):
            return -1
        elif len(version1) > len(version2):
            return 1
        
        return 0

    def get_statistics(self) -> dict:
        """Получить статистику дерева"""
        total_software = len(self.root)
        total_versions = sum(len(sw.versions) for sw in self.root.values())
        total_vulnerabilities = sum(len(sw.get_all_vulnerabilities()) for sw in self.root.values())
        
        # Подсчитай по уровням опасности
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        unknown_count = 0
        
        for software in self.root.values():
            for vuln in software.get_all_vulnerabilities():
                if hasattr(vuln, 'severity'):
                    if vuln.severity == SeverityLevel.CRITICAL:
                        critical_count += 1
                    elif vuln.severity == SeverityLevel.HIGH:
                        high_count += 1
                    elif vuln.severity == SeverityLevel.MEDIUM:
                        medium_count += 1
                    elif vuln.severity == SeverityLevel.LOW:
                        low_count += 1
                    else:
                        unknown_count += 1
                else:
                    unknown_count += 1

        return {
            'total_software': total_software,
            'total_versions': total_versions,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': critical_count,
            'high_vulnerabilities': high_count,
            'medium_vulnerabilities': medium_count,
            'low_vulnerabilities': low_count,
            'unknown_vulnerabilities': unknown_count,
        }

    def to_dict(self) -> dict:
        """Преобразование в словарь"""
        return {
            'statistics': self.get_statistics(),
            'software': {name: sw.to_dict() for name, sw in self.root.items()},
        }

    def __repr__(self) -> str:
        """Представление в виде строки"""
        stats = self.get_statistics()
        return (f"VulnerabilityTree(software={stats['total_software']}, "
                f"versions={stats['total_versions']}, "
                f"vulnerabilities={stats['total_vulnerabilities']}, "
                f"critical={stats['critical_vulnerabilities']})")
