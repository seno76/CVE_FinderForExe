"""
Сканер на основе реестра Windows
Получает установленные программы и версии из реестра и проверяет их в БДУ
"""

import sys
from typing import List, Dict, Optional, Callable
from pathlib import Path

if sys.platform == 'win32':
    from ..detectors.software_detector import get_installed_software_from_registry


class RegistrySoftwareInfo:
    """Информация о программе из реестра"""
    
    def __init__(self, name: str, version: str, install_path: str):
        self.name = name
        self.version = version
        self.install_path = install_path
    
    def __repr__(self):
        return f"RegistrySoftwareInfo(name={self.name}, version={self.version})"


class RegistryScanner:
    """
    Сканер, работающий на основе реестра Windows
    Получает список установленного ПО и проверяет версии в дереве уязвимостей
    """
    
    def __init__(self, vulnerability_tree):
        """
        Инициализация сканера
        
        Args:
            vulnerability_tree: VulnerabilityTree для поиска уязвимостей
        """
        self.tree = vulnerability_tree
        self.installed_software = []
    
    def get_installed_software(self) -> List[RegistrySoftwareInfo]:
        """
        Получить список установленного ПО из реестра Windows
        
        Returns:
            Список RegistrySoftwareInfo
        """
        if sys.platform != 'win32':
            print("⚠️  Сканирование по реестру доступно только на Windows")
            return []
        
        try:
            registry_data = get_installed_software_from_registry()
            
            software_list = []
            for name, info in registry_data.items():
                version = info.get('version', 'unknown')
                install_path = info.get('install_path', 'unknown')
                
                software_list.append(
                    RegistrySoftwareInfo(
                        name=name,
                        version=version,
                        install_path=install_path
                    )
                )
            
            self.installed_software = software_list
            return software_list
        
        except Exception as e:
            print(f"❌ Ошибка при чтении реестра: {e}")
            return []
    
    def scan_registry(self, progress_callback: Optional[Callable] = None) -> List[Dict]:
        """
        Сканировать установленное ПО из реестра
        Проверить каждую программу и версию в дереве уязвимостей
        
        Args:
            progress_callback: Функция для отображения прогресса (current, total)
            
        Returns:
            Список результатов сканирования
        """
        if not self.installed_software:
            self.get_installed_software()
        
        results = []
        total = len(self.installed_software)
        
        for idx, software in enumerate(self.installed_software):
            # Обновить прогресс
            if progress_callback:
                progress_callback(idx, total)
            
            # Найти в дереве уязвимостей
            vulnerabilities = self.tree.find_vulnerabilities(
                software.name,
                software.version
            )
            
            result = {
                'software_name': software.name,
                'software_version': software.version,
                'install_path': software.install_path,
                'vulnerabilities': vulnerabilities,
                'has_vulnerabilities': len(vulnerabilities) > 0,
                'vulnerability_count': len(vulnerabilities),
                'critical_count': len([v for v in vulnerabilities if v.severity.value == 'critical']),
                'high_count': len([v for v in vulnerabilities if v.severity.value == 'high']),
                'medium_count': len([v for v in vulnerabilities if v.severity.value == 'medium']),
                'low_count': len([v for v in vulnerabilities if v.severity.value == 'low']),
            }
            
            results.append(result)
        
        if progress_callback:
            progress_callback(total, total)
        
        return results
    
    def get_statistics(self, scan_results: List[Dict]) -> Dict:
        """
        Получить статистику сканирования
        
        Args:
            scan_results: Результаты сканирования
            
        Returns:
            Словарь со статистикой
        """
        total_software = len(scan_results)
        software_with_vulns = len([r for r in scan_results if r['has_vulnerabilities']])
        
        total_vulns = sum(r['vulnerability_count'] for r in scan_results)
        critical = sum(r['critical_count'] for r in scan_results)
        high = sum(r['high_count'] for r in scan_results)
        medium = sum(r['medium_count'] for r in scan_results)
        low = sum(r['low_count'] for r in scan_results)
        
        return {
            'total_software': total_software,
            'software_with_vulnerabilities': software_with_vulns,
            'total_vulnerabilities': total_vulns,
            'critical_vulnerabilities': critical,
            'high_vulnerabilities': high,
            'medium_vulnerabilities': medium,
            'low_vulnerabilities': low,
        }
