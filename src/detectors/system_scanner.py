"""
Сканер системных программ - автоматическое обнаружение установленного ПО
"""

import os
import platform
import shutil
from pathlib import Path
from typing import List, Dict, Tuple
import subprocess
import re


class SystemScanner:
    """
    Сканирует систему и находит установленное ПО
    """
    
    def __init__(self):
        """Инициализация"""
        self.system = platform.system()  # 'Windows', 'Linux', 'Darwin'
        self.program_paths: List[str] = []
    
    def scan_system(self) -> List[str]:
        """
        Сканировать систему и получить пути ко всем исполняемым файлам
        
        Returns:
            Список путей к программам
        """
        print(f"Сканирование системы ({self.system})...")
        
        if self.system == 'Windows':
            return self._scan_windows()
        elif self.system == 'Linux':
            return self._scan_linux()
        elif self.system == 'Darwin':
            return self._scan_macos()
        else:
            print(f"⚠ Система {self.system} не поддерживается")
            return []
    
    def _scan_windows(self) -> List[str]:
        """Сканирование Windows"""
        programs = []
        
        # Путями по умолчанию на Windows
        search_paths = [
            'C:\\Program Files',
            'C:\\Program Files (x86)',
            'C:\\ProgramData',
            'C:\\Windows\\System32',
        ]
        
        for base_path in search_paths:
            if os.path.exists(base_path):
                print(f"  Сканирование {base_path}...")
                for root, dirs, files in os.walk(base_path):
                    # Ограничи глубину поиска
                    if root.count(os.sep) - base_path.count(os.sep) > 3:
                        continue
                    
                    for file in files:
                        if file.lower().endswith(('.exe', '.dll')):
                            full_path = os.path.join(root, file)
                            programs.append(full_path)
                    
                    # Исключи некоторые папки
                    dirs[:] = [d for d in dirs if d not in ['$Recycle.Bin', 'System Volume Information']]
        
        return programs[:1000]  # Ограничь результаты для демонстрации
    
    def _scan_linux(self) -> List[str]:
        """Сканирование Linux"""
        # Попробуй получить список установленных пакетов через пакетный менеджер
        package_programs = self._scan_linux_package_manager()
        if package_programs:
            print(f"  Найдено установленных программ: {len(package_programs)}")
            return package_programs[:500]
        
        # Фоллбек: обход стандартных путей (как раньше)
        programs = []
        
        # Общие пути для Linux
        search_paths = [
            '/usr/bin',
            '/usr/local/bin',
            '/opt',
            '/usr/lib',
        ]
        
        for base_path in search_paths:
            if os.path.exists(base_path):
                print(f"  Сканирование {base_path}...")
                for root, dirs, files in os.walk(base_path):
                    # Ограничь глубину
                    if root.count(os.sep) - base_path.count(os.sep) > 2:
                        continue
                    
                    for file in files:
                        full_path = os.path.join(root, file)
                        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                            programs.append(full_path)
                    
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
        
        return programs[:500]
    
    def _scan_linux_package_manager(self) -> List[str]:
        """
        Получить список установленных программ через пакетный менеджер (dpkg/rpm)
        
        Returns:
            Список путей к найденным исполняемым файлам
        """
        programs = set()
        
        # Debian/Ubuntu: используем dpkg-query
        if shutil.which("dpkg-query"):
            try:
                output = subprocess.check_output(
                    ["dpkg-query", "-W", "-f=${Package}\n"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
                for line in output.splitlines():
                    pkg_name = line.strip()
                    if not pkg_name:
                        continue
                    
                    # Часто имя пакета совпадает с исполняемым файлом
                    bin_path = shutil.which(pkg_name)
                    if bin_path:
                        programs.add(bin_path)
            except subprocess.CalledProcessError:
                print("  ⚠️  Не удалось получить список пакетов из dpkg-query")
        
        # RHEL/CentOS/Fedora: rpm
        elif shutil.which("rpm"):
            try:
                output = subprocess.check_output(
                    ["rpm", "-qa", "--qf", "%{NAME}\n"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
                for line in output.splitlines():
                    pkg_name = line.strip()
                    if not pkg_name:
                        continue
                    
                    bin_path = shutil.which(pkg_name)
                    if bin_path:
                        programs.add(bin_path)
            except subprocess.CalledProcessError:
                print("  ⚠️  Не удалось получить список пакетов из rpm")
        
        return sorted(programs)
    
    def get_installed_packages_linux(self) -> List[Dict[str, str]]:
        """
        Получить список установленных пакетов Linux с версиями (аналог реестра Windows)
        
        Returns:
            Список словарей: [{'name': 'package_name', 'version': '1.2.3'}, ...]
        """
        packages = []
        package_manager = None
        
        # Debian/Ubuntu: dpkg-query
        if shutil.which("dpkg-query"):
            package_manager = "dpkg"
            try:
                output = subprocess.check_output(
                    ["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=120
                )
                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(' ', 1)
                    if len(parts) >= 2:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1],
                            'install_path': shutil.which(parts[0]) or f'/usr/bin/{parts[0]}'
                        })
                    elif len(parts) == 1:
                        packages.append({
                            'name': parts[0],
                            'version': 'unknown',
                            'install_path': shutil.which(parts[0]) or f'/usr/bin/{parts[0]}'
                        })
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                print(f"  ⚠️  Ошибка dpkg-query: {e}")
        
        # RHEL/CentOS/Fedora: rpm
        elif shutil.which("rpm"):
            package_manager = "rpm"
            try:
                output = subprocess.check_output(
                    ["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\n"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=120
                )
                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(' ', 1)
                    if len(parts) >= 2:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1],
                            'install_path': shutil.which(parts[0]) or f'/usr/bin/{parts[0]}'
                        })
                    elif len(parts) == 1:
                        packages.append({
                            'name': parts[0],
                            'version': 'unknown',
                            'install_path': shutil.which(parts[0]) or f'/usr/bin/{parts[0]}'
                        })
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                print(f"  ⚠️  Ошибка rpm: {e}")
        
        # Arch Linux: pacman
        elif shutil.which("pacman"):
            package_manager = "pacman"
            try:
                output = subprocess.check_output(
                    ["pacman", "-Q"],
                    text=True,
                    stderr=subprocess.DEVNULL,
                    timeout=60
                )
                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(' ', 1)
                    if len(parts) >= 2:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1],
                            'install_path': shutil.which(parts[0]) or f'/usr/bin/{parts[0]}'
                        })
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                print(f"  ⚠️  Ошибка pacman: {e}")
        
        if package_manager:
            print(f"  📦 Пакетный менеджер: {package_manager}")
        else:
            print("  ⚠️  Не найден поддерживаемый пакетный менеджер (dpkg/rpm/pacman)")
        
        return packages
    
    def _scan_macos(self) -> List[str]:
        """Сканирование macOS"""
        programs = []
        
        search_paths = [
            '/Applications',
            '/usr/local/bin',
            '/usr/bin',
            '/opt/local/bin',
        ]
        
        for base_path in search_paths:
            if os.path.exists(base_path):
                print(f"  Сканирование {base_path}...")
                for root, dirs, files in os.walk(base_path):
                    if root.count(os.sep) - base_path.count(os.sep) > 2:
                        continue
                    
                    for file in files:
                        full_path = os.path.join(root, file)
                        if os.path.isfile(full_path):
                            programs.append(full_path)
                    
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
        
        return programs[:500]
    
    def get_installed_software_info(self) -> Dict[str, List[str]]:
        """
        Получить информацию об установленном ПО
        
        Returns:
            Словарь с информацией по категориям
        """
        info = {
            'browsers': [],
            'databases': [],
            'webservers': [],
            'interpreters': [],
            'other': [],
        }
        
        programs = self.scan_system()
        
        for program in programs:
            name_lower = Path(program).name.lower()
            
            # Классификация
            if any(x in name_lower for x in ['firefox', 'chrome', 'edge', 'opera', 'safari']):
                info['browsers'].append(program)
            elif any(x in name_lower for x in ['mysql', 'postgres', 'mongodb', 'oracle']):
                info['databases'].append(program)
            elif any(x in name_lower for x in ['apache', 'nginx', 'iis']):
                info['webservers'].append(program)
            elif any(x in name_lower for x in ['python', 'java', 'node', 'php', 'ruby']):
                info['interpreters'].append(program)
            else:
                info['other'].append(program)
        
        return info
