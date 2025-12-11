"""
Сканер системных программ - автоматическое обнаружение установленного ПО
"""

import os
import platform
import shutil
from pathlib import Path
from typing import List, Dict, Tuple, Optional
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
    
    def get_installed_packages_linux(self) -> List[Dict[str, str]]:
        """
        Получить список установленных пакетов Linux с версиями.
        Поддерживает: dpkg (Debian/Ubuntu), rpm (RHEL/CentOS/Fedora), 
        pacman (Arch), zypper (openSUSE), apk (Alpine)
        
        Returns:
            Список словарей: [{'name': 'package_name', 'version': '1.2.3', 'install_path': '/usr/bin/...'}, ...]
        """
        packages = []
        package_manager = self._detect_package_manager()
        
        if not package_manager:
            print("  ⚠️  Не найден поддерживаемый пакетный менеджер")
            return packages
        
        print(f"  📦 Пакетный менеджер: {package_manager}")
        
        try:
            if package_manager == "dpkg":
                packages = self._get_packages_dpkg()
            elif package_manager == "rpm":
                packages = self._get_packages_rpm()
            elif package_manager == "pacman":
                packages = self._get_packages_pacman()
            elif package_manager == "zypper":
                packages = self._get_packages_zypper()
            elif package_manager == "apk":
                packages = self._get_packages_apk()
        except Exception as e:
            print(f"  ⚠️  Ошибка получения списка пакетов: {e}")
        
        return packages
    
    def _detect_package_manager(self) -> Optional[str]:
        """Определить используемый пакетный менеджер"""
        # Проверяем в порядке популярности
        managers = [
            ("dpkg-query", "dpkg"),      # Debian, Ubuntu, Mint
            ("rpm", "rpm"),              # RHEL, CentOS, Fedora, openSUSE
            ("pacman", "pacman"),        # Arch, Manjaro
            ("zypper", "zypper"),        # openSUSE
            ("apk", "apk"),              # Alpine
        ]
        
        for cmd, name in managers:
            if shutil.which(cmd):
                return name
        
        return None
    
    def _get_packages_dpkg(self) -> List[Dict[str, str]]:
        """Получить пакеты через dpkg (Debian/Ubuntu)"""
        packages = []
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
                pkg_name = parts[0]
                pkg_version = parts[1] if len(parts) > 1 else 'unknown'
                packages.append({
                    'name': pkg_name,
                    'version': pkg_version,
                    'install_path': shutil.which(pkg_name) or f'/usr/bin/{pkg_name}'
                })
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  ⚠️  Ошибка dpkg-query: {e}")
        return packages
    
    def _get_packages_rpm(self) -> List[Dict[str, str]]:
        """Получить пакеты через rpm (RHEL/CentOS/Fedora)"""
        packages = []
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
                pkg_name = parts[0]
                pkg_version = parts[1] if len(parts) > 1 else 'unknown'
                packages.append({
                    'name': pkg_name,
                    'version': pkg_version,
                    'install_path': shutil.which(pkg_name) or f'/usr/bin/{pkg_name}'
                })
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  ⚠️  Ошибка rpm: {e}")
        return packages
    
    def _get_packages_pacman(self) -> List[Dict[str, str]]:
        """Получить пакеты через pacman (Arch Linux, Manjaro)"""
        packages = []
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
                pkg_name = parts[0]
                pkg_version = parts[1] if len(parts) > 1 else 'unknown'
                packages.append({
                    'name': pkg_name,
                    'version': pkg_version,
                    'install_path': shutil.which(pkg_name) or f'/usr/bin/{pkg_name}'
                })
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  ⚠️  Ошибка pacman: {e}")
        return packages
    
    def _get_packages_zypper(self) -> List[Dict[str, str]]:
        """Получить пакеты через zypper (openSUSE)"""
        packages = []
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
                pkg_name = parts[0]
                pkg_version = parts[1] if len(parts) > 1 else 'unknown'
                packages.append({
                    'name': pkg_name,
                    'version': pkg_version,
                    'install_path': shutil.which(pkg_name) or f'/usr/bin/{pkg_name}'
                })
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  ⚠️  Ошибка zypper/rpm: {e}")
        return packages
    
    def _get_packages_apk(self) -> List[Dict[str, str]]:
        """Получить пакеты через apk (Alpine Linux)"""
        packages = []
        try:
            output = subprocess.check_output(
                ["apk", "info", "-v"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=60
            )
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Формат: package-name-1.2.3-r0
                # Нужно разделить имя и версию
                match = re.match(r'^(.+?)-(\d+\..*)$', line)
                if match:
                    pkg_name = match.group(1)
                    pkg_version = match.group(2)
                else:
                    pkg_name = line
                    pkg_version = 'unknown'
                packages.append({
                    'name': pkg_name,
                    'version': pkg_version,
                    'install_path': shutil.which(pkg_name) or f'/usr/bin/{pkg_name}'
                })
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  ⚠️  Ошибка apk: {e}")
        return packages
