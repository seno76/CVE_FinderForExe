"""
Анализатор файлов для определения типа и свойств файла
"""

import os
import struct
from pathlib import Path
from typing import Optional, Dict


class FileAnalyzer:
    """
    Анализирует файлы для определения:
    - Является ли файл исполняемым
    - Типа файла
    - Основной информации о файле
    """

    # Магические числа для определения типа файла
    MAGIC_SIGNATURES = {
        # Windows executables
        b'MZ': 'windows_exe',  # .exe, .dll
        
        # Linux executables
        b'\x7fELF': 'linux_elf',
        
        # Archives
        b'PK\x03\x04': 'zip',
        b'\x42\x5a': 'bzip2',
        b'\x1f\x8b': 'gzip',
        b'7z\xbc\xaf\x27\x1c': 'seven_zip',
        
        # Documents
        b'%PDF': 'pdf',
        b'PK': 'office_open',  # docx, xlsx, etc
        
        # Scripts
        b'#!/': 'script',
    }

    # Расширения файлов для исполняемых файлов
    EXECUTABLE_EXTENSIONS = {
        '.exe', '.sys', '.scr',  # Windows (только .exe для анализа)
        '.elf', '.so', '.sh', '.bin',    # Linux/Unix
        '.app', '.deb', '.rpm',          # Package managers
        '.msi', '.cab',                  # Windows installers
        '.jar', '.class',                # Java
        '.py', '.pyc',                   # Python
        '.js', '.ts',                    # JavaScript/TypeScript
    }

    # Безопасные расширения (НЕ анализировать)
    SAFE_EXTENSIONS = {
        '.txt', '.log', '.md', '.json', '.xml', '.html', '.css',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
        '.mp3', '.mp4', '.wav', '.avi',
    }

    def __init__(self):
        """Инициализация анализатора"""
        pass

    @staticmethod
    def is_executable(file_path: str) -> bool:
        """
        Проверить, является ли файл исполняемым
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            True если файл исполняемый
        """
        path = Path(file_path)
        
        # Проверь расширение
        if path.suffix.lower() in FileAnalyzer.EXECUTABLE_EXTENSIONS:
            return True

        # Проверь магический номер
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
                
                for magic, file_type in FileAnalyzer.MAGIC_SIGNATURES.items():
                    if header.startswith(magic):
                        # Проверь, исполняемый ли это файл
                        if file_type in ['windows_exe', 'linux_elf', 'script']:
                            return True
        except (IOError, OSError):
            return False

        return False

    @staticmethod
    def is_safe_to_ignore(file_path: str) -> bool:
        """
        Проверить, нужно ли игнорировать файл при сканировании
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            True если файл можно игнорировать
        """
        path = Path(file_path)
        
        # Игнорируй безопасные расширения
        if path.suffix.lower() in FileAnalyzer.SAFE_EXTENSIONS:
            return True
        
        # Игнорируй скрытые файлы и папки
        if path.name.startswith('.'):
            return True
        
        # Игнорируй системные папки
        if path.name in ['.git', '.venv', '__pycache__', 'node_modules', '.vscode']:
            return True

        return False

    @staticmethod
    def get_file_type(file_path: str) -> Optional[str]:
        """
        Определить тип файла
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            Тип файла (windows_exe, linux_elf, zip, script и т.д.) или None
        """
        path = Path(file_path)
        
        # По расширению
        ext = path.suffix.lower()
        if ext == '.exe':
            return 'windows_exe'
        elif ext == '.dll':
            return 'windows_dll'
        elif ext in ['.so', '.elf']:
            return 'linux_elf'
        elif ext in ['.py', '.pyc']:
            return 'python'
        elif ext in ['.sh', '.bash']:
            return 'bash_script'
        
        # По магическому номеру
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
                
                for magic, file_type in FileAnalyzer.MAGIC_SIGNATURES.items():
                    if header.startswith(magic):
                        return file_type
        except (IOError, OSError):
            pass

        return None

    @staticmethod
    def get_file_info(file_path: str) -> Dict[str, any]:
        """
        Получить информацию о файле
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            Словарь с информацией о файле
        """
        path = Path(file_path)
        
        info = {
            'path': str(path.absolute()),
            'name': path.name,
            'extension': path.suffix.lower(),
            'is_file': path.is_file(),
            'size': 0,
            'is_executable': False,
            'file_type': None,
        }
        
        try:
            if path.is_file():
                info['size'] = path.stat().st_size
                info['is_executable'] = FileAnalyzer.is_executable(file_path)
                info['file_type'] = FileAnalyzer.get_file_type(file_path)
        except (IOError, OSError):
            pass

        return info

