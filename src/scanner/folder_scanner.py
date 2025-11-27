"""
Сканер папок - рекурсивное сканирование директорий
"""

import os
from pathlib import Path
from typing import List, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.data_structures import VulnerabilityTree
from .file_scanner import FileScanner, VulnerabilityFinding


class FolderScanner:
    """
    Сканер для рекурсивного сканирования папок
    Поддерживает параллельную обработку файлов
    """
    
    def __init__(self, vulnerability_tree: VulnerabilityTree, max_workers: int = 4):
        """
        Инициализация сканера папок
        
        Args:
            vulnerability_tree: Дерево уязвимостей
            max_workers: Максимальное количество потоков для параллельной обработки
        """
        self.tree = vulnerability_tree
        self.max_workers = max_workers
        self.file_scanner = FileScanner(vulnerability_tree)
    
    def get_files_recursive(self, root_path: str, extensions: Optional[List[str]] = None,
                           exclude_patterns: Optional[List[str]] = None) -> List[str]:
        """
        Получить все файлы рекурсивно
        
        Args:
            root_path: Корневая папка для сканирования
            extensions: Список расширений для фильтрации (если None, включает все)
            exclude_patterns: Паттерны для исключения папок
            
        Returns:
            Список путей к файлам
        """
        root_path = Path(root_path)
        
        if not root_path.exists():
            raise FileNotFoundError(f"Папка {root_path} не найдена")
        
        files = []
        exclude_patterns = exclude_patterns or ['.git', '__pycache__', '.venv', 'node_modules']
        
        for root, dirs, filenames in os.walk(root_path):
            # Исключи папки
            dirs[:] = [d for d in dirs if not any(exc in d for exc in exclude_patterns)]
            
            for filename in filenames:
                file_path = os.path.join(root, filename)
                
                # Фильтруй по расширениям
                if extensions:
                    if not any(filename.endswith(ext) for ext in extensions):
                        continue
                
                files.append(file_path)
        
        return files
    
    def scan_folder(self, folder_path: str, progress_callback: Optional[Callable[[int, int], None]] = None,
                   parallel: bool = True) -> List[VulnerabilityFinding]:
        """
        Сканировать всю папку
        
        Args:
            folder_path: Путь к папке
            progress_callback: Функция обратного вызова для прогресса (current, total)
            parallel: Использовать параллельную обработку
            
        Returns:
            Список результатов сканирования
        """
        # Получи все файлы
        files = self.get_files_recursive(folder_path)
        
        if not files:
            print(f"Не найдено файлов для сканирования в {folder_path}")
            return []
        
        print(f"Найдено {len(files)} файлов для сканирования")
        
        findings = []
        
        if parallel and self.max_workers > 1:
            # Параллельное сканирование
            findings = self._scan_parallel(files, progress_callback)
        else:
            # Последовательное сканирование
            findings = self._scan_sequential(files, progress_callback)
        
        return findings
    
    def _scan_sequential(self, files: List[str], progress_callback: Optional[Callable] = None) -> List[VulnerabilityFinding]:
        """Последовательное сканирование файлов"""
        findings = []
        
        for i, file_path in enumerate(files):
            try:
                finding = self.file_scanner.scan_file(file_path)
                # Добавляй ВСЕ результаты сканирования, включая безопасные файлы
                if finding:
                    findings.append(finding)
            except Exception as e:
                # Создай запись о файле даже при ошибке
                finding = VulnerabilityFinding(file_path=file_path)
                findings.append(finding)
            
            # Вызови callback для прогресса
            if progress_callback:
                progress_callback(i + 1, len(files))
        
        return findings
    
    def _scan_parallel(self, files: List[str], progress_callback: Optional[Callable] = None) -> List[VulnerabilityFinding]:
        """Параллельное сканирование файлов"""
        findings = []
        completed = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Отправь задачи
            future_to_file = {executor.submit(self.file_scanner.scan_file, f): f for f in files}
            
            # Процессируй результаты по мере их завершения
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    # Добавляй ВСЕ результаты сканирования, включая безопасные файлы
                    if result:
                        findings.append(result)
                except Exception as e:
                    # Создай запись о файле даже при ошибке
                    finding = VulnerabilityFinding(file_path=file_path)
                    findings.append(finding)
                
                # Обнови прогресс
                completed += 1
                if progress_callback:
                    progress_callback(completed, len(files))
        
        return findings
    
    def get_statistics(self) -> dict:
        """Получить статистику сканирования"""
        return self.file_scanner.get_statistics()
