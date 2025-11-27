"""
Загрузчик данных - интегрирует парсеры и управляет деревом уязвимостей
"""

import json
import pickle
from pathlib import Path
from typing import Optional

from .bdu_parser import BDUParser
from ..core.data_structures import VulnerabilityTree


class DataLoader:
    """
    Загрузчик данных от различных парсеров
    Может кешировать дерево уязвимостей для быстрого доступа
    """

    def __init__(self, cache_dir: str = "cache"):
        """
        Инициализация загрузчика
        
        Args:
            cache_dir: Директория для кеша
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.tree: Optional[VulnerabilityTree] = None

    def _get_cache_path(self, source: str) -> Path:
        """Получить путь до файла кеша"""
        return self.cache_dir / f"tree_{source}.cache"

    def load_bdu(self, file_path: str, use_cache: bool = True) -> VulnerabilityTree:
        """
        Загрузить дерево из БДУ
        
        Args:
            file_path: Путь к файлу full_data.xlsx
            use_cache: Использовать кеш если доступен
            
        Returns:
            VulnerabilityTree
        """
        cache_path = self._get_cache_path("bdu")

        # Проверь кеш
        if use_cache and cache_path.exists():
            print(f"Загрузка дерева из кеша: {cache_path}")
            with open(cache_path, 'rb') as f:
                self.tree = pickle.load(f)
            print("✓ Дерево загружено из кеша")
            return self.tree

        # Парсь данные
        print(f"Парсинг БДУ данных из {file_path}...")
        parser = BDUParser(file_path)
        self.tree = parser.build_tree()

        # Сохрани кеш
        if use_cache:
            print(f"Сохранение кеша: {cache_path}")
            with open(cache_path, 'wb') as f:
                pickle.dump(self.tree, f)
            print("✓ Кеш сохранён")

        return self.tree

    def get_tree(self) -> Optional[VulnerabilityTree]:
        """Получить загруженное дерево"""
        return self.tree

    def clear_cache(self, source: str = "bdu") -> None:
        """Очистить кеш"""
        cache_path = self._get_cache_path(source)
        if cache_path.exists():
            cache_path.unlink()
            print(f"✓ Кеш удалён: {cache_path}")

    def save_tree_to_json(self, output_path: str) -> None:
        """
        Сохранить дерево в JSON (для отладки)
        
        Args:
            output_path: Путь к выходному JSON файлу
        """
        if not self.tree:
            raise ValueError("Дерево не загружено")

        print(f"Сохранение дерева в JSON: {output_path}")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.tree.to_dict(), f, ensure_ascii=False, indent=2)
        print(f"✓ JSON сохранён ({output_path})")
