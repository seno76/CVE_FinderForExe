"""
Парсер для загрузки данных из БДУ ФСТЕК (full_data.xlsx)
"""

import pandas as pd
import re
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from enum import Enum

from ..core.data_structures import Vulnerability, SeverityLevel, VulnerabilityTree


class BDUParser:
    """
    Парсер данных из БДУ ФСТЕК
    Загружает данные из Excel файла и создаёт дерево уязвимостей
    """

    # Маппинг текста уровня опасности на SeverityLevel
    SEVERITY_MAPPING = {
        'критический': SeverityLevel.CRITICAL,
        'critical': SeverityLevel.CRITICAL,
        'высокий': SeverityLevel.HIGH,
        'high': SeverityLevel.HIGH,
        'средний': SeverityLevel.MEDIUM,
        'medium': SeverityLevel.MEDIUM,
        'низкий': SeverityLevel.LOW,
        'low': SeverityLevel.LOW,
    }

    def __init__(self, file_path: str):
        """
        Инициализация парсера
        
        Args:
            file_path: Путь к файлу full_data.xlsx
        """
        self.file_path = Path(file_path)
        self.df = None
        self._load_data()

    def _load_data(self) -> None:
        """Загрузить данные из Excel файла"""
        if not self.file_path.exists():
            raise FileNotFoundError(f"Файл {self.file_path} не найден")

        print(f"Загрузка данных из {self.file_path}...")
        self.df = pd.read_excel(self.file_path, header=2)  # Заголовки в строке 3 (индекс 2)
        print(f"✓ Загружено {len(self.df)} уязвимостей")

    def _parse_severity(self, severity_text: Optional[str]) -> SeverityLevel:
        """
        Парсить уровень опасности из текста
        
        Args:
            severity_text: Текст с описанием уровня опасности
            
        Returns:
            SeverityLevel
        """
        if not severity_text or not isinstance(severity_text, str):
            return SeverityLevel.UNKNOWN

        text_lower = severity_text.lower()
        
        # Проверь начало текста
        for keyword, level in self.SEVERITY_MAPPING.items():
            if text_lower.startswith(keyword):
                return level

        return SeverityLevel.UNKNOWN

    def _extract_cve_id(self, cve_field: Optional[str]) -> Optional[str]:
        """
        Извлечь CVE ID из поля
        
        Args:
            cve_field: Значение из поля "Идентификаторы других систем..."
            
        Returns:
            CVE ID или None
        """
        if not cve_field or not isinstance(cve_field, str):
            return None

        # Ищи CVE-XXXX-XXXXX
        match = re.search(r'CVE-\d{4}-\d+', cve_field)
        return match.group(0) if match else None

    def _extract_cwe_id(self, cwe_field: Optional[str]) -> Optional[str]:
        """
        Извлечь CWE ID из поля
        
        Args:
            cwe_field: Значение из поля "Тип ошибки CWE"
            
        Returns:
            CWE ID или None
        """
        if not cwe_field or not isinstance(cwe_field, str):
            return None

        # Ищи CWE-XXXXX
        match = re.search(r'CWE-\d+', cwe_field)
        return match.group(0) if match else None

    def _parse_cvss_score(self, score_str: Optional[str]) -> Optional[float]:
        """
        Парсить CVSS оценку
        
        Args:
            score_str: Строка с CVSS оценкой (например, "AV:N/AC:L/Au:N/C:C/I:C/A:C")
            
        Returns:
            Число от 0 до 10 или None
        """
        if not score_str or not isinstance(score_str, str):
            return None

        # Если это вектор CVSS (AV:N/AC:L...), пока вернём None
        # В будущем можно добавить парсинг вектора
        if score_str.startswith('AV:'):
            return None

        # Попробуй преобразовать в число
        try:
            return float(score_str)
        except (ValueError, TypeError):
            return None

    def parse_row(self, row: pd.Series) -> Optional[Tuple[str, str, Vulnerability]]:
        """
        Парсить одну строку из DataFrame
        
        Args:
            row: Строка DataFrame
            
        Returns:
            Кортеж (software_name, version_str, Vulnerability) или None
        """
        try:
            # Получи основные поля
            bdu_id = str(row.get('Идентификатор', '')).strip()
            if not bdu_id or bdu_id == 'nan':
                return None

            software_name = str(row.get('Название ПО', '')).strip()
            if not software_name or software_name == 'nan':
                return None

            version_str = str(row.get('Версия ПО', '')).strip()
            if not version_str or version_str == 'nan':
                version_str = 'unknown'

            # Создай объект Vulnerability
            vulnerability = Vulnerability(
                bdu_id=bdu_id,
                cve_id=self._extract_cve_id(row.get('Идентификаторы других систем описаний уязвимости')),
                name=str(row.get('Наименование уязвимости', '')).strip(),
                description=str(row.get('Описание уязвимости', '')).strip(),
                severity=self._parse_severity(row.get('Уровень опасности уязвимости')),
                cvss_2_0=self._parse_cvss_score(row.get('CVSS 2.0')),
                cvss_3_0=self._parse_cvss_score(row.get('CVSS 3.0')),
                cvss_4_0=self._parse_cvss_score(row.get('CVSS 4.0')),
                vulnerability_class=str(row.get('Класс уязвимости', '')).strip(),
                cwe_id=self._extract_cwe_id(row.get('Тип ошибки CWE')),
                cwe_description=str(row.get('Описание ошибки CWE', '')).strip(),
                published_date=str(row.get('Дата публикации', '')).strip(),
                exploit_available='Существует' in str(row.get('Наличие эксплойта', '')),
            )
            
            # Добавь рекомендации в additional_info
            vulnerability.additional_info['recommendations'] = str(row.get('Возможные меры по устранению', '')).strip()
            vulnerability.additional_info['remediation'] = str(row.get('Способ устранения', '')).strip()
            vulnerability.additional_info['status'] = str(row.get('Статус уязвимости', '')).strip()

            return (software_name, version_str, vulnerability)

        except Exception as e:
            print(f"⚠ Ошибка парсинга строки {bdu_id}: {e}")
            return None

    def build_tree(self) -> VulnerabilityTree:
        """
        Построить дерево уязвимостей из данных
        
        Returns:
            VulnerabilityTree
        """
        print("Построение дерева уязвимостей...")
        tree = VulnerabilityTree()

        processed = 0
        skipped = 0

        for idx, row in self.df.iterrows():
            result = self.parse_row(row)
            if result:
                software_name, version_str, vulnerability = result
                vendor = str(row.get('Вендор ПО', '')).strip()
                software_type = str(row.get('Тип ПО', '')).strip()

                tree.add_vulnerability(
                    software_name=software_name,
                    version_str=version_str,
                    vulnerability=vulnerability,
                    vendor=vendor,
                    software_type=software_type
                )
                processed += 1
            else:
                skipped += 1

            # Показывай прогресс каждые 10000 строк
            if (idx + 1) % 10000 == 0:
                print(f"  Обработано {idx + 1}/{len(self.df)} строк...")

        print(f"✓ Дерево построено: {processed} уязвимостей добавлено, {skipped} пропущено")
        
        stats = tree.get_statistics()
        print(f"  • ПО в базе: {stats['total_software']:,}")
        print(f"  • Версий: {stats['total_versions']:,}")
        print(f"  • Всего уязвимостей: {stats['total_vulnerabilities']:,}")
        print(f"  • Критических: {stats['critical_vulnerabilities']:,}")
        print(f"  • Высоких: {stats['high_vulnerabilities']:,}")
        print(f"  • Средних: {stats['medium_vulnerabilities']:,}")
        print(f"  • Низких: {stats['low_vulnerabilities']:,}")

        return tree

    def get_top_vulnerable_software(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Получить топ наиболее уязвимого ПО
        
        Args:
            limit: Количество ПО
            
        Returns:
            Список кортежей (название_ПО, кол-во_уязвимостей)
        """
        software_counts = self.df['Название ПО'].value_counts().head(limit)
        return list(zip(software_counts.index, software_counts.values))
