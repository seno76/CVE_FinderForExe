#!/usr/bin/env python3
"""
Консольный сканер уязвимостей
Использование: python cli_scanner.py --folder <path> [options]
"""

import argparse
import sys
import json
import io
from pathlib import Path
import time

# Установи правильную кодировку для консоли
if sys.platform == 'win32':
    import os
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    # Перенаправь stdout в UTF-8
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Добавь корневую директорию проекта в путь
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parsers import DataLoader
from src.scanner import FolderScanner
from src.reports import ReportGenerator


def print_banner():
    """Вывести баннер приложения"""
    print("""
    ╔══════════════════════════════════════════╗
    ║   Bochka - Сканер Уязвимостей ПО        ║
    ║   Vulnerability Scanner v0.1.0          ║
    ╚══════════════════════════════════════════╝
    """)


def progress_bar(current: int, total: int, length: int = 40):
    """Вывести прогресс-бар"""
    if total == 0:
        return
    
    percent = 100 * current / total
    filled = int(length * current / total)
    bar = '█' * filled + '░' * (length - filled)
    
    print(f'\r[{bar}] {percent:.1f}% ({current}/{total})', end='', flush=True)


def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(
        description='Сканер уязвимостей программного обеспечения',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python cli_scanner.py --folder "C:\\Program Files" --output report.json
  python cli_scanner.py --folder "/usr/bin" --output report.json --html report.html
  python cli_scanner.py --folder "/opt" --json-output data.json --verbose
        """
    )
    
    parser.add_argument(
        '--folder', '-f',
        required=True,
        help='Папка для сканирования'
    )
    parser.add_argument(
        '--json-output', '-o',
        help='Путь для сохранения JSON отчёта'
    )
    parser.add_argument(
        '--html-output', '-H',
        help='Путь для сохранения HTML отчёта'
    )
    parser.add_argument(
        '--bdu-data',
        default='data/full_data.xlsx',
        help='Путь к файлу БДУ данных (по умолчанию: data/full_data.xlsx)'
    )
    parser.add_argument(
        '--use-cache',
        action='store_true',
        default=True,
        help='Использовать кеш дерева уязвимостей (по умолчанию: да)'
    )
    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Не использовать кеш (пересчитать дерево)'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=4,
        help='Количество потоков для параллельного сканирования (по умолчанию: 4)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Подробный вывод'
    )
    parser.add_argument(
        '--system-scan',
        action='store_true',
        help='Сканировать системные программы вместо указанной папки'
    )
    
    args = parser.parse_args()
    
    # Выведи баннер
    print_banner()
    
    # Проверь аргументы
    if not args.system_scan and not Path(args.folder).exists():
        print(f"❌ Ошибка: Папка {args.folder} не существует")
        return 1
    
    if not Path(args.bdu_data).exists():
        print(f"❌ Ошибка: Файл БДУ данных {args.bdu_data} не найден")
        return 1
    
    if not args.json_output and not args.html_output:
        print("⚠ Предупреждение: Не указаны пути для сохранения отчётов")
        args.json_output = 'report.json'
        args.html_output = 'report.html'
        print(f"  JSON будет сохранён в: {args.json_output}")
        print(f"  HTML будет сохранён в: {args.html_output}")
    
    try:
        # 1. Загрузи дерево уязвимостей
        print("\n📋 Загрузка дерева уязвимостей БДУ...")
        print(f"   📂 Источник: {args.bdu_data}")
        
        # Информация о файле
        bdu_file = Path(args.bdu_data)
        if bdu_file.exists():
            file_size_mb = bdu_file.stat().st_size / (1024 * 1024)
            print(f"   📊 Размер файла: {file_size_mb:.2f} МБ")
        
        loader = DataLoader(cache_dir='cache')
        use_cache = args.use_cache and not args.no_cache
        start_load = time.time()
        tree = loader.load_bdu(args.bdu_data, use_cache=use_cache)
        load_time = time.time() - start_load
        
        stats = tree.get_statistics()
        print(f"\n✅ База данных загружена ({load_time:.2f} сек)")
        print(f"   • ПО в базе: {stats['total_software']:,}")
        print(f"   • Версий: {stats['total_versions']:,}")
        print(f"   • Всего уязвимостей: {stats['total_vulnerabilities']:,}")
        print(f"   • Критических: {stats['critical_vulnerabilities']:,}")
        print(f"   • Высоких: {stats['high_vulnerabilities']:,}")
        print(f"   • Средних: {stats['medium_vulnerabilities']:,}")
        
        # 2. Запусти сканирование
        print(f"\n🔍 Сканирование папки: {args.folder}")
        scanner = FolderScanner(tree, max_workers=args.workers)
        
        start_time = time.time()
        
        # Функция для отображения прогресса
        def show_progress(current, total):
            progress_bar(current, total)
        
        findings = scanner.scan_folder(
            args.folder,
            progress_callback=show_progress,
            parallel=args.workers > 1
        )
        
        elapsed_time = time.time() - start_time
        print(f"\n✓ Сканирование завершено за {elapsed_time:.2f} сек")
        findings_with_vulns = [f for f in findings if f.has_vulnerabilities()]
        
        # Подсчёт по уровням опасности
        total_vulns = 0
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        low_vulns = 0
        
        for f in findings_with_vulns:
            for v in f.vulnerabilities:
                total_vulns += 1
                if hasattr(v, 'severity'):
                    if v.severity == 'CRITICAL':
                        critical_vulns += 1
                    elif v.severity == 'HIGH':
                        high_vulns += 1
                    elif v.severity == 'MEDIUM':
                        medium_vulns += 1
                    elif v.severity == 'LOW':
                        low_vulns += 1
        
        print(f"\n📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ:")
        print(f"  📁 Всего файлов найдено: {len(findings)}")
        print(f"  🔴 Файлов с уязвимостями: {len(findings_with_vulns)}")
        print(f"  📈 Всего уязвимостей: {total_vulns}")
        print(f"     🔴 Критических: {critical_vulns}")
        print(f"     🟠 Высоких: {high_vulns}")
        print(f"     🟡 Средних: {medium_vulns}")
        print(f"     🟢 Низких: {low_vulns}")
        
        # 4. Сохранение отчётов
        print(f"\n📄 Генерирование отчётов...")
        
        report_gen = ReportGenerator()
        report_gen.add_findings(findings)
        
        if args.json_output:
            report_gen.generate_json(args.json_output)
            print(f"   ✅ JSON: {args.json_output}")
        
        if args.html_output:
            report_gen.generate_html(args.html_output)
            print(f"   ✅ HTML: {args.html_output}")
        
        print(f"\n✅ Готово!")
        return 0
        
    except KeyboardInterrupt:
        print("\n\n❌ Сканирование прервано пользователем")
        return 130
    except Exception as e:
        print(f"\n\n❌ Ошибка: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
