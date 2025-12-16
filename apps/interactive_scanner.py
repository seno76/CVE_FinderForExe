
"""
Интерактивный сканер уязвимостей с выбором режима сканирования
"""

import sys
import time
import io
from pathlib import Path

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
from src.scanner import FolderScanner, FileScanner, RegistryScanner
from src.detectors.system_scanner import SystemScanner
from src.reports import ReportGenerator


def print_banner():
    """Вывести баннер приложения"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║          🔐 Bochka - Сканер Уязвимостей                 ║
    ║       Vulnerability Scanner v1.0 (Interactive)           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)


def progress_bar(current: int, total: int, length: int = 40):
    """Вывести прогресс-бар"""
    if total == 0:
        return
    
    percent = 100 * current / total
    filled = int(length * current / total)
    bar = '█' * filled + '░' * (length - filled)
    
    print(f'\r[{bar}] {percent:.1f}% ({current}/{total})', end='', flush=True)


def show_menu():
    """Показать меню выбора режима сканирования"""
    is_windows = sys.platform == 'win32'
    
    print("\n" + "="*70)
    print("                    ВЫБЕРИТЕ РЕЖИМ СКАНИРОВАНИЯ".center(70))
    print("="*70)
    print("""
    📁 ВЫБОР ПУТИ:
    ├─ 1. Сканировать конкретный FILE
    ├─ 2. Сканировать конкретную ПАПКУ
    ├─ 3. Сканировать несколько папок
    │""", end='')
    
    if is_windows:
        print("""
    💻 СИСТЕМНОЕ СКАНИРОВАНИЕ (Windows):
    ├─ 4. Сканировать C:\\Program Files (Windows)
    ├─ 5. Сканировать C:\\Program Files (x86) (Windows)
    ├─ 8. Полное системное сканирование (все программы)""")
    else:
        print("""
    💻 СИСТЕМНОЕ СКАНИРОВАНИЕ (Linux):
    ├─ 4. Сканировать /usr/bin
    ├─ 5. Сканировать /usr/local/bin
    ├─ 6. Сканировать /opt
    ├─ 7. Сканировать /home (пользовательские программы)
    ├─ 8. Полное системное сканирование (все стандартные папки)""")
    
    if is_windows:
        print("""
    🪟 СКАНИРОВАНИЕ РЕЕСТРА (Windows):
    ├─ 9. Сканировать установленные программы (из реестра)
    │
    💾 КОМБИНИРОВАННОЕ СКАНИРОВАНИЕ:
    ├─ 10. Реестр + ВСЕ ДИСКИ (Program Files на всех дисках)""")
    
    print("""
    🛑 ЗАВЕРШЕНИЕ:
    └─ 0. Выход
    
    """.rstrip())


def get_choice():
    """Получить выбор пользователя"""
    while True:
        choice = input("Выберите опцию (0-10): ").strip()
        if choice in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10']:
            return choice
        print("❌ Неверный выбор. Пожалуйста, выберите 0-10.")


def get_file_path():
    """Получить путь к файлу от пользователя"""
    while True:
        path = input("\n📄 Укажите путь к файлу: ").strip()
        
        # Убери кавычки если их вввел пользователь
        path = path.strip('"\'')
        
        file = Path(path)
        
        if not file.exists():
            print(f"❌ Файл не существует: {path}")
            continue
        
        if not file.is_file():
            print(f"❌ Это не файл: {path}")
            continue
        
        return str(file.absolute())


def get_folder_path():
    """Получить путь к папке от пользователя"""
    while True:
        path = input("\n📁 Укажите путь к папке: ").strip()
        
        # Убери кавычки если их вввел пользователь
        path = path.strip('"\'')
        
        folder = Path(path)
        
        if not folder.exists():
            print(f"❌ Папка не существует: {path}")
            continue
        
        if not folder.is_dir():
            print(f"❌ Это не папка: {path}")
            continue
        
        return str(folder.absolute())


def get_multiple_folders():
    """Получить несколько папок для сканирования"""
    folders = []
    print("\n📁 Укажите папки для сканирования (введите пусто для завершения):")
    
    while True:
        path = input(f"\nПапка #{len(folders) + 1}: ").strip()
        
        if not path:
            if folders:
                break
            else:
                print("❌ Укажите хотя бы одну папку")
                continue
        
        # Убери кавычки
        path = path.strip('"\'')
        folder = Path(path)
        
        if not folder.exists():
            print(f"❌ Папка не существует: {path}")
            continue
        
        if not folder.is_dir():
            print(f"❌ Это не папка: {path}")
            continue
        
        folders.append(str(folder.absolute()))
        print(f"✅ Добавлена: {folder.name}")
    
    return folders


def get_output_names():
    """Получить имена для выходных файлов"""
    json_output = input("\n💾 Имя JSON отчёта (по умолчанию: report.json): ").strip()
    if not json_output:
        json_output = "report.json"
    
    html_output = input("💾 Имя HTML отчёта (по умолчанию: report.html): ").strip()
    if not html_output:
        html_output = "report.html"
    
    return json_output, html_output


def scan_file(file_path, tree, report_gen):
    """Сканировать один файл"""
    print(f"\n🔍 Анализ файла: {file_path}")
    
    scanner = FileScanner(tree)
    file_info = scanner.scan_file(file_path)
    
    if file_info:
        report_gen.add_findings([file_info])
        
        print(f"✅ Анализ завершён")
        print(f"   📦 Определённое ПО: {file_info.software_name or 'Не определено'}")
        print(f"   📌 Версия: {file_info.software_version or 'Неизвестно'}")
        
        if file_info.has_vulnerabilities():
            findings = file_info.vulnerabilities
            print(f"   ⚠️  Найдено уязвимостей: {len(findings)}")
            
            critical = [v for v in findings if hasattr(v, 'severity') and v.severity.value == 'critical']
            high = [v for v in findings if hasattr(v, 'severity') and v.severity.value == 'high']
            medium = [v for v in findings if hasattr(v, 'severity') and v.severity.value == 'medium']
            low = [v for v in findings if hasattr(v, 'severity') and v.severity.value == 'low']
            
            if critical:
                print(f"      🔴 Критических: {len(critical)}")
            if high:
                print(f"      🟠 Высоких: {len(high)}")
            if medium:
                print(f"      🟡 Средних: {len(medium)}")
            if low:
                print(f"      🟢 Низких: {len(low)}")
        else:
            print(f"   ✅ Уязвимостей не найдено")
        
        return [file_info]
    else:
        print(f"✅ Анализ завершён")
        print(f"   ℹ️  Файл: не является исполняемым или доступ запрещен")
        return []


def scan_folder(folder_path, tree, report_gen, all_scanned_files):
    """Сканировать папку"""
    print(f"\n🔍 Сканирование: {folder_path}")
    
    scanner = FolderScanner(tree, max_workers=4)
    
    start_time = time.time()
    findings = scanner.scan_folder(
        folder_path,
        progress_callback=progress_bar,
        parallel=True
    )
    scan_time = time.time() - start_time
    
    scanned_files = scanner.get_files_recursive(folder_path)
    all_scanned_files.extend(scanned_files)
    
    # Добавь ВСЕ файлы в all_analyzed_items (для показа в отчёте)
    report_gen.add_all_analyzed_items(findings)
    
    # Добавь только уязвимые в findings (для детальной информации)
    vulnerable_findings = [f for f in findings if f.has_vulnerabilities()]
    report_gen.add_findings(vulnerable_findings)
    
    print(f"\n✅ Сканирование завершено за {scan_time:.2f} сек")
    print(f"   • Файлов просканировано: {len(findings)}")
    print(f"   • Файлов с уязвимостями: {len(vulnerable_findings)}")
    
    return findings


def scan_system(tree, report_gen):
    """Сканировать все стандартные системные папки (только .exe файлы для Windows) + реестр"""
    print("\n🔍 Полное системное сканирование...")
    print("⏳ Это может занять длительное время...")
    
    all_findings = []
    registry_to_exe_map = {}
    
    # ========================================================================
    # ЭТАП 1: СКАНИРОВАНИЕ РЕЕСТРА (только для Windows)
    # ========================================================================
    if sys.platform == 'win32':
        print("\n📋 ЭТАП 1: СКАНИРОВАНИЕ РЕЕСТРА...")
        registry_scanner = RegistryScanner(tree)
        installed = registry_scanner.get_installed_software()
        print(f"✅ Найдено установленного ПО: {len(installed)}")
        
        # Сканируй реестр для получения уязвимостей
        registry_results = registry_scanner.scan_registry(progress_callback=progress_bar)
        
        class RegistryFinding:
            def __init__(self, data):
                self.file_path = data['install_path']
                self.software_name = data['software_name']
                self.software_version = data['software_version']
                self.vulnerabilities = data['vulnerabilities']
            
            def has_vulnerabilities(self):
                return len(self.vulnerabilities) > 0
            
            def to_dict(self):
                return {
                    'file_path': self.file_path,
                    'software_name': self.software_name,
                    'software_version': self.software_version,
                    'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
                }
        
        for result in registry_results:
            finding = RegistryFinding(result)
            all_findings.append(finding)
            # Инициализируй запись для отслеживания
            registry_to_exe_map[result['software_name']] = []
        
        registry_with_vulns = len([r for r in registry_results if r['has_vulnerabilities']])
        print(f"   📊 Из реестра: {len(registry_results)} программ ({registry_with_vulns} с уязвимостями)")
        
        # Создай словарь для сопоставления путей -> программы
        install_paths_map = {}
        software_by_name = {}
        for soft in installed:
            path = soft.install_path
            if path and path != 'unknown':
                path_normalized = str(Path(path).resolve()).lower()
                install_paths_map[path_normalized] = {
                    'name': soft.name,
                    'version': soft.version,
                    'original_path': path
                }
            software_by_name[soft.name.lower()] = soft
    
    # ========================================================================
    # ЭТАП 2: СКАНИРОВАНИЕ ФАЙЛОВОЙ СИСТЕМЫ
    # ========================================================================
    print("\n📂 ЭТАП 2: СКАНИРОВАНИЕ СИСТЕМНЫХ ПАПОК...")
    
    # Определи папки в зависимости от ОС
    if sys.platform == 'win32':
        folders_to_scan = [
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ]
        print("📌 Будут сканироваться только .exe файлы")
    else:
        # Linux/macOS
        folders_to_scan = [
            "/usr/bin",
            "/usr/local/bin",
            "/opt",
        ]
    
    print(f"\n📁 Папки для сканирования: {', '.join(folders_to_scan)}")
    
    total_findings = []
    file_scanner = FileScanner(tree)
    
    for folder in folders_to_scan:
        folder_path = Path(folder)
        if not folder_path.exists():
            print(f"⚠️  Папка не найдена: {folder}")
            continue
        
        print(f"\n📂 Сканирование: {folder}")
        try:
            # Для Windows - только .exe файлы
            if sys.platform == 'win32':
                exe_files = list(folder_path.rglob('*.exe'))
                print(f"   Найдено .exe файлов: {len(exe_files)}")
                
                findings = []
                for i, exe_file in enumerate(exe_files):
                    try:
                        finding = file_scanner.scan_file(str(exe_file))
                        if finding:
                            # Попробуй сопоставить с реестром
                            exe_path = str(exe_file.resolve())
                            matched_program = None
                            
                            # Ищи по пути
                            for install_path, prog_info in install_paths_map.items():
                                if exe_path.lower().startswith(install_path):
                                    matched_program = prog_info
                                    break
                            
                            # Если нашли соответствие с реестром
                            if matched_program:
                                finding.software_name = matched_program['name']
                                finding.software_version = matched_program['version']
                                
                                # Перепроверь уязвимости
                                vulnerabilities = tree.find_vulnerabilities(
                                    matched_program['name'],
                                    matched_program['version']
                                )
                                finding.vulnerabilities = vulnerabilities
                                
                                # Запомни соответствие
                                registry_to_exe_map[matched_program['name']].append(exe_path)
                            
                            findings.append(finding)
                        
                        # Показать прогресс
                        if (i + 1) % 100 == 0:
                            progress_bar(i + 1, len(exe_files))
                    except Exception:
                        continue
                
                progress_bar(len(exe_files), len(exe_files))
            else:
                # Для Linux/macOS - использовать FolderScanner
                scanner = FolderScanner(tree, max_workers=4)
                findings = scanner.scan_folder(
                    folder,
                    progress_callback=progress_bar,
                    parallel=True
                )
            total_findings.extend(findings)
            
            vulnerable = len([f for f in findings if f.has_vulnerabilities()])
            print(f"\n   ✅ Файлов: {len(findings)}, уязвимых: {vulnerable}")
        except Exception as e:
            print(f"   ❌ Ошибка: {e}")
    
    # Объедини все результаты
    all_findings.extend(total_findings)
    
    # ========================================================================
    # ПОКАЗАТЬ СООТВЕТСТВИЕ: РЕЕСТР -> .EXE (только для Windows)
    # ========================================================================
    if sys.platform == 'win32' and registry_to_exe_map:
        print("\n" + "="*70)
        print("📋 СООТВЕТСТВИЕ: ПРОГРАММЫ ИЗ РЕЕСТРА → НАЙДЕННЫЕ .EXE ФАЙЛЫ")
        print("="*70)
        
        matched_programs = 0
        for prog_name, exe_list in sorted(registry_to_exe_map.items()):
            if exe_list:
                matched_programs += 1
                print(f"\n✅ {prog_name}")
                for exe_path in exe_list[:3]:  # Показать первые 3 .exe
                    print(f"   → {exe_path}")
                if len(exe_list) > 3:
                    print(f"   ... и ещё {len(exe_list) - 3} файлов")
        
        # Программы из реестра без найденных .exe
        unmatched_programs = len(registry_results) - matched_programs
        if unmatched_programs > 0:
            print(f"\n⚠️  Программ из реестра без найденных .exe: {unmatched_programs}")
        
        print(f"\n📊 ИТОГОВАЯ СТАТИСТИКА СООТВЕТСТВИЯ:")
        print(f"   • Программ из реестра: {len(registry_results)}")
        print(f"   • Нашли .exe для программ: {matched_programs}")
        print(f"   • Процент соответствия: {(matched_programs / len(registry_results) * 100):.1f}%")
    
    # ========================================================================
    # ОТЧЁТ
    # ========================================================================
    if all_findings:
        report_gen.add_all_analyzed_items(all_findings)
        vulnerable_findings = [f for f in all_findings if f.has_vulnerabilities()]
        report_gen.add_findings(vulnerable_findings)
        
        print(f"\n✅ ИТОГО СИСТЕМНОГО СКАНИРОВАНИЯ:")
        if sys.platform == 'win32':
            print(f"   • Программ из реестра: {len(registry_results)}")
        print(f"   • Всего файлов проверено: {len(all_findings)}")
        print(f"   • Файлов с уязвимостями: {len(vulnerable_findings)}")
        
        if vulnerable_findings:
            total_vulns = sum(len(f.vulnerabilities) for f in vulnerable_findings)
            print(f"   • Всего уязвимостей: {total_vulns}")
            return total_vulns
    else:
        print("\n❌ Не удалось отсканировать системные папки")
    
    return 0


def scan_registry(tree, report_gen):
    """Сканировать установленные программы из реестра Windows"""
    if sys.platform != 'win32':
        print("❌ Сканирование по реестру доступно только на Windows")
        return []
    
    print("\n🔍 Сканирование установленных программ из реестра Windows...")
    print("⏳ Получение данных из реестра...")
    
    registry_scanner = RegistryScanner(tree)
    
    # Получи список установленного ПО
    installed = registry_scanner.get_installed_software()
    print(f"✅ Найдено установленного ПО: {len(installed)}")
    
    if not installed:
        print("❌ Не удалось получить список программ из реестра")
        return []
    
    # Сканируй каждую программу
    print("\n🔎 Проверка программ в БДУ ФСТЕК...")
    start_time = time.time()
    
    scan_results = registry_scanner.scan_registry(progress_callback=progress_bar)
    scan_time = time.time() - start_time
    
    print(f"\n✅ Сканирование завершено за {scan_time:.2f} сек")
    
    # Статистика
    stats = registry_scanner.get_statistics(scan_results)
    
    print(f"\n📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ:")
    print(f"   • Всего программ проверено: {stats['total_software']}")
    print(f"   • Программ с уязвимостями: {stats['software_with_vulnerabilities']}")
    print(f"   • Всего найдено уязвимостей: {stats['total_vulnerabilities']}")
    
    if stats['total_vulnerabilities'] > 0:
        print(f"      🔴 Критических: {stats['critical_vulnerabilities']}")
        print(f"      🟠 Высоких: {stats['high_vulnerabilities']}")
        print(f"      🟡 Средних: {stats['medium_vulnerabilities']}")
        print(f"      🟢 Низких: {stats['low_vulnerabilities']}")
    
    # Покажи топ уязвимых программ
    vulnerable_software = [r for r in scan_results if r['has_vulnerabilities']]
    if vulnerable_software:
        vulnerable_software.sort(key=lambda x: x['vulnerability_count'], reverse=True)
        
        print(f"\n🔴 ТОП ПРОГРАММ С УЯЗВИМОСТЯМИ:")
        for i, result in enumerate(vulnerable_software[:10], 1):
            print(f"   {i}. {result['software_name']} {result['software_version']}")
            print(f"      Уязвимостей: {result['vulnerability_count']}")
    
    # Добавь все результаты сканирования в отчёт (и с уязвимостями, и без)
    all_findings = []
    
    for result in scan_results:
        # Создай MockFinding для каждого результата (уязвимый или безопасный)
        class MockFinding:
            def __init__(self, data):
                self.file_path = data['install_path']
                self.software_name = data['software_name']
                self.software_version = data['software_version']
                self.vulnerabilities = data['vulnerabilities']
            
            def has_vulnerabilities(self):
                return len(self.vulnerabilities) > 0
            
            def to_dict(self):
                return {
                    'file_path': self.file_path,
                    'software_name': self.software_name,
                    'software_version': self.software_version,
                    'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
                }
        
        finding = MockFinding(result)
        all_findings.append(finding)
    
    # Добавь ВСЕ программы (для отображения в отчёте)
    report_gen.add_all_analyzed_items(all_findings)
    
    # Добавь только уязвимые в findings (для детальной информации)
    vulnerable_findings = [f for f in all_findings if f.has_vulnerabilities()]
    report_gen.add_findings(vulnerable_findings)
    
    return scan_results


def scan_all_drives_combined(tree, report_gen):
    """
    Комбинированное сканирование: реестр + все .exe файлы из установленных программ
    Показывает все .exe файлы с данными (версия и т.д.), но только те которые есть в реестре
    """
    if sys.platform != 'win32':
        print("❌ Доступно только на Windows")
        return
    
    print("\n" + "="*70)
    print("💾 КОМБИНИРОВАННОЕ СКАНИРОВАНИЕ: РЕЕСТР + ВСЕ .EXE УСТАНОВЛЕННЫХ ПРОГРАММ")
    print("="*70)
    
    all_findings = []
    
    # ========================================================================
    # 1. РЕЕСТР (получи список установленных программ и их пути)
    # ========================================================================
    print("\n📋 ЭТАП 1: ПОЛУЧЕНИЕ СПИСКА УСТАНОВЛЕННЫХ ПРОГРАММ ИЗ РЕЕСТРА...")
    registry_scanner = RegistryScanner(tree)
    installed = registry_scanner.get_installed_software()
    print(f"✅ Найдено установленного ПО: {len(installed)}")
    
    # Создай словарь для быстрого поиска: путь -> информация о программе
    install_paths_map = {}
    for soft in installed:
        path = soft.install_path
        if path and path != 'unknown':
            path_normalized = str(Path(path).resolve())
            install_paths_map[path_normalized.lower()] = {
                'name': soft.name,
                'version': soft.version,
                'original_path': path
            }
    
    # Также создай словарь по названию программы для сопоставления
    software_by_name = {soft.name.lower(): soft for soft in installed}
    
    # Сканируй реестр для получения уязвимостей
    registry_results = registry_scanner.scan_registry(progress_callback=progress_bar)
    
    class RegistryFinding:
        def __init__(self, data):
            self.file_path = data['install_path']
            self.software_name = data['software_name']
            self.software_version = data['software_version']
            self.vulnerabilities = data['vulnerabilities']
        
        def has_vulnerabilities(self):
            return len(self.vulnerabilities) > 0
        
        def to_dict(self):
            return {
                'file_path': self.file_path,
                'software_name': self.software_name,
                'software_version': self.software_version,
                'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            }
    
    for result in registry_results:
        finding = RegistryFinding(result)
        all_findings.append(finding)
    
    registry_with_vulns = len([r for r in registry_results if r['has_vulnerabilities']])
    print(f"   📊 Из реестра: {len(registry_results)} программ ({registry_with_vulns} с уязвимостями)")
    
    # ========================================================================
    # 2. СКАНИРОВАНИЕ ВСЕХ .EXE ФАЙЛОВ В ПАПКАХ УСТАНОВКИ (ВСЕ ДИСКИ)
    # ========================================================================
    print("\n💾 ЭТАП 2: СКАНИРОВАНИЕ ВСЕХ .EXE ФАЙЛОВ В ПАПКАХ УСТАНОВКИ НА ВСЕХ ДИСКАХ...")
    
    # Получи все уникальные пути установки со всех дисков
    all_install_paths = set()
    paths_by_drive = {}  # Для статистики по дискам
    
    for soft in installed:
        path = soft.install_path
        if path and path != 'unknown':
            try:
                path_obj = Path(path)
                if path_obj.exists() and path_obj.is_dir():
                    resolved_path = str(path_obj.resolve())
                    all_install_paths.add(resolved_path)
                    
                    # Собери статистику по дискам
                    drive = path_obj.drive if path_obj.drive else 'Unknown'
                    if drive not in paths_by_drive:
                        paths_by_drive[drive] = []
                    paths_by_drive[drive].append(resolved_path)
            except (OSError, ValueError):
                # Пропусти недоступные пути
                continue
    
    print(f"Найдено папок установки: {len(all_install_paths)}")
    print("\n📊 Распределение по дискам:")
    for drive, paths in sorted(paths_by_drive.items()):
        print(f"   {drive}: {len(paths)} папок")
    
    file_scanner = FileScanner(tree)
    exe_findings = []
    total_exe_found = 0
    total_exe_scanned = 0
    
    # Словарь для отслеживания: программа из реестра -> найденные .exe
    registry_to_exe_map = {}
    
    print(f"\n🔍 Поиск и анализ .exe файлов...")
    
    for install_path in sorted(all_install_paths):
        try:
            path_obj = Path(install_path)
            if not path_obj.exists() or not path_obj.is_dir():
                continue
            
            # Найди все .exe файлы в папке и подпапках (рекурсивно)
            exe_files = list(path_obj.rglob('*.exe'))
            total_exe_found += len(exe_files)
            
            if exe_files:
                # Определи программу для этой папки
                path_normalized = str(path_obj.resolve()).lower()
                program_info = None
                for key, info in install_paths_map.items():
                    if path_normalized.startswith(key) or key in path_normalized:
                        program_info = info
                        break
                
                # Если не нашли по пути, попробуй найти по родительской папке
                if not program_info:
                    parent_path = str(path_obj.parent.resolve()).lower()
                    for key, info in install_paths_map.items():
                        if parent_path.startswith(key) or key in parent_path:
                            program_info = info
                            break
                
                # Если нашли программу из реестра, запомни
                if program_info:
                    prog_name = program_info['name']
                    if prog_name not in registry_to_exe_map:
                        registry_to_exe_map[prog_name] = []
                
                # Сканируй каждый .exe файл
                for exe_file in exe_files:
                    try:
                        # Проанализируй PE файл для получения информации
                        finding = file_scanner.scan_file(str(exe_file))
                        
                        if finding:
                            # Если нашли информацию о программе из реестра, используй её
                            if program_info:
                                # Используй данные из реестра как приоритетные
                                finding.software_name = program_info['name']
                                finding.software_version = program_info['version']
                                
                                # Перепроверь уязвимости с правильным названием и версией
                                vulnerabilities = tree.find_vulnerabilities(
                                    program_info['name'],
                                    program_info['version']
                                )
                                finding.vulnerabilities = vulnerabilities
                                
                                # Запомни что нашли .exe для этой программы из реестра
                                prog_name = program_info['name']
                                registry_to_exe_map[prog_name].append(str(exe_file))
                            
                            # Если не определили ПО из PE, но есть в реестре
                            elif not finding.software_name or finding.software_name == 'unknown':
                                # Попробуй определить по имени файла или пути
                                exe_name_lower = exe_file.name.lower()
                                
                                # Ищи совпадение по имени файла в реестре
                                for soft_name, soft_info in software_by_name.items():
                                    if exe_name_lower.startswith(soft_name.lower().replace(' ', '')) or \
                                       soft_name.lower() in exe_name_lower:
                                        finding.software_name = soft_info.name
                                        finding.software_version = soft_info.version
                                        
                                        # Перепроверь уязвимости
                                        vulnerabilities = tree.find_vulnerabilities(
                                            soft_info.name,
                                            soft_info.version
                                        )
                                        finding.vulnerabilities = vulnerabilities
                                        break
                            
                            exe_findings.append(finding)
                            total_exe_scanned += 1
                            
                    except Exception as e:
                        # Пропусти файл при ошибке
                        continue
        
        except Exception as e:
            print(f"   ⚠️  Ошибка при сканировании {install_path}: {e}")
            continue
    
    all_findings.extend(exe_findings)
    print(f"\n   📊 Найдено .exe файлов: {total_exe_found}")
    print(f"   📊 Проанализировано .exe файлов: {total_exe_scanned}")
    print(f"   📊 Файлов связанных с реестром: {len(exe_findings)}")
    
    # ========================================================================
    # ПОКАЗАТЬ СООТВЕТСТВИЕ: РЕЕСТР -> .EXE
    # ========================================================================
    print("\n" + "="*70)
    print("📋 СООТВЕТСТВИЕ: ПРОГРАММЫ ИЗ РЕЕСТРА → НАЙДЕННЫЕ .EXE ФАЙЛЫ")
    print("="*70)
    
    matched_programs = 0
    for prog_name, exe_list in sorted(registry_to_exe_map.items()):
        if exe_list:
            matched_programs += 1
            print(f"\n✅ {prog_name}")
            for exe_path in exe_list[:3]:  # Показать первые 3 .exe
                print(f"   → {exe_path}")
            if len(exe_list) > 3:
                print(f"   ... и ещё {len(exe_list) - 3} файлов")
    
    # Программы из реестра без найденных .exe
    unmatched_programs = len(registry_results) - matched_programs
    if unmatched_programs > 0:
        print(f"\n⚠️  Программ из реестра без найденных .exe: {unmatched_programs}")
    
    print(f"\n📊 ИТОГОВАЯ СТАТИСТИКА СООТВЕТСТВИЯ:")
    print(f"   • Программ из реестра: {len(registry_results)}")
    print(f"   • Нашли .exe для программ: {matched_programs}")
    print(f"   • Процент соответствия: {(matched_programs / len(registry_results) * 100):.1f}%")
    
    # ========================================================================
    # 3. ОТЧЁТ
    # ========================================================================
    print("\n📄 Генерирование отчёта...")
    report_gen.add_all_analyzed_items(all_findings)
    vulnerable_findings = [f for f in all_findings if f.has_vulnerabilities()]
    report_gen.add_findings(vulnerable_findings)
    
    print(f"\n✅ ИТОГО:")
    print(f"   • Всего программ из реестра: {len(registry_results)}")
    print(f"   • Всего .exe файлов проанализировано: {total_exe_scanned}")
    print(f"   • Всего предметов в отчёте: {len(all_findings)}")
    print(f"   • С уязвимостями: {len(vulnerable_findings)}")
    
    if vulnerable_findings:
        total_vulns = sum(len(f.vulnerabilities) for f in vulnerable_findings)
        print(f"   • Всего уязвимостей: {total_vulns}")


def main():
    """Главная функция"""
    print_banner()
    
    # Загрузи БДУ
    print("\n⏳ Загрузка базы данных БДУ ФСТЕК...")
    print("   📂 Источник: data/full_data.xlsx")
    
    try:
        # Получи информацию о файле
        bdu_file = Path('data/full_data.xlsx')
        if bdu_file.exists():
            file_size_mb = bdu_file.stat().st_size / (1024 * 1024)
            print(f"   📊 Размер файла: {file_size_mb:.2f} МБ")
        
        loader = DataLoader(cache_dir='cache')
        start_time = time.time()
        tree = loader.load_bdu('data/full_data.xlsx', use_cache=True)
        load_time = time.time() - start_time
        
        print("✅ База данных загружена успешно!")
        print(f"   ⏱️  Время загрузки: {load_time:.2f} сек")
        
        stats = tree.get_statistics()
        print("\n📊 СТАТИСТИКА БДУ:")
        print(f"   • ПО в базе: {stats['total_software']:,}")
        print(f"   • Версий: {stats['total_versions']:,}")
        print(f"   • Всего уязвимостей: {stats['total_vulnerabilities']:,}")
        print(f"   • Критических уязвимостей: {stats['critical_vulnerabilities']:,}")
        print(f"   • Высоких: {stats.get('high_vulnerabilities', 0):,}")
        print(f"   • Средних: {stats.get('medium_vulnerabilities', 0):,}")
        
    except Exception as e:
        print(f"❌ Ошибка при загрузке БДУ: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Показать меню
    while True:
        show_menu()
        choice = get_choice()
        
        # Инициализируй отчёт
        report_gen = ReportGenerator()
        all_scanned_files = []
        scan_results = []
        
        try:
            if choice == '1':
                # Сканировать конкретный файл
                file_path = get_file_path()
                scan_file(file_path, tree, report_gen)
            
            elif choice == '2':
                # Сканировать конкретную папку
                folder_path = get_folder_path()
                scan_folder(folder_path, tree, report_gen, all_scanned_files)
            
            elif choice == '3':
                # Сканировать несколько папок
                folders = get_multiple_folders()
                for folder_path in folders:
                    scan_folder(folder_path, tree, report_gen, all_scanned_files)
            
            elif choice == '4':
                # Сканировать Program Files (Windows)
                if sys.platform == 'win32':
                    folder_path = r"C:\Program Files"
                    scan_folder(folder_path, tree, report_gen, all_scanned_files)
                else:
                    print("❌ Program Files доступен только на Windows")
                    continue
            
            elif choice == '5':
                # Сканировать Program Files (x86) (Windows)
                if sys.platform == 'win32':
                    folder_path = r"C:\Program Files (x86)"
                    if Path(folder_path).exists():
                        scan_folder(folder_path, tree, report_gen, all_scanned_files)
                    else:
                        print("❌ Папка Program Files (x86) не найдена")
                        continue
                else:
                    print("❌ Program Files доступен только на Windows")
                    continue
            
            elif choice == '6':
                # Сканировать /usr/bin (Linux)
                if sys.platform != 'win32':
                    folder_path = "/usr/bin"
                    scan_folder(folder_path, tree, report_gen, all_scanned_files)
                else:
                    print("❌ /usr/bin доступен только на Linux/macOS")
                    continue
            
            elif choice == '7':
                # Сканировать /opt (Linux)
                if sys.platform != 'win32':
                    folder_path = "/opt"
                    if Path(folder_path).exists():
                        scan_folder(folder_path, tree, report_gen, all_scanned_files)
                    else:
                        print("❌ Папка /opt не найдена")
                        continue
                else:
                    print("❌ /opt доступен только на Linux/macOS")
                    continue
            
            elif choice == '8':
                # Полное системное сканирование
                print("\n⚠️  Это может занять длительное время...")
                confirm = input("Вы уверены? (y/n): ").strip().lower()
                if confirm == 'y':
                    scan_system(tree, report_gen)
                else:
                    continue
            
            elif choice == '9':
                # Сканирование по реестру Windows
                if sys.platform == 'win32':
                    scan_registry(tree, report_gen)
                else:
                    print("❌ Сканирование по реестру доступно только на Windows")
                    continue
            
            elif choice == '10':
                # Комбинированное сканирование: реестр + все диски
                if sys.platform == 'win32':
                    scan_all_drives_combined(tree, report_gen)
                else:
                    print("❌ Сканирование всех дисков доступно только на Windows")
                    continue
            
            elif choice == '0':
                print("\n👋 До встречи!")
                return 0
            
            # Добавь список файлов
            if all_scanned_files:
                report_gen.add_scanned_files(all_scanned_files, len(all_scanned_files))
            
            # Получи имена файлов
            json_output, html_output = get_output_names()
            
            # Генерируй отчёты
            print(f"\n📄 Генерирование отчётов...")
            report_gen.generate_json(json_output)
            report_gen.generate_html(html_output)
            
            print(f"\n✅ СКАНИРОВАНИЕ ЗАВЕРШЕНО:")
            print(f"   📊 Всего файлов сканировано: {len(all_scanned_files)}")
            print(f"   🔴 Файлов с уязвимостями: {len(report_gen.findings)}")
            
            # Статистика уязвимостей
            if report_gen.findings:
                critical = len([v for v in report_gen.findings if hasattr(v, 'severity') and v.severity == 'CRITICAL'])
                high = len([v for v in report_gen.findings if hasattr(v, 'severity') and v.severity == 'HIGH'])
                medium = len([v for v in report_gen.findings if hasattr(v, 'severity') and v.severity == 'MEDIUM'])
                low = len([v for v in report_gen.findings if hasattr(v, 'severity') and v.severity == 'LOW'])
                
                print(f"   🔴 Критических: {critical}")
                print(f"   🟠 Высоких: {high}")
                print(f"   🟡 Средних: {medium}")
                print(f"   🟢 Низких: {low}")
            
            print(f"\n📄 Отчёты сохранены:")
            print(f"   📊 JSON: {json_output}")
            print(f"   🌐 HTML: {html_output}")
            
            # Спроси, продолжить ли
            another = input("\n❓ Хотите выполнить ещё одно сканирование? (y/n): ").strip().lower()
            if another != 'y':
                print("\n👋 Спасибо за использование Bochka!")
                return 0
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Сканирование прервано пользователем")
            return 1
        except Exception as e:
            print(f"\n❌ Ошибка: {e}")
            import traceback
            traceback.print_exc()
            return 1


if __name__ == '__main__':
    sys.exit(main())
