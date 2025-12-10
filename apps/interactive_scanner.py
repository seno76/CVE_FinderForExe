
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
    ├─ 8. Полное системное сканирование (все стандартные папки)
    🧩 Сканирование установленных пакетов:
    ├─ 9. Проверить установленные программы (dpkg/rpm)""")
    
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
    """Сканировать все стандартные системные папки"""
    print("\n🔍 Полное системное сканирование...")
    print("⏳ Это может занять длительное время...")
    
    # Определи папки в зависимости от ОС
    if sys.platform == 'win32':
        folders_to_scan = [
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ]
    else:
        # Linux/macOS
        folders_to_scan = [
            "/usr/bin",
            "/usr/local/bin",
            "/opt",
        ]
    
    print(f"\n📁 Папки для сканирования: {', '.join(folders_to_scan)}")
    
    all_scanned_files = []
    total_findings = []
    
    for folder in folders_to_scan:
        folder_path = Path(folder)
        if not folder_path.exists():
            print(f"⚠️  Папка не найдена: {folder}")
            continue
        
        print(f"\n📂 Сканирование: {folder}")
        try:
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
    
    # Добавь все результаты в отчёт
    if total_findings:
        report_gen.add_all_analyzed_items(total_findings)
        vulnerable_findings = [f for f in total_findings if f.has_vulnerabilities()]
        report_gen.add_findings(vulnerable_findings)
        
        print(f"\n✅ ИТОГО СИСТЕМНОГО СКАНИРОВАНИЯ:")
        print(f"   • Всего файлов проверено: {len(total_findings)}")
        print(f"   • Файлов с уязвимостями: {len(vulnerable_findings)}")
        
        if vulnerable_findings:
            total_vulns = sum(len(f.vulnerabilities) for f in vulnerable_findings)
            print(f"   • Всего уязвимостей: {total_vulns}")
    else:
        print("\n❌ Не удалось отсканировать системные папки")
    
    return total_vulns


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


def scan_installed_linux_packages(tree, report_gen, all_scanned_files):
    """Сканировать только установленные пакеты Linux через dpkg/rpm"""
    if sys.platform == 'win32':
        print("❌ Доступно только на Linux/macOS")
        return []
    
    scanner = SystemScanner()
    program_paths = scanner.scan_system()
    
    if not program_paths:
        print("❌ Не удалось получить список установленных программ")
        return []
    
    print(f"\n🔍 Проверка установленных программ: {len(program_paths)}")
    file_scanner = FileScanner(tree)
    findings = []
    
    total = len(program_paths)
    for idx, program in enumerate(program_paths, 1):
        progress_bar(idx, total)
        finding = file_scanner.scan_file(program)
        if finding:
            findings.append(finding)
    
    # Добавь в список просканированных файлов (для отчёта)
    all_scanned_files.extend(program_paths)
    
    print("\n✅ Проверка завершена")
    if findings:
        report_gen.add_all_analyzed_items(findings)
        vulnerable = [f for f in findings if f.has_vulnerabilities()]
        report_gen.add_findings(vulnerable)
        print(f"   • Всего проверено: {len(findings)}")
        print(f"   • С уязвимостями: {len(vulnerable)}")
    else:
        print("   • Не удалось определить ПО по найденным файлам")
    
    return findings


def scan_linux_packages(tree, report_gen):
    """
    Сканировать установленные пакеты Linux через dpkg/rpm/pacman
    Аналог scan_registry() для Windows - получает список ПО с версиями
    """
    if sys.platform == 'win32':
        print("❌ Сканирование пакетов доступно только на Linux/macOS")
        return []
    
    print("\n🔍 Сканирование установленных пакетов Linux...")
    print("⏳ Получение списка пакетов из пакетного менеджера...")
    
    scanner = SystemScanner()
    
    # Получи список пакетов с версиями
    packages = scanner.get_installed_packages_linux()
    print(f"✅ Найдено установленных пакетов: {len(packages)}")
    
    if not packages:
        print("❌ Не удалось получить список пакетов")
        return []
    
    # Сканируй каждый пакет в БДУ ФСТЕК
    print("\n🔎 Проверка пакетов в БДУ ФСТЕК...")
    start_time = time.time()
    
    scan_results = []
    total = len(packages)
    
    for idx, pkg in enumerate(packages, 1):
        progress_bar(idx, total)
        
        pkg_name = pkg['name']
        pkg_version = pkg['version']
        install_path = pkg.get('install_path', f'/usr/bin/{pkg_name}')
        
        # Поиск уязвимостей в дереве БДУ
        vulnerabilities = tree.search(pkg_name, pkg_version)
        
        scan_results.append({
            'software_name': pkg_name,
            'software_version': pkg_version,
            'install_path': install_path,
            'vulnerabilities': vulnerabilities,
            'has_vulnerabilities': len(vulnerabilities) > 0,
            'vulnerability_count': len(vulnerabilities)
        })
    
    scan_time = time.time() - start_time
    print(f"\n✅ Сканирование завершено за {scan_time:.2f} сек")
    
    # Статистика
    total_software = len(scan_results)
    software_with_vulns = len([r for r in scan_results if r['has_vulnerabilities']])
    total_vulns = sum(r['vulnerability_count'] for r in scan_results)
    
    # Подсчёт по уровням
    critical_vulns = 0
    high_vulns = 0
    medium_vulns = 0
    low_vulns = 0
    
    for result in scan_results:
        for v in result['vulnerabilities']:
            if hasattr(v, 'severity'):
                sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
                sev_lower = sev.lower()
                if sev_lower == 'critical':
                    critical_vulns += 1
                elif sev_lower == 'high':
                    high_vulns += 1
                elif sev_lower == 'medium':
                    medium_vulns += 1
                elif sev_lower == 'low':
                    low_vulns += 1
    
    print(f"\n📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ:")
    print(f"   • Всего пакетов проверено: {total_software}")
    print(f"   • Пакетов с уязвимостями: {software_with_vulns}")
    print(f"   • Всего найдено уязвимостей: {total_vulns}")
    
    if total_vulns > 0:
        print(f"      🔴 Критических: {critical_vulns}")
        print(f"      🟠 Высоких: {high_vulns}")
        print(f"      🟡 Средних: {medium_vulns}")
        print(f"      🟢 Низких: {low_vulns}")
    
    # Покажи топ уязвимых пакетов
    vulnerable_software = [r for r in scan_results if r['has_vulnerabilities']]
    if vulnerable_software:
        vulnerable_software.sort(key=lambda x: x['vulnerability_count'], reverse=True)
        
        print(f"\n🔴 ТОП ПАКЕТОВ С УЯЗВИМОСТЯМИ:")
        for i, result in enumerate(vulnerable_software[:10], 1):
            print(f"   {i}. {result['software_name']} {result['software_version']}")
            print(f"      Уязвимостей: {result['vulnerability_count']}")
    
    # Создай findings для отчёта
    all_findings = []
    
    for result in scan_results:
        class LinuxPackageFinding:
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
        
        finding = LinuxPackageFinding(result)
        all_findings.append(finding)
    
    # Добавь ВСЕ пакеты (для отображения в отчёте)
    report_gen.add_all_analyzed_items(all_findings)
    
    # Добавь только уязвимые в findings (для детальной информации)
    vulnerable_findings = [f for f in all_findings if f.has_vulnerabilities()]
    report_gen.add_findings(vulnerable_findings)
    
    return scan_results


def scan_all_drives_combined(tree, report_gen):
    """Комбинированное сканирование: реестр + только установленные .exe на всех дисках"""
    import string
    
    if sys.platform != 'win32':
        print("❌ Доступно только на Windows")
        return
    
    print("\n" + "="*70)
    print("💾 КОМБИНИРОВАННОЕ СКАНИРОВАНИЕ: РЕЕСТР + .EXE УСТАНОВЛЕННЫХ ПРОГРАММ")
    print("="*70)
    
    all_findings = []
    
    # ========================================================================
    # 1. РЕЕСТР (получи пути установки)
    # ========================================================================
    print("\n📋 ЭТАП 1: СКАНИРОВАНИЕ РЕЕСТРА...")
    registry_scanner = RegistryScanner(tree)
    installed = registry_scanner.get_installed_software()
    print(f"✅ Найдено установленного ПО: {len(installed)}")
    
    # Сканируй реестр
    registry_results = registry_scanner.scan_registry(progress_callback=progress_bar)
    
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
    
    for result in registry_results:
        finding = MockFinding(result)
        all_findings.append(finding)
    
    registry_with_vulns = len([r for r in registry_results if r['has_vulnerabilities']])
    print(f"   📊 Из реестра: {len(registry_results)} программ ({registry_with_vulns} с уязвимостями)")
    
    # ========================================================================
    # 2. СКАНИРОВАНИЕ ПАПОК УСТАНОВКИ НА ДРУГИХ ДИСКАХ
    # ========================================================================
    print("\n💾 ЭТАП 2: СКАНИРОВАНИЕ ПАПОК УСТАНОВКИ НА ВСЕХ ДИСКАХ...")
    
    # Получи уникальные пути установки со всех дисков
    install_paths = set()
    for soft in installed:
        path = soft.install_path
        if path and path != 'unknown' and Path(path).exists():
            install_paths.add(path)
    
    # Фильтруй только пути на других дисках (не C:\Program Files)
    other_disk_paths = []
    for path in sorted(install_paths):
        path_obj = Path(path)
        # Пропусти стандартные пути
        if not (path_obj.drive == 'C:' and ('Program Files' in path)):
            other_disk_paths.append(path)
    
    print(f"Найдено путей установки на других дисках: {len(other_disk_paths)}")
    
    if other_disk_paths:
        print("\nПути установки на других дисках:")
        for i, path in enumerate(other_disk_paths[:10], 1):
            print(f"   {i}. {path}")
        if len(other_disk_paths) > 10:
            print(f"   ... и ещё {len(other_disk_paths) - 10}")
    
    # Сканируй только .exe в папках установки на других дисках
    file_scanner = FileScanner(tree)
    disk_findings = []
    
    print(f"\n🔍 Сканирование .exe файлов в папках установки...")
    
    for install_path in other_disk_paths:
        try:
            path_obj = Path(install_path)
            
            # Найди все .exe файлы в папке и подпапках
            exe_files = list(path_obj.rglob('*.exe'))
            
            if exe_files:
                print(f"\n📁 {install_path}")
                print(f"   Найдено .exe: {len(exe_files)}")
                
                # Сканируй каждый .exe
                scanned_count = 0
                for exe_file in exe_files[:5]:  # Лимит - первые 5 .exe
                    try:
                        finding = file_scanner.scan_file(str(exe_file))
                        if finding:
                            disk_findings.append(finding)
                            if finding.has_vulnerabilities():
                                print(f"      ⚠️  {exe_file.name}: {len(finding.vulnerabilities)} уязв.")
                            scanned_count += 1
                    except:
                        pass
                
                print(f"   ✅ Проанализировано: {scanned_count}")
        
        except Exception as e:
            print(f"   ⚠️  Ошибка: {e}")
    
    all_findings.extend(disk_findings)
    print(f"\n   📊 Со всех дисков: {len(disk_findings)} файлов проверено")
    
    # ========================================================================
    # 3. ОТЧЁТ
    # ========================================================================
    print("\n📄 Генерирование отчёта...")
    report_gen.add_all_analyzed_items(all_findings)
    vulnerable_findings = [f for f in all_findings if f.has_vulnerabilities()]
    report_gen.add_findings(vulnerable_findings)
    
    print(f"\n✅ ИТОГО:")
    print(f"   • Всего предметов проверено: {len(all_findings)}")
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
                # Сканировать Program Files (Windows) или /usr/bin (Linux)
                if sys.platform == 'win32':
                    folder_path = r"C:\Program Files"
                    scan_folder(folder_path, tree, report_gen, all_scanned_files)
                else:
                    folder_path = "/usr/bin"
                    if Path(folder_path).exists():
                        scan_folder(folder_path, tree, report_gen, all_scanned_files)
                    else:
                        print("❌ Папка /usr/bin не найдена")
                        continue
            
            elif choice == '5':
                # Сканировать Program Files (x86) (Windows) или /usr/local/bin (Linux)
                if sys.platform == 'win32':
                    folder_path = r"C:\Program Files (x86)"
                    if Path(folder_path).exists():
                        scan_folder(folder_path, tree, report_gen, all_scanned_files)
                    else:
                        print("❌ Папка Program Files (x86) не найдена")
                        continue
                else:
                    folder_path = "/usr/local/bin"
                    if Path(folder_path).exists():
                        scan_folder(folder_path, tree, report_gen, all_scanned_files)
                    else:
                        print("❌ Папка /usr/local/bin не найдена")
                        continue
            
            elif choice == '6':
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
            
            elif choice == '7':
                # Сканировать /home (Linux)
                if sys.platform != 'win32':
                    folder_path = "/home"
                    if Path(folder_path).exists():
                        scan_folder(folder_path, tree, report_gen, all_scanned_files)
                    else:
                        print("❌ Папка /home не найдена")
                        continue
                else:
                    print("❌ /home доступен только на Linux/macOS")
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
                # Сканирование установленного ПО
                if sys.platform == 'win32':
                    # Windows: реестр
                    scan_registry(tree, report_gen)
                else:
                    # Linux: dpkg/rpm/pacman
                    scan_linux_packages(tree, report_gen)
            
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
