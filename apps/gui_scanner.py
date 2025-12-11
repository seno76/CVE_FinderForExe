"""
Графический интерфейс для Bochka - Сканера уязвимостей
"""

import sys
import time
from pathlib import Path
from threading import Thread
from typing import List, Optional

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog, QMessageBox,
    QProgressBar, QListWidget, QListWidgetItem, QTabWidget,
    QTextEdit, QComboBox, QSpinBox, QCheckBox, QGroupBox,
    QDialog, QScrollArea, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QColor, QFont, QIcon, QPixmap

# Добавь корневую директорию проекта в путь
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parsers import DataLoader
from src.scanner import FolderScanner, FileScanner, RegistryScanner
from src.scanner.file_scanner import VulnerabilityFinding
from src.detectors.system_scanner import SystemScanner
from src.reports import ReportGenerator


class ScanWorker(QObject):
    """Рабочий поток для сканирования"""
    
    progress = pyqtSignal(int, int)  # current, total
    finished = pyqtSignal(dict)  # результаты
    error = pyqtSignal(str)  # ошибка
    
    def __init__(self, tree, scan_type, scan_path=None):
        super().__init__()
        self.tree = tree
        self.scan_type = scan_type
        self.scan_path = scan_path
        self.report_gen = ReportGenerator()
    
    def progress_callback(self, current, total):
        """Обновить прогресс"""
        self.progress.emit(current, total)
    
    def run_scan(self):
        """Запустить сканирование"""
        try:
            if self.scan_type == 'file':
                self._scan_file()
            elif self.scan_type == 'folder':
                self._scan_folder()
            elif self.scan_type == 'registry' and sys.platform == 'win32':
                self._scan_registry()
            elif self.scan_type == 'installed_packages':
                self._scan_installed_packages()
            elif self.scan_type == 'system':
                self._scan_system()
            
            self.finished.emit({
                'findings': self.report_gen.findings,
                'all_analyzed_items': self.report_gen.all_analyzed_items
            })
        except Exception as e:
            self.error.emit(str(e))
    
    def _scan_file(self):
        """Сканировать один файл"""
        scanner = FileScanner(self.tree)
        finding = scanner.scan_file(self.scan_path)
        if finding:
            self.report_gen.add_findings([finding])
    
    def _scan_folder(self):
        """Сканировать папку"""
        scanner = FolderScanner(self.tree, max_workers=4)
        findings = scanner.scan_folder(
            self.scan_path,
            progress_callback=self.progress_callback,
            parallel=True
        )
        self.report_gen.add_all_analyzed_items(findings)
        vulnerable = [f for f in findings if f.has_vulnerabilities()]
        self.report_gen.add_findings(vulnerable)
    
    def _scan_registry(self):
        """Сканировать реестр Windows"""
        if sys.platform != 'win32':
            self.error.emit("Реестр доступен только на Windows")
            return
        
        registry_scanner = RegistryScanner(self.tree)
        scan_results = registry_scanner.scan_registry(
            progress_callback=self.progress_callback
        )
        
        # Создай правильные Finding объекты из результатов реестра
        all_findings = []
        for result in scan_results:
            finding = VulnerabilityFinding(
                file_path=result['install_path'],
                software_name=result['software_name'],
                software_version=result['software_version'],
                vulnerabilities=result['vulnerabilities']
            )
            all_findings.append(finding)
        
        self.report_gen.add_all_analyzed_items(all_findings)
        
        vulnerable = [f for f in all_findings if f.has_vulnerabilities()]
        self.report_gen.add_findings(vulnerable)
    
    def _scan_installed_packages(self):
        """Сканировать установленное ПО (Windows: реестр, Linux: dpkg/rpm)"""
        if sys.platform == 'win32':
            # Windows: через реестр
            registry_scanner = RegistryScanner(self.tree)
            scan_results = registry_scanner.scan_registry(
                progress_callback=self.progress_callback
            )
            
            all_findings = []
            for result in scan_results:
                finding = VulnerabilityFinding(
                    file_path=result['install_path'],
                    software_name=result['software_name'],
                    software_version=result['software_version'],
                    vulnerabilities=result['vulnerabilities']
                )
                all_findings.append(finding)
            
            self.report_gen.add_all_analyzed_items(all_findings)
            vulnerable = [f for f in all_findings if f.has_vulnerabilities()]
            self.report_gen.add_findings(vulnerable)
        else:
            # Linux: через dpkg/rpm/pacman
            scanner = SystemScanner()
            packages = scanner.get_installed_packages_linux()
            
            if not packages:
                self.error.emit("Не удалось получить список пакетов")
                return
            
            total = len(packages)
            all_findings = []
            
            for idx, pkg in enumerate(packages, 1):
                self.progress_callback(idx, total)
                
                pkg_name = pkg['name']
                pkg_version = pkg['version']
                install_path = pkg.get('install_path', f'/usr/bin/{pkg_name}')
                
                vulnerabilities = self.tree.search(pkg_name, pkg_version)
                
                finding = VulnerabilityFinding(
                    file_path=install_path,
                    software_name=pkg_name,
                    software_version=pkg_version,
                    vulnerabilities=vulnerabilities
                )
                all_findings.append(finding)
            
            self.report_gen.add_all_analyzed_items(all_findings)
            vulnerable = [f for f in all_findings if f.has_vulnerabilities()]
            self.report_gen.add_findings(vulnerable)
    
    def _scan_system(self):
        """Сканировать системные папки"""
        folders = []
        if sys.platform == 'win32':
            folders = [r"C:\Program Files", r"C:\Program Files (x86)"]
        else:
            folders = ["/usr/bin", "/usr/local/bin", "/opt"]
        
        all_findings = []
        for folder in folders:
            if not Path(folder).exists():
                continue
            
            scanner = FolderScanner(self.tree, max_workers=4)
            findings = scanner.scan_folder(
                folder,
                progress_callback=self.progress_callback,
                parallel=True
            )
            all_findings.extend(findings)
        
        self.report_gen.add_all_analyzed_items(all_findings)
        vulnerable = [f for f in all_findings if f.has_vulnerabilities()]
        self.report_gen.add_findings(vulnerable)


class BochkaGUI(QMainWindow):
    """Главное окно приложения Bochka"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Bochka - Сканер уязвимостей БДУ ФСТЕК")
        self.setGeometry(100, 100, 1200, 800)
        
        # Загрузи БДУ
        self.tree = None
        self.report_gen = None
        self.scan_thread = None
        self.scan_worker = None
        
        # Инициализируй UI
        self.init_ui()
        
        # Загрузи БДУ в отдельном потоке
        self.load_bdu()
    
    def init_ui(self):
        """Инициализировать интерфейс"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Заголовок
        header = QLabel("🔐 Bochka - Сканер уязвимостей")
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setBold(True)
        header.setFont(header_font)
        layout.addWidget(header)
        
        # Статус БДУ
        self.status_label = QLabel("⏳ Загрузка базы данных БДУ...")
        layout.addWidget(self.status_label)
        
        # Табы
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Таб 1: Сканирование
        self.init_scan_tab()
        
        # Таб 2: Результаты
        self.init_results_tab()
        
        # Таб 3: Отчёты
        self.init_reports_tab()
    
    def init_scan_tab(self):
        """Таб сканирования"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Группа: Выбор файла/папки
        file_group = QGroupBox("📁 Выбор пути")
        file_layout = QHBoxLayout()
        
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Выберите файл или папку...")
        file_layout.addWidget(self.path_input)
        
        browse_btn = QPushButton("Обзор...")
        browse_btn.clicked.connect(self.browse_path)
        file_layout.addWidget(browse_btn)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Группа: Режимы сканирования
        mode_group = QGroupBox("💻 Режимы сканирования")
        mode_layout = QVBoxLayout()
        
        # Кнопки режимов
        self.file_btn = QPushButton("📄 Сканировать файл")
        self.file_btn.clicked.connect(self.scan_file)
        self.file_btn.setEnabled(False)
        mode_layout.addWidget(self.file_btn)
        
        self.folder_btn = QPushButton("📂 Сканировать папку")
        self.folder_btn.clicked.connect(self.scan_folder)
        self.folder_btn.setEnabled(False)
        mode_layout.addWidget(self.folder_btn)
        
        # Кнопка сканирования установленного ПО (работает на обеих платформах)
        if sys.platform == 'win32':
            self.installed_btn = QPushButton("📦 Сканировать установленное ПО (реестр Windows)")
        else:
            self.installed_btn = QPushButton("📦 Сканировать установленное ПО (dpkg/rpm)")
        self.installed_btn.clicked.connect(self.scan_installed_packages)
        self.installed_btn.setEnabled(False)
        mode_layout.addWidget(self.installed_btn)
        
        # Для совместимости оставляем registry_btn = None на Linux
        self.registry_btn = None
        
        self.system_btn = QPushButton("⚙️ Полное системное сканирование")
        self.system_btn.clicked.connect(self.scan_system)
        self.system_btn.setEnabled(False)
        mode_layout.addWidget(self.system_btn)
        
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)
        
        # Прогресс
        layout.addWidget(QLabel("📊 Прогресс:"))
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.progress_label = QLabel()
        layout.addWidget(self.progress_label)
        
        layout.addStretch()
        
        self.tabs.addTab(widget, "🔍 Сканирование")
    
    def init_results_tab(self):
        """Таб результатов"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Статистика
        stats_group = QGroupBox("📊 Статистика")
        stats_layout = QHBoxLayout()
        
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setMaximumHeight(100)
        stats_layout.addWidget(self.stats_text)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Результаты
        layout.addWidget(QLabel("🔎 Результаты:"))
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        self.tabs.addTab(widget, "📋 Результаты")
    
    def init_reports_tab(self):
        """Таб отчётов"""
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Параметры отчёта
        params_group = QGroupBox("⚙️ Параметры отчёта")
        params_layout = QVBoxLayout()
        
        # Имя JSON
        json_layout = QHBoxLayout()
        json_layout.addWidget(QLabel("JSON файл:"))
        self.json_input = QLineEdit("report.json")
        json_layout.addWidget(self.json_input)
        params_layout.addLayout(json_layout)
        
        # Имя HTML
        html_layout = QHBoxLayout()
        html_layout.addWidget(QLabel("HTML файл:"))
        self.html_input = QLineEdit("report.html")
        html_layout.addWidget(self.html_input)
        params_layout.addLayout(html_layout)
        
        params_group.setLayout(params_layout)
        layout.addWidget(params_group)
        
        # Кнопки
        buttons_layout = QHBoxLayout()
        
        json_btn = QPushButton("💾 Сохранить JSON")
        json_btn.clicked.connect(self.save_json_report)
        buttons_layout.addWidget(json_btn)
        
        html_btn = QPushButton("🌐 Сохранить HTML")
        html_btn.clicked.connect(self.save_html_report)
        buttons_layout.addWidget(html_btn)
        
        open_html_btn = QPushButton("📖 Открыть HTML")
        open_html_btn.clicked.connect(self.open_html_report)
        buttons_layout.addWidget(open_html_btn)
        
        layout.addLayout(buttons_layout)
        
        layout.addStretch()
        
        self.tabs.addTab(widget, "📄 Отчёты")
    
    def load_bdu(self):
        """Загрузить БДУ"""
        def load():
            try:
                loader = DataLoader(cache_dir='cache')
                self.tree = loader.load_bdu('data/full_data.xlsx', use_cache=True)
                
                stats = self.tree.get_statistics()
                status_text = f"""✅ База данных загружена успешно!
                
📊 Статистика БДУ:
  • ПО в базе: {stats['total_software']:,}
  • Версий: {stats['total_versions']:,}
  • Всего уязвимостей: {stats['total_vulnerabilities']:,}
  • Критических: {stats['critical_vulnerabilities']:,}
"""
                self.status_label.setText(status_text)
                
                # Включи кнопки
                self.file_btn.setEnabled(True)
                self.folder_btn.setEnabled(True)
                self.system_btn.setEnabled(True)
                if hasattr(self, 'installed_btn'):
                    self.installed_btn.setEnabled(True)
                if self.registry_btn:
                    self.registry_btn.setEnabled(True)
            
            except Exception as e:
                self.status_label.setText(f"❌ Ошибка загрузки БДУ: {e}")
        
        thread = Thread(target=load, daemon=True)
        thread.start()
    
    def browse_path(self):
        """Выбрать путь"""
        path = QFileDialog.getExistingDirectory(self, "Выберите папку")
        if path:
            self.path_input.setText(path)
    
    def scan_file(self):
        """Сканировать файл"""
        file_path = QFileDialog.getOpenFileName(
            self,
            "Выберите файл для сканирования",
            "",
            "Executable Files (*.exe *.bin *.elf);;All Files (*)"
        )[0]
        
        if file_path:
            self.start_scan('file', file_path)
    
    def scan_folder(self):
        """Сканировать папку"""
        if not self.path_input.text():
            QMessageBox.warning(self, "Ошибка", "Выберите папку")
            return
        
        self.start_scan('folder', self.path_input.text())
    
    def scan_registry(self):
        """Сканировать реестр"""
        if sys.platform != 'win32':
            QMessageBox.warning(self, "Ошибка", "Реестр доступен только на Windows")
            return
        
        self.start_scan('registry')
    
    def scan_installed_packages(self):
        """Сканировать установленное ПО (реестр Windows / dpkg/rpm Linux)"""
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            "Сканирование установленного ПО может занять некоторое время.\nПродолжить?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.start_scan('installed_packages')
    
    def scan_system(self):
        """Полное системное сканирование"""
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            "Полное системное сканирование может занять длительное время.\nПродолжить?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.start_scan('system')
    
    def start_scan(self, scan_type, path=None):
        """Запустить сканирование"""
        if not self.tree:
            QMessageBox.warning(self, "Ошибка", "БДУ не загружена")
            return
        
        # Заверши предыдущий поток если он ещё работает
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.quit()
            self.scan_thread.wait()
        
        # Отключи кнопки
        self.file_btn.setEnabled(False)
        self.folder_btn.setEnabled(False)
        self.system_btn.setEnabled(False)
        if hasattr(self, 'installed_btn'):
            self.installed_btn.setEnabled(False)
        if self.registry_btn:
            self.registry_btn.setEnabled(False)
        
        # Покажи прогресс
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Сканирование в процессе...")
        
        # Создай рабочий поток
        self.scan_worker = ScanWorker(self.tree, scan_type, path)
        self.scan_thread = QThread()
        self.scan_worker.moveToThread(self.scan_thread)
        
        self.scan_worker.progress.connect(self.update_progress)
        self.scan_worker.finished.connect(self.scan_finished)
        self.scan_worker.error.connect(self.scan_error)
        
        # Завершай поток после сканирования
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.error.connect(self.scan_thread.quit)
        
        self.scan_thread.started.connect(self.scan_worker.run_scan)
        self.scan_thread.start()
    
    def update_progress(self, current, total):
        """Обновить прогресс"""
        if total > 0:
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(current)
            self.progress_label.setText(f"Обработано: {current}/{total}")
    
    def scan_finished(self, result):
        """Сканирование завершено"""
        self.progress_bar.setVisible(False)
        self.progress_label.setText("✅ Сканирование завершено")
        
        # Сохрани результаты
        self.report_gen = self.scan_worker.report_gen
        
        # Покажи результаты
        self.show_results(result)
        
        # Включи кнопки
        self.file_btn.setEnabled(True)
        self.folder_btn.setEnabled(True)
        self.system_btn.setEnabled(True)
        if hasattr(self, 'installed_btn'):
            self.installed_btn.setEnabled(True)
        if self.registry_btn:
            self.registry_btn.setEnabled(True)
        
        # Перейди на таб результатов
        self.tabs.setCurrentIndex(1)
        
        # Безопасно завершай работника
        if self.scan_worker:
            self.scan_worker.deleteLater()
    
    def scan_error(self, error):
        """Ошибка сканирования"""
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Ошибка сканирования", error)
        
        # Включи кнопки
        self.file_btn.setEnabled(True)
        self.folder_btn.setEnabled(True)
        self.system_btn.setEnabled(True)
        if hasattr(self, 'installed_btn'):
            self.installed_btn.setEnabled(True)
        if self.registry_btn:
            self.registry_btn.setEnabled(True)
        
        # Безопасно завершай работника
        if self.scan_worker:
            self.scan_worker.deleteLater()
    
    def show_results(self, result):
        """Показать результаты"""
        findings = result['findings']
        all_items = result['all_analyzed_items']
        
        # Статистика
        vulnerable = len([f for f in findings if f.has_vulnerabilities()])
        total_vulns = sum(len(f.vulnerabilities) for f in findings)
        
        stats_text = f"""📊 СТАТИСТИКА:
  • Всего файлов проверено: {len(all_items)}
  • Файлов с уязвимостями: {vulnerable}
  • Всего уязвимостей найдено: {total_vulns}
"""
        self.stats_text.setText(stats_text)
        
        # Результаты
        results_text = "🔎 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ:\n\n"
        
        for finding in findings:
            results_text += f"📦 {finding.software_name} {finding.software_version}\n"
            results_text += f"   Файл: {finding.file_path}\n"
            results_text += f"   Уязвимостей: {len(finding.vulnerabilities)}\n"
            
            for vuln in finding.vulnerabilities[:5]:
                results_text += f"     • {vuln.bdu_id}: {vuln.name}\n"
            
            if len(finding.vulnerabilities) > 5:
                results_text += f"     ... и ещё {len(finding.vulnerabilities) - 5}\n"
            
            results_text += "\n"
        
        self.results_text.setText(results_text)
    
    def save_json_report(self):
        """Сохранить JSON отчёт"""
        if not self.report_gen:
            QMessageBox.warning(self, "Ошибка", "Сначала выполни сканирование")
            return
        
        if not self.report_gen.findings or len(self.report_gen.findings) == 0:
            QMessageBox.warning(self, "Ошибка", "Нет результатов для сохранения")
            return
        
        filename = self.json_input.text()
        if not filename:
            QMessageBox.warning(self, "Ошибка", "Укажите имя файла JSON")
            return
        
        try:
            self.report_gen.generate_json(filename)
            QMessageBox.information(self, "Успех", f"JSON отчёт сохранён:\n{filename}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка сохранения JSON:\n{str(e)}")
    
    def save_html_report(self):
        """Сохранить HTML отчёт"""
        if not self.report_gen:
            QMessageBox.warning(self, "Ошибка", "Сначала выполни сканирование")
            return
        
        if not self.report_gen.findings or len(self.report_gen.findings) == 0:
            QMessageBox.warning(self, "Ошибка", "Нет результатов для сохранения")
            return
        
        filename = self.html_input.text()
        if not filename:
            QMessageBox.warning(self, "Ошибка", "Укажите имя файла HTML")
            return
        
        try:
            self.report_gen.generate_html(filename)
            QMessageBox.information(self, "Успех", f"HTML отчёт сохранён:\n{filename}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка сохранения HTML:\n{str(e)}")
    
    def open_html_report(self):
        """Открыть HTML отчёт в браузере"""
        filename = self.html_input.text()
        if not Path(filename).exists():
            QMessageBox.warning(self, "Ошибка", f"Файл не найден: {filename}")
            return
        
        import webbrowser
        webbrowser.open(f"file://{Path(filename).absolute()}")


def main():
    """Запустить приложение"""
    app = QApplication(sys.argv)
    
    # Стиль
    app.setStyle('Fusion')
    
    # Главное окно
    window = BochkaGUI()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
