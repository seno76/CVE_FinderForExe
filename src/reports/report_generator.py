"""
Генератор отчётов в формате JSON и HTML
"""

import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from ..scanner.file_scanner import VulnerabilityFinding


class ReportGenerator:
    """
    Генератор отчётов из результатов сканирования
    """
    
    def __init__(self):
        """Инициализация генератора"""
        self.findings: List[VulnerabilityFinding] = []
        self.scan_timestamp = None
        self.scanned_files: List[str] = []  # Все просканированные файлы
        self.total_files_scanned = 0
        self.all_analyzed_items = []  # Все анализированные предметы (файлы или программы)
    
    def add_findings(self, findings: List[VulnerabilityFinding]) -> None:
        """Добавить результаты сканирования"""
        self.findings.extend(findings)
        # Также добавь в список всех анализированных предметов
        self.all_analyzed_items.extend(findings)
        self.scan_timestamp = datetime.now().isoformat()
    
    def add_scanned_files(self, files: List[str], total: int = None) -> None:
        """
        Добавить информацию о просканированных файлах
        
        Args:
            files: Список просканированных файлов
            total: Всего файлов
        """
        self.scanned_files = files
        self.total_files_scanned = total or len(files)
    
    def add_all_analyzed_items(self, items: List[VulnerabilityFinding]) -> None:
        """
        Добавить все анализированные предметы (файлы или программы из реестра)
        Используется для отображения полного списка в отчёте
        
        Args:
            items: Список всех анализированных предметов
        """
        self.all_analyzed_items = items
    
    def generate_json(self, output_path: str) -> None:
        """
        Сгенерировать отчёт в JSON
        
        Args:
            output_path: Путь к файлу отчёта
        """
        # Подсчитай статистику
        vulnerable_files = [f for f in self.findings if f.has_vulnerabilities()]
        all_vulnerabilities = []
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for finding in self.findings:
            for vuln in finding.vulnerabilities:
                all_vulnerabilities.append(vuln)
                if hasattr(vuln, 'severity'):
                    if vuln.severity.value == 'critical':
                        critical_count += 1
                    elif vuln.severity.value == 'high':
                        high_count += 1
                    elif vuln.severity.value == 'medium':
                        medium_count += 1
                    elif vuln.severity.value == 'low':
                        low_count += 1
        
        report_data = {
            'metadata': {
                'scan_date': self.scan_timestamp or datetime.now().isoformat(),
                'total_files_scanned': len(self.all_analyzed_items) or len(self.findings),
                'files_with_vulnerabilities': len(vulnerable_files),
                'total_vulnerabilities': len(all_vulnerabilities),
                'critical_vulnerabilities': critical_count,
                'high_vulnerabilities': high_count,
                'medium_vulnerabilities': medium_count,
                'low_vulnerabilities': low_count,
            },
            # ВСЕ файлы/программы, включая безопасные
            'all_files': [
                {
                    'file_path': f.file_path,
                    'software_name': f.software_name,
                    'software_version': f.software_version,
                    'vulnerabilities_count': len(f.vulnerabilities),
                    'status': 'vulnerable' if f.has_vulnerabilities() else 'safe'
                }
                for f in (self.all_analyzed_items or self.findings)
            ],
            # Только файлы с уязвимостями с деталями
            'findings': [f.to_dict() for f in vulnerable_files],
        }
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        
        print(f"✓ JSON отчёт сохранён: {output_path}")
    
    def generate_html(self, output_path: str, title: str = "Отчёт о уязвимостях") -> None:
        """
        Сгенерировать отчёт в HTML
        
        Args:
            output_path: Путь к файлу отчёта
            title: Заголовок отчёта
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Подготовь данные
        findings_with_vulns = [f for f in self.findings if f.has_vulnerabilities()]
        total_vulns = sum(len(f.vulnerabilities) for f in findings_with_vulns)
        critical_vulns = sum(
            len([v for v in f.vulnerabilities if v.severity.value == 'critical'])
            for f in findings_with_vulns
        )
        high_vulns = sum(
            len([v for v in f.vulnerabilities if v.severity.value == 'high'])
            for f in findings_with_vulns
        )
        
        # Создай HTML
        html_content = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            color: #333;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .stat-box {{
            background: rgba(255, 255, 255, 0.2);
            padding: 15px;
            border-radius: 5px;
        }}
        
        .stat-box .label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        
        .stat-box .value {{
            font-size: 2em;
            font-weight: bold;
            margin-top: 5px;
        }}
        
        .tabs {{
            display: flex;
            gap: 10px;
            margin: 30px 0 20px 0;
            border-bottom: 2px solid #ddd;
        }}
        
        .tab-button {{
            padding: 10px 20px;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 16px;
            color: #666;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }}
        
        .tab-button.active {{
            color: #667eea;
            border-bottom-color: #667eea;
        }}
        
        .tab-content {{
            display: none;
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        .critical {{
            color: #ff6b6b;
        }}
        
        .high {{
            color: #ffa94d;
        }}
        
        .medium {{
            color: #ffd93d;
        }}
        
        .low {{
            color: #6bcf7f;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
        }}
        
        table th {{
            background-color: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        table td {{
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }}
        
        table tr:hover {{
            background-color: #f9f9f9;
        }}
        
        .vulnerability {{
            background: #f0f0f0;
            padding: 10px;
            margin: 5px 0;
            border-left: 4px solid #667eea;
            border-radius: 3px;
        }}
        
        .vulnerability.critical {{
            border-left-color: #ff6b6b;
        }}
        
        .vulnerability.high {{
            border-left-color: #ffa94d;
        }}
        
        .vulnerability.medium {{
            border-left-color: #ffd93d;
        }}
        
        .vulnerability.low {{
            border-left-color: #6bcf7f;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
            color: white;
        }}
        
        .severity-badge.critical {{
            background-color: #ff6b6b;
        }}
        
        .severity-badge.high {{
            background-color: #ffa94d;
        }}
        
        .severity-badge.medium {{
            background-color: #ffd93d;
            color: #333;
        }}
        
        .severity-badge.low {{
            background-color: #6bcf7f;
        }}
        
        .no-vulnerabilities {{
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 10px;
        }}
        
        .recommendations {{
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin: 10px 0;
            border-radius: 3px;
        }}
        
        .recommendations h4 {{
            color: #1976D2;
            margin-bottom: 10px;
        }}
        
        .recommendations p {{
            color: #0d47a1;
            line-height: 1.6;
        }}
        
        .scanned-files {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
        }}
        
        .scanned-files h3 {{
            margin-bottom: 15px;
            color: #667eea;
        }}
        
        .file-list {{
            max-height: 400px;
            overflow-y: auto;
            background: #f9f9f9;
            padding: 10px;
            border-radius: 5px;
        }}
        
        .file-item {{
            padding: 8px;
            margin: 5px 0;
            background: white;
            border-left: 3px solid #ddd;
            font-size: 0.9em;
            word-break: break-all;
        }}
        
        footer {{
            text-align: center;
            color: #999;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{title}</h1>
            <p>Дата сканирования: {self.scan_timestamp or datetime.now().isoformat()}</p>
            
            <div class="stats">
                <div class="stat-box">
                    <div class="label">Просканировано файлов</div>
                    <div class="value">{self.total_files_scanned}</div>
                </div>
                <div class="stat-box">
                    <div class="label">Файлов с уязвимостями</div>
                    <div class="value">{len(findings_with_vulns)}</div>
                </div>
                <div class="stat-box">
                    <div class="label">Всего уязвимостей</div>
                    <div class="value">{total_vulns}</div>
                </div>
                <div class="stat-box">
                    <div class="label critical">Критических</div>
                    <div class="value critical">{critical_vulns}</div>
                </div>
                <div class="stat-box">
                    <div class="label high">Высокой опасности</div>
                    <div class="value high">{high_vulns}</div>
                </div>
            </div>
        </header>
        
        <main>
            <div class="tabs">
                <button class="tab-button active" onclick="switchTab('vulnerabilities')">Уязвимости</button>
                <button class="tab-button" onclick="switchTab('files')">Просканированные файлы</button>
            </div>
            
            <div id="vulnerabilities" class="tab-content active">
                <h2>Результаты сканирования</h2>
                {self._generate_html_table(findings_with_vulns)}
            </div>
            
            <div id="files" class="tab-content">
                <div class="scanned-files">
                    <h3>Просканированные файлы ({len(self.all_analyzed_items or self.findings)})</h3>
                    <div class="file-list">
                        {self._generate_file_list()}
                    </div>
                </div>
            </div>
        </main>
        
        <footer>
            <p>Отчёт сгенерирован автоматически системой Bochka</p>
        </footer>
    </div>
    
    <script>
        function switchTab(tabName) {{
            // Скрой все вкладки
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(c => c.classList.remove('active'));
            
            // Убери активный класс со всех кнопок
            const buttons = document.querySelectorAll('.tab-button');
            buttons.forEach(b => b.classList.remove('active'));
            
            // Покажи выбранную вкладку
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }}
    </script>
</body>
</html>"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✓ HTML отчёт сохранён: {output_path}")
    
    def _generate_html_table(self, findings: List[VulnerabilityFinding]) -> str:
        """Сгенерировать HTML таблицу с результатами"""
        if not findings:
            return '<p class="no-vulnerabilities">Уязвимостей не найдено!</p>'
        
        table_html = '<table><thead><tr>'
        table_html += '<th>Файл</th>'
        table_html += '<th>ПО</th>'
        table_html += '<th>Версия</th>'
        table_html += '<th>Уязвимости и рекомендации</th>'
        table_html += '</tr></thead><tbody>'
        
        for finding in findings:
            if not finding.has_vulnerabilities():
                continue
            
            # Сгенерируй строку таблицы
            file_path = finding.file_path
            software_name = finding.software_name or 'Неизвестно'
            software_version = finding.software_version or 'Неизвестно'
            
            # Сгенерируй список уязвимостей с рекомендациями
            vulns_html = '<div>'
            for vuln in finding.vulnerabilities:
                severity = vuln.severity.value
                severity_class = self._get_severity_class(severity)
                
                recommendations = vuln.additional_info.get('recommendations', '')
                remediation = vuln.additional_info.get('remediation', '')
                
                # Подготовь текст рекомендаций
                rec_text = recommendations if recommendations else remediation
                rec_html = ''
                if rec_text:
                    rec_html = f'''<div class="recommendations">
                        <h4>Рекомендация по устранению:</h4>
                        <p>{rec_text}</p>
                    </div>'''
                
                vuln_html = f'''<div class="vulnerability {severity_class}">
                    <strong>{vuln.bdu_id}</strong> 
                    {f'({vuln.cve_id})' if vuln.cve_id else ''}
                    <span class="severity-badge {severity_class}">{severity.upper()}</span>
                    <p><strong>{vuln.name}</strong></p>
                    <p>{vuln.description[:200]}{'...' if len(vuln.description) > 200 else ''}</p>
                    {rec_html}
                </div>'''
                vulns_html += vuln_html
            vulns_html += '</div>'
            
            table_html += f'''<tr>
                <td><small>{file_path}</small></td>
                <td>{software_name}</td>
                <td>{software_version}</td>
                <td>{vulns_html}</td>
            </tr>'''
        
        table_html += '</tbody></table>'
        return table_html
    
    def _generate_file_list(self) -> str:
        """Сгенерировать список всех анализированных файлов/программ"""
        # Используй all_analyzed_items вместо scanned_files
        items = self.all_analyzed_items or self.findings
        
        if not items:
            return '<p>Нет анализированных файлов</p>'
        
        file_html = '<table class="files-table"><thead><tr><th>Файл/Программа</th><th>ПО</th><th>Версия</th><th>Уязвимостей</th><th>Статус</th></tr></thead><tbody>'
        
        for item in items[:1000]:  # Лимит на 1000 файлов
            status = 'Уязвимо' if item.has_vulnerabilities() else 'Безопасно'
            status_class = 'critical' if item.has_vulnerabilities() else 'low'
            
            file_html += f'''<tr>
                <td>{item.file_path or 'N/A'}</td>
                <td>{item.software_name or '-'}</td>
                <td>{item.software_version or '-'}</td>
                <td>{len(item.vulnerabilities)}</td>
                <td><span class="{status_class}">{status}</span></td>
            </tr>'''
        
        file_html += '</tbody></table>'
        
        if len(items) > 1000:
            file_html += f'<p><em>... и ещё {len(items) - 1000} файлов</em></p>'
        
        return file_html
    
    @staticmethod
    def _get_severity_class(severity: str) -> str:
        """Получить CSS класс для уровня критичности"""
        severity_lower = severity.lower()
        if 'critical' in severity_lower:
            return 'critical'
        elif 'high' in severity_lower:
            return 'high'
        elif 'medium' in severity_lower:
            return 'medium'
        elif 'low' in severity_lower:
            return 'low'
        return 'unknown'
