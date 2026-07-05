import os
import sys
import threading
import subprocess
from datetime import datetime, timedelta

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QProgressBar, QTextEdit,
    QDateEdit, QFileDialog, QMessageBox, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QGroupBox, QGridLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDate, QDateTime
from PyQt5.QtGui import QFont, QColor, QBrush

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from modules.file_scanner import FileScanner
from modules.content_analyzer import ContentAnalyzer
from modules.usb_auditor import USBAuditor
from modules.browser_analyzer import BrowserAnalyzer
from modules.chat_auditor import ChatAuditor
from modules.timeline_aggregator import TimelineAggregator
from modules.rule_engine import RuleEngine
from modules.pdf_report import PDFReportGenerator

class AuditThread(QThread):
    progress_update = pyqtSignal(int, str)
    audit_complete = pyqtSignal(dict)
    
    def __init__(self, employee_name, directory_path, start_date, end_date, chat_db_path='', usb_json_path=''):
        super().__init__()
        self.employee_name = employee_name
        self.directory_path = directory_path
        self.start_date = start_date
        self.end_date = end_date
        self.chat_db_path = chat_db_path
        self.usb_json_path = usb_json_path
    
    def run(self):
        try:
            self.progress_update.emit(5, '初始化审计模块...')
            
            file_scanner = FileScanner()
            content_analyzer = ContentAnalyzer()
            usb_auditor = USBAuditor()
            browser_analyzer = BrowserAnalyzer()
            chat_auditor = ChatAuditor()
            timeline_aggregator = TimelineAggregator()
            rule_engine = RuleEngine()
            
            self.progress_update.emit(10, '① 文件扫描：扫描指定目录下所有文件...')
            file_results = file_scanner.scan_directory(
                self.directory_path,
                self.start_date,
                self.end_date,
                lambda msg: self.progress_update.emit(10, msg)
            )
            
            self.progress_update.emit(25, '② 内容分析：提取文档文本并匹配敏感关键词...')
            content_findings = content_analyzer.analyze_files(
                file_results,
                lambda msg: self.progress_update.emit(25, msg)
            )
            
            self.progress_update.emit(40, '③ 聊天记录审计：解析微信/QQ/Skype聊天数据库...')
            chat_records = chat_auditor.audit_chat_records(
                lambda msg: self.progress_update.emit(40, msg),
                self.chat_db_path
            )
            
            self.progress_update.emit(55, '④ USB设备审计：读取注册表提取U盘插拔记录...')
            usb_devices, usb_operations = usb_auditor.audit_usb_devices(
                lambda msg: self.progress_update.emit(55, msg),
                self.usb_json_path
            )
            
            self.progress_update.emit(70, '⑤ 浏览器行为分析：提取历史记录匹配外传渠道...')
            browser_history, cloud_visits, email_visits = browser_analyzer.analyze_browsers(
                lambda msg: self.progress_update.emit(70, msg)
            )
            
            self.progress_update.emit(85, '⑥ 时间线聚合：将所有事件按时间排序...')
            timeline_aggregator.add_events(file_results, 'file')
            timeline_aggregator.add_events(content_findings, 'content')
            timeline_aggregator.add_events(usb_devices, 'usb')
            timeline_aggregator.add_events(browser_history, 'browser')
            timeline_aggregator.add_events(chat_records, 'chat')
            timeline = timeline_aggregator.build_timeline()
            
            self.progress_update.emit(90, '规则引擎汇总分析：计算风险评分...')
            
            scan_results = {
                'night_time_file_operations': file_scanner.get_night_time_operations(),
                'usb_insertions_last_30_days': usb_auditor.get_usb_insertions_count(30),
                'usb_file_copies': usb_auditor.get_usb_file_copies(),
                'chat_leak_keywords_found': chat_auditor.get_leak_keywords_count(),
                'browser_cloud_visits': browser_analyzer.get_cloud_visits_count(30),
                'large_archives_created': len(file_scanner.get_large_archives(min_size_mb=0.001)),
                'content_sensitive_findings': sum(1 for f in content_findings if f.get('type') == 'sensitive_keyword')
            }
            
            risk_assessment = rule_engine.assess_risk(self.employee_name, scan_results)
            scan_results['risk_score'] = risk_assessment['risk_score']
            
            self.progress_update.emit(95, '生成PDF报告...')
            
            browser_findings = browser_analyzer.get_findings()
            all_findings = content_findings + browser_findings
            
            report_data = {
                'employee_name': self.employee_name,
                'audit_range': self.directory_path,
                'audit_time_range': f"{self.start_date.strftime('%Y-%m-%d')} 至 {self.end_date.strftime('%Y-%m-%d')}",
                'data_sources': self._build_data_sources(),
                'risk_level': risk_assessment['risk_level'],
                'findings': risk_assessment['findings'],
                'content_findings': all_findings,
                'timeline': timeline,
                'file_scan_results': file_results
            }
            
            report_generator = PDFReportGenerator()
            report_path = report_generator.generate_report(report_data)
            
            report_data['report_path'] = report_path
            report_data['scan_results'] = scan_results
            report_data['chat_summary'] = chat_auditor.get_summary()
            report_data['browser_summary'] = browser_analyzer.get_summary()
            report_data['usb_summary'] = usb_auditor.get_summary()
            report_data['file_summary'] = file_scanner.get_summary()
            
            self.progress_update.emit(100, '审计完成！')
            self.audit_complete.emit(report_data)
            
        except Exception as e:
            self.progress_update.emit(-1, f'审计过程中发生错误: {str(e)}')

    def _build_data_sources(self):
        return {
            '工作目录': self.directory_path,
            '聊天记录样本': self.chat_db_path or '未指定，尝试读取本机默认聊天目录',
            'USB使用记录样本': self.usb_json_path or '未指定，尝试读取本机注册表'
        }

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('离职场景电子数据取证辅助系统')
        self.setGeometry(100, 100, 1000, 700)
        
        self.init_ui()
    
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        header = QLabel('离职场景电子数据取证辅助系统')
        header.setFont(QFont('SimHei', 20, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header)
        
        input_group = QGroupBox('审计参数')
        input_layout = QGridLayout(input_group)
        
        input_layout.addWidget(QLabel('员工姓名：'), 0, 0)
        self.employee_name_edit = QLineEdit()
        input_layout.addWidget(self.employee_name_edit, 0, 1)
        
        input_layout.addWidget(QLabel('工作目录路径：'), 1, 0)
        self.directory_edit = QLineEdit()
        input_layout.addWidget(self.directory_edit, 1, 1)
        
        browse_btn = QPushButton('浏览')
        browse_btn.clicked.connect(self.browse_directory)
        input_layout.addWidget(browse_btn, 1, 2)

        input_layout.addWidget(QLabel('聊天记录样本：'), 2, 0)
        self.chat_db_edit = QLineEdit()
        self.chat_db_edit.setPlaceholderText('可选：test_data/mock_chat.sqlite')
        input_layout.addWidget(self.chat_db_edit, 2, 1)
        
        browse_chat_btn = QPushButton('选择')
        browse_chat_btn.clicked.connect(self.browse_chat_db)
        input_layout.addWidget(browse_chat_btn, 2, 2)
        
        input_layout.addWidget(QLabel('USB记录样本：'), 3, 0)
        self.usb_json_edit = QLineEdit()
        self.usb_json_edit.setPlaceholderText('可选：test_data/mock_usb_events.json')
        input_layout.addWidget(self.usb_json_edit, 3, 1)
        
        browse_usb_btn = QPushButton('选择')
        browse_usb_btn.clicked.connect(self.browse_usb_json)
        input_layout.addWidget(browse_usb_btn, 3, 2)
        
        input_layout.addWidget(QLabel('审计开始日期：'), 4, 0)
        self.start_date_edit = QDateEdit(QDate.currentDate().addDays(-30))
        self.start_date_edit.setDisplayFormat('yyyy-MM-dd')
        input_layout.addWidget(self.start_date_edit, 4, 1)
        
        input_layout.addWidget(QLabel('审计结束日期：'), 5, 0)
        self.end_date_edit = QDateEdit(QDate.currentDate())
        self.end_date_edit.setDisplayFormat('yyyy-MM-dd')
        input_layout.addWidget(self.end_date_edit, 5, 1)
        
        main_layout.addWidget(input_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel('就绪')
        self.status_label.setFont(QFont('SimHei', 12))
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)
        
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton('开始审计')
        self.start_btn.clicked.connect(self.start_audit)
        self.start_btn.setFont(QFont('SimHei', 14))
        btn_layout.addWidget(self.start_btn)
        
        self.open_report_btn = QPushButton('打开报告')
        self.open_report_btn.clicked.connect(self.open_report)
        self.open_report_btn.setFont(QFont('SimHei', 14))
        self.open_report_btn.setEnabled(False)
        btn_layout.addWidget(self.open_report_btn)
        
        main_layout.addLayout(btn_layout)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont('Consolas', 10))
        main_layout.addWidget(self.log_text)
        
        self.tabs = QTabWidget()
        self.create_tabs()
        main_layout.addWidget(self.tabs)
        
        self.report_path = None
    
    def create_tabs(self):
        self.findings_tab = QWidget()
        self.findings_table = QTableWidget(0, 5)
        self.findings_table.setHorizontalHeaderLabels(['序号', '类型', '文件名', '路径', '描述'])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        findings_layout = QVBoxLayout(self.findings_tab)
        findings_layout.addWidget(self.findings_table)
        self.tabs.addTab(self.findings_tab, '审计发现')
        
        self.timeline_tab = QWidget()
        self.timeline_table = QTableWidget(0, 4)
        self.timeline_table.setHorizontalHeaderLabels(['序号', '时间', '类型', '描述'])
        self.timeline_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        timeline_layout = QVBoxLayout(self.timeline_tab)
        timeline_layout.addWidget(self.timeline_table)
        self.tabs.addTab(self.timeline_tab, '时间线')
        
        self.risk_tab = QWidget()
        self.risk_table = QTableWidget(0, 4)
        self.risk_table.setHorizontalHeaderLabels(['规则ID', '规则名称', '评分', '描述'])
        self.risk_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        risk_layout = QVBoxLayout(self.risk_tab)
        risk_layout.addWidget(self.risk_table)
        self.tabs.addTab(self.risk_tab, '风险评估')
    
    def browse_directory(self):
        directory = QFileDialog.getExistingDirectory(self, '选择工作目录')
        if directory:
            self.directory_edit.setText(directory)

    def browse_chat_db(self):
        file_path, _ = QFileDialog.getOpenFileName(self, '选择聊天记录SQLite样本', '', 'SQLite文件 (*.sqlite *.db);;所有文件 (*)')
        if file_path:
            self.chat_db_edit.setText(file_path)

    def browse_usb_json(self):
        file_path, _ = QFileDialog.getOpenFileName(self, '选择USB记录JSON样本', '', 'JSON文件 (*.json);;所有文件 (*)')
        if file_path:
            self.usb_json_edit.setText(file_path)
    
    def start_audit(self):
        employee_name = self.employee_name_edit.text().strip()
        directory_path = self.directory_edit.text().strip()
        chat_db_path = self.chat_db_edit.text().strip()
        usb_json_path = self.usb_json_edit.text().strip()
        start_date = self.start_date_edit.date().toPyDate()
        end_date = self.end_date_edit.date().toPyDate()
        
        if not employee_name:
            QMessageBox.warning(self, '警告', '请输入员工姓名')
            return
        
        if not directory_path:
            QMessageBox.warning(self, '警告', '请选择工作目录')
            return
        
        if not os.path.exists(directory_path):
            QMessageBox.warning(self, '警告', '指定的目录不存在')
            return

        if chat_db_path and not os.path.exists(chat_db_path):
            QMessageBox.warning(self, '警告', '指定的聊天记录样本不存在')
            return

        if usb_json_path and not os.path.exists(usb_json_path):
            QMessageBox.warning(self, '警告', '指定的USB记录样本不存在')
            return
        
        if start_date > end_date:
            QMessageBox.warning(self, '警告', '开始日期不能大于结束日期')
            return
        
        self.start_btn.setEnabled(False)
        self.log_text.clear()
        self.progress_bar.setValue(0)
        
        self.audit_thread = AuditThread(employee_name, directory_path, start_date, end_date, chat_db_path, usb_json_path)
        self.audit_thread.progress_update.connect(self.update_progress)
        self.audit_thread.audit_complete.connect(self.handle_audit_complete)
        self.audit_thread.start()
    
    def update_progress(self, progress, message):
        if progress == -1:
            self.log_text.append(f'❌ {message}')
            self.status_label.setText('审计失败')
            self.status_label.setStyleSheet('color: red')
            self.start_btn.setEnabled(True)
        else:
            self.progress_bar.setValue(progress)
            self.status_label.setText(message)
            self.log_text.append(f'[{progress}%] {message}')
    
    def handle_audit_complete(self, report_data):
        self.report_path = report_data.get('report_path')
        
        self.log_text.append(f'📄 报告已生成: {self.report_path}')
        self.open_report_btn.setEnabled(True)
        self.start_btn.setEnabled(True)
        
        risk_level = report_data.get('risk_level', {})
        level_text = risk_level.get('level', '无风险')
        color = risk_level.get('color', '#00FF00')
        
        self.status_label.setText(f'审计完成 - 风险等级：{level_text}')
        self.status_label.setStyleSheet(f'color: {color}; font-weight: bold')
        
        self.populate_findings(report_data.get('content_findings', []))
        self.populate_timeline(report_data.get('timeline', []))
        self.populate_risk(report_data.get('findings', []))
    
    def populate_findings(self, findings):
        self.findings_table.setRowCount(0)
        
        severity_colors = {
            'critical': QColor(255, 0, 0),
            'high': QColor(255, 0, 0),
            'medium': QColor(255, 165, 0),
            'low': QColor(255, 255, 0)
        }
        
        for idx, finding in enumerate(findings, 1):
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            
            self.findings_table.setItem(row, 0, QTableWidgetItem(str(idx)))
            self.findings_table.setItem(row, 1, QTableWidgetItem(finding.get('type', '')))
            self.findings_table.setItem(row, 2, QTableWidgetItem(finding.get('file_name', '')))
            
            path_item = QTableWidgetItem(finding.get('file_path', ''))
            path_item.setToolTip(finding.get('file_path', ''))
            self.findings_table.setItem(row, 3, path_item)
            
            desc_item = QTableWidgetItem(finding.get('description', ''))
            severity = finding.get('severity', 'medium')
            desc_item.setForeground(QBrush(severity_colors.get(severity, QColor(0, 0, 0))))
            self.findings_table.setItem(row, 4, desc_item)
    
    def populate_timeline(self, timeline):
        self.timeline_table.setRowCount(0)
        
        for idx, event in enumerate(timeline, 1):
            row = self.timeline_table.rowCount()
            self.timeline_table.insertRow(row)
            
            self.timeline_table.setItem(row, 0, QTableWidgetItem(str(idx)))
            
            timestamp = event.get('timestamp')
            time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(timestamp, 'strftime') else ''
            self.timeline_table.setItem(row, 1, QTableWidgetItem(time_str))
            
            self.timeline_table.setItem(row, 2, QTableWidgetItem(event.get('event_type', '')))
            
            description = ''
            if event.get('file_name'):
                description = event['file_name']
            elif event.get('description'):
                description = str(event['description'])
            elif event.get('url'):
                title = event.get('title', '')
                if title:
                    description = f"{title} - {event['url']}"
                else:
                    description = str(event['url'])
            elif event.get('device_name'):
                description = event['device_name']
            
            self.timeline_table.setItem(row, 3, QTableWidgetItem(description))
    
    def populate_risk(self, findings):
        self.risk_table.setRowCount(0)
        
        for finding in findings:
            row = self.risk_table.rowCount()
            self.risk_table.insertRow(row)
            
            self.risk_table.setItem(row, 0, QTableWidgetItem(finding.get('rule_id', '')))
            self.risk_table.setItem(row, 1, QTableWidgetItem(finding.get('rule_name', '')))
            self.risk_table.setItem(row, 2, QTableWidgetItem(str(finding.get('score', 0))))
            
            desc_item = QTableWidgetItem(finding.get('description', ''))
            severity = finding.get('severity', 'medium')
            
            if severity in ['critical', 'high']:
                desc_item.setForeground(QBrush(QColor(255, 0, 0)))
            elif severity == 'medium':
                desc_item.setForeground(QBrush(QColor(255, 165, 0)))
            else:
                desc_item.setForeground(QBrush(QColor(255, 255, 0)))
            
            self.risk_table.setItem(row, 3, desc_item)
    
    def open_report(self):
        if self.report_path and os.path.exists(self.report_path):
            try:
                subprocess.Popen(['start', self.report_path], shell=True)
            except Exception as e:
                QMessageBox.warning(self, '警告', f'无法打开报告: {str(e)}')
        else:
            QMessageBox.warning(self, '警告', '报告不存在')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
