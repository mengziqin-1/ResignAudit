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

from modules.audit_orchestrator import AuditOrchestrator

class AuditThread(QThread):
    progress_update = pyqtSignal(int, str)
    audit_complete = pyqtSignal(dict)
    
    def __init__(self, employee_name, directory_path, start_date, end_date, chat_db_path=''):
        super().__init__()
        self.employee_name = employee_name
        self.directory_path = directory_path
        self.start_date = start_date
        self.end_date = end_date
        self.chat_db_path = chat_db_path
    
    def run(self):
        try:
            orchestrator = AuditOrchestrator(
                self.employee_name,
                self.directory_path,
                self.start_date,
                self.end_date,
                self.chat_db_path
            )
            
            report_data = orchestrator.run(
                progress_callback=lambda progress, message: self.progress_update.emit(progress, message)
            )
            
            self.audit_complete.emit(report_data)
            
        except Exception as e:
            self.progress_update.emit(-1, f'审计过程中发生错误: {str(e)}')

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
        self.html_report_path = None
    
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


    
    def start_audit(self):
        employee_name = self.employee_name_edit.text().strip()
        directory_path = self.directory_edit.text().strip()
        chat_db_path = self.chat_db_edit.text().strip()
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
        
        if start_date > end_date:
            QMessageBox.warning(self, '警告', '开始日期不能大于结束日期')
            return
        
        self.start_btn.setEnabled(False)
        self.log_text.clear()
        self.progress_bar.setValue(0)
        
        self.audit_thread = AuditThread(employee_name, directory_path, start_date, end_date, chat_db_path)
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
        self.html_report_path = report_data.get('html_report_path')
        
        self.log_text.append(f'📄 PDF报告已生成: {self.report_path}')
        self.log_text.append(f'🌐 HTML报告已生成: {self.html_report_path}')
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
        # 优先打开HTML报告
        if self.html_report_path and os.path.exists(self.html_report_path):
            try:
                subprocess.Popen(['start', self.html_report_path], shell=True)
                return
            except Exception as e:
                QMessageBox.warning(self, '警告', f'无法打开HTML报告: {str(e)}')
        
        # 如果HTML不存在，再尝试打开PDF
        if self.report_path and os.path.exists(self.report_path):
            try:
                subprocess.Popen(['start', self.report_path], shell=True)
                return
            except Exception as e:
                QMessageBox.warning(self, '警告', f'无法打开PDF报告: {str(e)}')
        
        QMessageBox.warning(self, '警告', '报告不存在')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
