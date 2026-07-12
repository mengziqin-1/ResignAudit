import os
import sqlite3
from datetime import date, datetime, time

from modules.browser_analyzer import BrowserAnalyzer
from modules.chat_auditor import ChatAuditor
from modules.content_analyzer import ContentAnalyzer
from modules.evidence_engine import EvidenceEngine
from modules.file_scanner import FileScanner
from modules.html_report import HTMLReportGenerator
from modules.pdf_report import PDFReportGenerator
from modules.rule_engine import RuleEngine
from modules.timeline_aggregator import TimelineAggregator
from modules.usb_auditor import USBAuditor


class AuditOrchestrator:
    """审计总编排器：把采集、分析、评分、时间线和报告生成串成一条主链。"""

    def __init__(self, employee_name, directory_path, start_date=None, end_date=None, chat_db_path=''):
        self.employee_name = employee_name
        self.directory_path = directory_path
        self.start_date = start_date
        self.end_date = end_date
        self.chat_db_path = chat_db_path

    def run(self, progress_callback=None):
        self._emit(progress_callback, 5, '初始化审计任务')
        self._validate_inputs()

        detected_chat_db = self.chat_db_path or self._detect_chat_database(self.directory_path)
        self.chat_db_path = detected_chat_db

        audit_start_dt = self._to_start_datetime(self.start_date)
        audit_end_dt = self._to_end_datetime(self.end_date)

        scanner = FileScanner()
        self._emit(progress_callback, 10, '正在扫描文件目录')
        file_scan_results = scanner.scan_directory(
            self.directory_path,
            self.start_date,
            self.end_date,
            progress_callback=lambda msg: self._emit(progress_callback, 15, msg)
        )

        self._emit(progress_callback, 25, '正在检查压缩包内容')
        archive_inspection = scanner.inspect_archives(
            progress_callback=lambda msg: self._emit(progress_callback, 28, msg)
        )

        content_analyzer = ContentAnalyzer()
        self._emit(progress_callback, 35, '正在分析文档敏感内容')
        document_findings = content_analyzer.analyze_files(
            file_scan_results,
            progress_callback=lambda msg: self._emit(progress_callback, 40, msg)
        )

        chat_auditor = ChatAuditor()
        self._emit(progress_callback, 50, '正在分析聊天记录')
        chat_records = chat_auditor.audit_chat_records(
            progress_callback=lambda msg: self._emit(progress_callback, 52, msg),
            mock_db_path=detected_chat_db
        )

        usb_auditor = USBAuditor()
        self._emit(progress_callback, 60, '正在分析USB使用痕迹')
        usb_devices, usb_operations = usb_auditor.audit_usb_devices(
            progress_callback=lambda msg: self._emit(progress_callback, 62, msg)
        )

        browser_analyzer = BrowserAnalyzer()
        self._emit(progress_callback, 70, '正在分析浏览器历史记录')
        browser_records, cloud_visits, email_visits = browser_analyzer.analyze_browsers(
            progress_callback=lambda msg: self._emit(progress_callback, 72, msg)
        )
        browser_findings = browser_analyzer.get_findings()

        content_findings = document_findings + browser_findings

        self._emit(progress_callback, 80, '正在生成事件时间线')
        timeline = self._build_timeline(
            file_scan_results,
            content_findings,
            chat_records,
            usb_devices,
            usb_operations,
            cloud_visits + email_visits
        )

        self._emit(progress_callback, 86, '正在计算综合风险评分')
        scan_results = {
            'content_sensitive_findings': self._count_findings(content_findings, 'sensitive_keyword'),
            'content_keyword_score': self._sum_keyword_score(content_findings),
            'night_time_file_operations': scanner.get_night_time_operations(audit_start_dt, audit_end_dt),
            'usb_insertions_last_30_days': usb_auditor.get_usb_insertions_count(30),
            'usb_file_copies': usb_auditor.get_usb_file_copies(),
            'usb_short_time_insertions': usb_auditor.get_short_time_insertions(),
            'chat_leak_keywords_found': chat_auditor.get_leak_keywords_count(),
            'chat_leak_keyword_score': chat_auditor.get_leak_keyword_score(),
            'browser_cloud_visits': browser_analyzer.get_cloud_visits_count(30) + browser_analyzer.get_email_visits_count(30),
            'large_archives_created': len([item for item in archive_inspection if item.get('sensitive_hit_count', 0) > 0]),
            'archive_inspection': archive_inspection,
        }

        rule_engine = RuleEngine()
        risk_result = rule_engine.assess_risk(self.employee_name, scan_results)

        audit_data = {
            'employee_name': self.employee_name,
            'audit_range': os.path.abspath(self.directory_path),
            'audit_time_range': self._format_audit_time_range(),
            'data_sources': self._build_data_sources(),
            'evidence_type_summary': self._build_evidence_type_summary(
                file_scan_results,
                content_findings,
                chat_records,
                usb_devices,
                usb_operations,
                cloud_visits + email_visits
            ),
            'file_scan_results': file_scan_results,
            'scan_results': {
                **scan_results,
                'risk_score': risk_result['risk_score'],
                'display_score': risk_result['display_score'],
            },
            'content_findings': content_findings,
            'chat_records': chat_records,
            'browser_records': browser_records,
            'usb_devices': usb_devices,
            'usb_operations': usb_operations,
            'timeline': timeline,
            'risk_level': risk_result['risk_level'],
            'findings': risk_result['findings'],
            'file_summary': scanner.get_summary(),
            'content_summary': content_analyzer.get_summary(content_findings),
            'chat_summary': chat_auditor.get_summary(),
            'browser_summary': browser_analyzer.get_summary(),
            'usb_summary': usb_auditor.get_summary(),
            'assessment_time': risk_result['assessment_time'],
        }

        evidence_result = EvidenceEngine().build(audit_data)
        audit_data.update(evidence_result)

        self._emit(progress_callback, 92, '正在生成PDF报告')
        audit_data['report_path'] = PDFReportGenerator().generate_report(audit_data)

        self._emit(progress_callback, 96, '正在生成HTML报告')
        audit_data['html_report_path'] = HTMLReportGenerator().generate_report(audit_data)

        self._emit(progress_callback, 100, '审计完成')
        return audit_data

    def _validate_inputs(self):
        if not self.employee_name:
            raise ValueError('员工姓名不能为空')
        if not self.directory_path:
            raise ValueError('工作目录不能为空')
        if not os.path.isdir(self.directory_path):
            raise ValueError(f'工作目录不存在或不是文件夹: {self.directory_path}')
        if self.chat_db_path and not os.path.exists(self.chat_db_path):
            raise ValueError(f'聊天记录样本不存在: {self.chat_db_path}')

    def _build_timeline(self, file_scan_results, content_findings, chat_records, usb_devices, usb_operations, browser_visits):
        aggregator = TimelineAggregator()
        aggregator.add_events(file_scan_results, 'file')
        aggregator.add_events(content_findings, 'content')
        aggregator.add_events(chat_records, 'chat')
        aggregator.add_events(usb_devices + usb_operations, 'usb')
        aggregator.add_events(browser_visits, 'browser')
        return aggregator.build_timeline()

    def _build_data_sources(self):
        sources = {
            '工作目录': os.path.abspath(self.directory_path),
            '文件系统': '已扫描',
            '浏览器历史': '尝试读取本机 Chrome / Edge / Firefox',
            'USB记录': '尝试读取 Windows 注册表',
        }
        if self.chat_db_path:
            sources['聊天记录样本'] = os.path.abspath(self.chat_db_path)
        else:
            sources['聊天记录样本'] = '未提供，尝试扫描本机常见聊天目录'
        return sources

    def _detect_chat_database(self, directory):
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d.lower() not in {'.git', '__pycache__', 'venv', '.venv', 'node_modules'}]
            for filename in files:
                if not filename.lower().endswith(('.sqlite', '.db')):
                    continue
                db_path = os.path.join(root, filename)
                if self._looks_like_chat_database(db_path):
                    return db_path
        return ''

    def _looks_like_chat_database(self, db_path):
        try:
            conn = sqlite3.connect(db_path)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
                return cursor.fetchone() is not None
            finally:
                conn.close()
        except Exception:
            return False

    def _build_evidence_type_summary(self, file_scan_results, content_findings, chat_records, usb_devices, usb_operations, browser_visits):
        return [
            {
                'type': '文件资产证据',
                'meaning': '证明被审计电脑或样本目录中存在何种资料，例如客户资料、源代码、合同、压缩包等。',
                'count': len(file_scan_results),
                'strength': '确定证据'
            },
            {
                'type': '内容敏感证据',
                'meaning': '证明文件或页面内容中出现敏感资产、外传动作、传输渠道等关键词。',
                'count': len(content_findings),
                'strength': '确定证据/推测线索'
            },
            {
                'type': '沟通意图证据',
                'meaning': '证明聊天记录中是否存在打包、发送、外传、个人邮箱等主观意图表达。',
                'count': len(chat_records),
                'strength': '行为线索'
            },
            {
                'type': '外设使用证据',
                'meaning': '证明是否存在USB设备插拔或外设使用痕迹；除非有文件操作日志，否则不直接等同于复制文件。',
                'count': len(usb_devices) + len(usb_operations),
                'strength': '环境记录'
            },
            {
                'type': '外传通道证据',
                'meaning': '证明是否访问过网盘、邮箱等可能的数据外传渠道。',
                'count': len(browser_visits),
                'strength': '环境记录'
            }
        ]

    def _format_audit_time_range(self):
        if self.start_date and self.end_date:
            return f'{self._format_date(self.start_date)} 至 {self._format_date(self.end_date)}'
        return '未限制'

    def _format_date(self, value):
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d')
        if isinstance(value, date):
            return value.strftime('%Y-%m-%d')
        return str(value)

    def _to_start_datetime(self, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, date):
            return datetime.combine(value, time.min)
        return value

    def _to_end_datetime(self, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, date):
            return datetime.combine(value, time.max)
        return value

    def _count_findings(self, findings, finding_type):
        return len([finding for finding in findings if finding.get('type') == finding_type])

    def _sum_keyword_score(self, findings):
        return sum(int(finding.get('keyword_score', 0) or 0) for finding in findings)

    def _emit(self, progress_callback, progress, message):
        if progress_callback:
            progress_callback(progress, message)
