import os
import uuid
from datetime import datetime
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, Frame
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase.cidfonts import UnicodeCIDFont

from utils.common import sanitize_filename

_CHINESE_FONT_REGISTERED = False

def _register_chinese_font():
    global _CHINESE_FONT_REGISTERED
    if _CHINESE_FONT_REGISTERED:
        return
    
    font_paths = [
        r'C:\Windows\Fonts\simhei.ttf',
        r'C:\Windows\Fonts\simfang.ttf',
        r'C:\Windows\Fonts\simsun.ttc',
        r'C:\Windows\Fonts\msyh.ttc',
        r'C:\Windows\Fonts\msyhbd.ttc',
        os.path.expanduser(r'~\AppData\Local\Microsoft\Windows\Fonts\simhei.ttf'),
    ]
    
    for font_path in font_paths:
        if os.path.exists(font_path):
            try:
                pdfmetrics.registerFont(TTFont('Chinese', font_path))
                _CHINESE_FONT_REGISTERED = True
                return
            except Exception:
                continue
    
    try:
        pdfmetrics.registerFont(UnicodeCIDFont('STSong-Light'))
        pdfmetrics.registerFontFamily('Chinese', normal='STSong-Light', bold='STSong-Light')
        _CHINESE_FONT_REGISTERED = True
    except Exception:
        pass

_register_chinese_font()

def _get_pdf_font_name():
    try:
        pdfmetrics.getFont('Chinese')
        return 'Chinese'
    except Exception:
        pass
    try:
        pdfmetrics.getFont('STSong-Light')
        return 'STSong-Light'
    except Exception:
        return 'Helvetica'

class PDFReportGenerator:
    def __init__(self):
        self.font_name = _get_pdf_font_name()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            fontSize=20,
            alignment=1,
            fontName=self.font_name,
            spaceAfter=20
        )
        
        self.heading1_style = ParagraphStyle(
            'CustomHeading1',
            fontSize=16,
            fontName=self.font_name,
            spaceBefore=15,
            spaceAfter=10,
            textColor=colors.darkblue
        )
        
        self.heading2_style = ParagraphStyle(
            'CustomHeading2',
            fontSize=14,
            fontName=self.font_name,
            spaceBefore=10,
            spaceAfter=5,
            textColor=colors.blue
        )
        
        self.normal_style = ParagraphStyle(
            'CustomNormal',
            fontSize=11,
            fontName=self.font_name,
            leading=18
        )
        
        self.small_style = ParagraphStyle(
            'CustomSmall',
            fontSize=10,
            fontName=self.font_name,
            leading=16
        )
        
        self.table_cell_style = ParagraphStyle(
            'CustomTableCell',
            fontSize=9,
            fontName=self.font_name,
            leading=14,
            wordWrap='CJK'
        )
        
        self.table_header_style = ParagraphStyle(
            'CustomTableHeader',
            fontSize=9,
            fontName=self.font_name,
            leading=14,
            alignment=1
        )
        
        self.high_risk_style = ParagraphStyle(
            'CustomHighRisk',
            fontSize=11,
            fontName=self.font_name,
            textColor=colors.red
        )
        
        self.medium_risk_style = ParagraphStyle(
            'CustomMediumRisk',
            fontSize=11,
            fontName=self.font_name,
            textColor=colors.orange
        )
        
        self.low_risk_style = ParagraphStyle(
            'CustomLowRisk',
            fontSize=11,
            fontName=self.font_name,
            textColor=colors.yellow
        )

    def _safe_text(self, value, max_len=240):
        text = '' if value is None else str(value)
        text = text.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
        text = ' '.join(text.split())
        if len(text) > max_len:
            return text[:max_len] + '...'
        return text
    
    def generate_report(self, audit_data, output_path=None):
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            employee_name = sanitize_filename(audit_data["employee_name"])
            report_name = f'离职安全审计报告_{employee_name}_{timestamp}.pdf'
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'reports')
            employee_dir = os.path.join(reports_dir, employee_name)
            os.makedirs(employee_dir, exist_ok=True)
            output_path = os.path.join(employee_dir, report_name)
        
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        elements = []
        
        elements.append(Paragraph('离职场景电子数据取证分析报告', self.title_style))
        elements.append(Spacer(1, 12))
        
        self._add_report_info(elements, audit_data)
        self._add_evidence_type_summary(elements, audit_data)
        self._add_risk_summary(elements, audit_data)
        self._add_evidence_chains(elements, audit_data)
        self._add_findings(elements, audit_data)
        self._add_timeline(elements, audit_data)
        self._add_evidence_list(elements, audit_data)
        self._add_appendix(elements)
        
        doc.build(elements)
        return output_path
    
    def _add_report_info(self, elements, audit_data):
        elements.append(Paragraph('一、报告信息', self.heading1_style))
        
        info_data = [
            [Paragraph('审计项目', self.table_header_style), Paragraph('面向离职风险的电子数据取证辅助系统', self.table_cell_style)],
            [Paragraph('审计日期', self.table_header_style), Paragraph(datetime.now().strftime('%Y年%m月%d日 %H:%M:%S'), self.table_cell_style)],
            [Paragraph('员工姓名', self.table_header_style), Paragraph(audit_data.get('employee_name', '未指定'), self.table_cell_style)],
            [Paragraph('审计范围', self.table_header_style), Paragraph(audit_data.get('audit_range', '未指定'), self.table_cell_style)],
            [Paragraph('审计时间', self.table_header_style), Paragraph(audit_data.get('audit_time_range', '未指定'), self.table_cell_style)],
            [Paragraph('风险等级', self.table_header_style), Paragraph(audit_data.get('risk_level', {}).get('level', '未评估'), self.table_cell_style)]
        ]

        data_sources = audit_data.get('data_sources', {})
        for source_name, source_value in data_sources.items():
            info_data.append([
                Paragraph(source_name, self.table_header_style),
                Paragraph(str(source_value), self.table_cell_style)
            ])
        
        table = Table(info_data, colWidths=[100, 400])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.darkblue),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, -1), self.font_name),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        
        elements.append(table)
        elements.append(Spacer(1, 12))

    def _add_evidence_type_summary(self, elements, audit_data):
        elements.append(Paragraph('二、证据类型说明', self.heading1_style))

        evidence_types = audit_data.get('evidence_type_summary', [])
        if not evidence_types:
            elements.append(Paragraph('暂无证据类型统计', self.normal_style))
            elements.append(Spacer(1, 12))
            return

        data = [['证据类型', '证明含义', '数量', '证据强度']]
        for item in evidence_types:
            data.append([
                Paragraph(self._safe_text(item.get('type', ''), 60), self.table_cell_style),
                Paragraph(self._safe_text(item.get('meaning', ''), 260), self.table_cell_style),
                Paragraph(str(item.get('count', 0)), self.table_cell_style),
                Paragraph(self._safe_text(item.get('strength', ''), 60), self.table_cell_style)
            ])

        table = Table(data, colWidths=[105, 265, 45, 85], repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, -1), self.font_name),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey)
        ]))

        elements.append(table)
        elements.append(Spacer(1, 12))
    
    def _add_risk_summary(self, elements, audit_data):
        elements.append(Paragraph('三、风险评估结果', self.heading1_style))
        
        risk_level = audit_data.get('risk_level', {})
        score = risk_level.get('score', 0)
        level = risk_level.get('level', '无风险')
        color = risk_level.get('color', '#00FF00')
        
        elements.append(Paragraph(f'风险评分：{score} 分', self.normal_style))
        elements.append(Paragraph(f'风险等级：<font color="{color}"><b>{level}</b></font>', self.normal_style))
        
        elements.append(Spacer(1, 10))
        
        findings = audit_data.get('findings', [])
        if findings:
            elements.append(Paragraph('风险发现列表：', self.heading2_style))
            
            for idx, finding in enumerate(findings, 1):
                severity_color = self._get_severity_color(finding.get('severity', 'medium'))
                elements.append(Paragraph(
                    f'{idx}. <b>{finding.get("rule_name", "")}</b> '
                    f'(规则ID: {finding.get("rule_id", "")}, 评分: {finding.get("score", 0)}分)',
                    ParagraphStyle(f'FindingRow_{idx}', textColor=severity_color, fontSize=11, fontName=self.font_name)
                ))
                elements.append(Paragraph(f'   描述：{finding.get("description", "")}', self.small_style))
                elements.append(Spacer(1, 5))
        
        elements.append(Spacer(1, 12))
    
    def _add_evidence_chains(self, elements, audit_data):
        elements.append(Paragraph('四、证据链分析', self.heading1_style))

        chains = audit_data.get('evidence_chains', [])
        if not chains:
            elements.append(Paragraph('暂无证据链分析结果', self.normal_style))
            elements.append(Spacer(1, 12))
            return

        for chain in chains:
            elements.append(Paragraph(
                f"{chain.get('title', '证据链')}：完整度 {chain.get('completeness', 0)}%，置信度 {chain.get('confidence', 0)}%",
                self.heading2_style
            ))
            elements.append(Paragraph(self._safe_text(chain.get('summary', ''), 400), self.normal_style))

            data = [['环节', '证据标题', '证据来源', '证据强度', '说明']]
            for event in chain.get('events', []):
                data.append([
                    Paragraph(self._safe_text(event.get('stage_label', ''), 40), self.table_cell_style),
                    Paragraph(self._safe_text(event.get('title', ''), 80), self.table_cell_style),
                    Paragraph(self._safe_text(event.get('source', ''), 50), self.table_cell_style),
                    Paragraph(self._safe_text(event.get('strength', ''), 50), self.table_cell_style),
                    Paragraph(self._safe_text(event.get('description', ''), 180), self.table_cell_style)
                ])

            table = Table(data, colWidths=[65, 110, 80, 70, 190], repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, -1), self.font_name),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 0.3, colors.grey)
            ]))
            elements.append(table)
            elements.append(Spacer(1, 10))

        elements.append(Spacer(1, 12))

    def _add_findings(self, elements, audit_data):
        elements.append(Paragraph('五、详细审计发现', self.heading1_style))
        
        finding_types = {
            'sensitive_keyword': '敏感关键词',
            'cloud_storage': '云存储相关',
            'email': '邮箱相关',
            'email_address': '邮箱地址',
            'phone_number': '手机号码',
            'ip_address': 'IP地址'
        }
        
        content_findings = audit_data.get('content_findings', [])
        
        for finding_type, type_name in finding_types.items():
            type_findings = [f for f in content_findings if f.get('type') == finding_type]
            if type_findings:
                elements.append(Paragraph(f'{type_name}（共{len(type_findings)}条）', self.heading2_style))
                
                data = [['序号', '内容', '修改时间', '证据强度', '发现内容']]
                for idx, finding in enumerate(type_findings, 1):
                    modify_time_val = finding.get('modify_time', '')
                    modify_time_str = modify_time_val.strftime('%Y-%m-%d %H:%M') if hasattr(modify_time_val, 'strftime') else ''
                    display_name = finding.get('file_name', finding.get('file_path', ''))
                    # 如果是本地文件，还是显示绝对路径
                    if finding.get('file_path') and os.path.exists(finding.get('file_path')):
                        display_name = os.path.abspath(finding.get('file_path'))
                    
                    data.append([
                        Paragraph(str(idx), self.table_cell_style),
                        Paragraph(self._safe_text(display_name, 150), self.table_cell_style),
                        Paragraph(modify_time_str, self.table_cell_style),
                        Paragraph(self._safe_text(finding.get('evidence_strength', '推测线索'), 40), self.table_cell_style),
                        Paragraph(self._safe_text(finding.get('description', ''), 240), self.table_cell_style)
                    ])
                
                table = Table(data, colWidths=[35, 190, 105, 75, 145], repeatRows=1)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('FONTNAME', (0, 0), (-1, -1), self.font_name),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('GRID', (0, 0), (-1, -1), 0.3, colors.grey)
                ]))
                
                elements.append(table)
                elements.append(Spacer(1, 8))
        
        elements.append(Spacer(1, 12))
    
    def _add_timeline(self, elements, audit_data):
        elements.append(Paragraph('六、事件时间线', self.heading1_style))
        
        timeline = audit_data.get('timeline', [])
        if timeline:
            data = [['序号', '时间', '事件类型', '描述']]
            
            for idx, event in enumerate(timeline, 1):
                timestamp = event.get('timestamp')
                time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(timestamp, 'strftime') else ''
                
                event_type = event.get('event_type', '')
                description = ''
                
                if event_type == 'file':
                    description = event.get('file_name', '')
                elif event_type == 'content':
                    description = event.get('description', '')
                elif event_type == 'usb':
                    description = event.get('device_name', '') or 'USB设备操作'
                elif event_type == 'browser':
                    title = event.get('title', '')
                    url = event.get('url', '')
                    if title:
                        description = f"{title} - {url}"
                    else:
                        description = url
                elif event_type == 'chat':
                    sender = event.get('sender', '')
                    receiver = event.get('receiver', '')
                    content = event.get('content', '')
                    description = f"{sender} -> {receiver}: {content[:80]}"
                
                data.append([
                    Paragraph(str(idx), self.table_cell_style),
                    Paragraph(time_str, self.table_cell_style),
                    Paragraph(self._safe_text(event_type, 20), self.table_cell_style),
                    Paragraph(self._safe_text(description, 260), self.table_cell_style)
                ])
            
            table = Table(data, colWidths=[35, 130, 70, 270], repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, -1), self.font_name),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('GRID', (0, 0), (-1, -1), 0.3, colors.grey)
            ]))
            
            elements.append(table)
        else:
            elements.append(Paragraph('暂无事件记录', self.normal_style))
        
        elements.append(Spacer(1, 12))
    
    def _add_evidence_list(self, elements, audit_data):
        elements.append(Paragraph('七、证据清单', self.heading1_style))
        
        all_evidence = []
        
        file_scan_results = audit_data.get('file_scan_results', [])
        for file in file_scan_results:
            file_path = file.get('file_path', '')
            if file_path and os.path.exists(file_path):
                file_path = os.path.abspath(file_path)
            all_evidence.append({
                'type': '文件',
                'path': file_path,
                'size': file.get('file_size_human', ''),
                'modify_time': file.get('modify_time')
            })
        
        content_findings = audit_data.get('content_findings', [])
        for finding in content_findings:
            display_path = finding.get('file_name', finding.get('file_path', ''))
            # 如果是本地文件，还是显示绝对路径
            if finding.get('file_path') and os.path.exists(finding.get('file_path')):
                display_path = os.path.abspath(finding.get('file_path'))
            all_evidence.append({
                'type': f'内容发现({finding.get("type", "")})',
                'path': display_path,
                'size': '',
                'modify_time': finding.get('modify_time')
            })
        
        if all_evidence:
            data = [['序号', '类型', '路径', '大小', '修改时间']]
            for idx, evidence in enumerate(all_evidence, 1):
                modify_time = evidence.get('modify_time')
                time_str = modify_time.strftime('%Y-%m-%d %H:%M') if hasattr(modify_time, 'strftime') else ''
                
                data.append([
                    Paragraph(str(idx), self.table_cell_style),
                    Paragraph(self._safe_text(evidence.get('type', ''), 40), self.table_cell_style),
                    Paragraph(self._safe_text(evidence.get('path', ''), 260), self.table_cell_style),
                    Paragraph(self._safe_text(evidence.get('size', ''), 20), self.table_cell_style),
                    Paragraph(time_str, self.table_cell_style)
                ])
            
            table = Table(data, colWidths=[35, 80, 280, 60, 140], repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, -1), self.font_name),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('GRID', (0, 0), (-1, -1), 0.3, colors.grey)
            ]))
            
            elements.append(table)
        else:
            elements.append(Paragraph('暂无证据记录', self.normal_style))
        
        elements.append(Spacer(1, 12))
    
    def _add_appendix(self, elements):
        elements.append(Paragraph('八、附录', self.heading1_style))
        
        elements.append(Paragraph('1. 审计规则说明', self.heading2_style))
        rules = [
            ('R000', '敏感内容命中', '按关键词分级权重折算，区分高危资产、行为词、通道词和弱线索', 20),
            ('R001', '非工作时间密集文件操作', '审计时间范围内夜间文件操作较多', 30),
            ('R002', 'USB设备使用痕迹', '近期存在USB插拔或明确的疑似文件操作记录', 25),
            ('R003', '聊天记录泄露', '聊天样本中发现泄露相关表达，按意图证据加权', 60),
            ('R004', '访问网盘/邮箱', '浏览器记录中出现云存储或邮箱访问', 20),
            ('R005', '大量文件打包', '指定目录中发现压缩包或压缩包内含敏感文件名', 30),
            ('R006', '多源证据组合风险', '敏感文件、USB、压缩包、网盘/邮箱、聊天等多类证据组合出现', 25)
        ]
        
        data = [['规则ID', '规则名称', '触发条件', '风险评分']]
        for rule in rules:
            data.append([
                Paragraph(rule[0], self.table_cell_style),
                Paragraph(rule[1], self.table_cell_style),
                Paragraph(rule[2], self.table_cell_style),
                Paragraph(str(rule[3]), self.table_cell_style)
            ])
        
        table = Table(data, colWidths=[60, 150, 200, 80])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, -1), self.font_name),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey)
        ]))
        
        elements.append(table)
        
        elements.append(Spacer(1, 10))
        elements.append(Paragraph('2. 风险等级判定标准', self.heading2_style))
        elements.append(Paragraph('- 高风险：评分 >= 60', self.normal_style))
        elements.append(Paragraph('- 中风险：30 <= 评分 < 60', self.normal_style))
        elements.append(Paragraph('- 低风险：0 < 评分 < 30', self.normal_style))
        elements.append(Paragraph('- 无风险：评分 = 0', self.normal_style))
        
        elements.append(Spacer(1, 10))
        elements.append(Paragraph('3. 报告适用范围', self.heading2_style))
        elements.append(Paragraph('本报告基于用户指定的本地工作目录及可选聊天记录、USB使用记录、浏览器记录等样本生成，用于课堂实训和授权取证场景下的辅助分析，不等同于企业级远程全量自动取证平台。', self.normal_style))
        
        elements.append(Spacer(1, 10))
        elements.append(Paragraph('报告生成时间：' + datetime.now().strftime('%Y年%m月%d日 %H:%M:%S'), self.small_style))
    
    def _get_severity_color(self, severity):
        severity_colors = {
            'critical': colors.red,
            'high': colors.red,
            'medium': colors.orange,
            'low': colors.yellow
        }
        return severity_colors.get(severity, colors.black)
