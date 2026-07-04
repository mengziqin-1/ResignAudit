import os
import uuid
from datetime import datetime
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

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

_register_chinese_font()

class PDFReportGenerator:
    def __init__(self):
        self.title_style = ParagraphStyle(
            'CustomTitle',
            fontSize=20,
            alignment=1,
            fontName='Chinese',
            spaceAfter=20
        )
        
        self.heading1_style = ParagraphStyle(
            'CustomHeading1',
            fontSize=16,
            fontName='Chinese',
            spaceBefore=15,
            spaceAfter=10,
            textColor=colors.darkblue
        )
        
        self.heading2_style = ParagraphStyle(
            'CustomHeading2',
            fontSize=14,
            fontName='Chinese',
            spaceBefore=10,
            spaceAfter=5,
            textColor=colors.blue
        )
        
        self.normal_style = ParagraphStyle(
            'CustomNormal',
            fontSize=11,
            fontName='Chinese',
            leading=18
        )
        
        self.small_style = ParagraphStyle(
            'CustomSmall',
            fontSize=10,
            fontName='Chinese',
            leading=16
        )
        
        self.high_risk_style = ParagraphStyle(
            'CustomHighRisk',
            fontSize=11,
            fontName='Chinese',
            textColor=colors.red
        )
        
        self.medium_risk_style = ParagraphStyle(
            'CustomMediumRisk',
            fontSize=11,
            fontName='Chinese',
            textColor=colors.orange
        )
        
        self.low_risk_style = ParagraphStyle(
            'CustomLowRisk',
            fontSize=11,
            fontName='Chinese',
            textColor=colors.yellow
        )
    
    def generate_report(self, audit_data, output_path=None):
        print('[PDF DEBUG] Starting PDF generation...')
        
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_name = f'离职安全审计报告_{audit_data["employee_name"]}_{timestamp}.pdf'
            output_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'reports', report_name)
        
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        elements = []
        
        elements.append(Paragraph('离职安全审计报告', self.title_style))
        elements.append(Spacer(1, 12))
        
        print('[PDF DEBUG] Adding report info...')
        self._add_report_info(elements, audit_data)
        
        print('[PDF DEBUG] Adding risk summary...')
        self._add_risk_summary(elements, audit_data)
        
        print('[PDF DEBUG] Adding findings...')
        self._add_findings(elements, audit_data)
        
        print('[PDF DEBUG] Adding timeline...')
        self._add_timeline(elements, audit_data)
        
        print('[PDF DEBUG] Adding evidence list...')
        self._add_evidence_list(elements, audit_data)
        
        print('[PDF DEBUG] Adding appendix...')
        self._add_appendix(elements)
        
        print('[PDF DEBUG] Building document...')
        doc.build(elements)
        
        print(f'[PDF DEBUG] PDF generated successfully: {output_path}')
        return output_path
    
    def _add_report_info(self, elements, audit_data):
        elements.append(Paragraph('一、报告信息', self.heading1_style))
        
        info_data = [
            ['审计项目', '离职安全审计系统'],
            ['审计日期', datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')],
            ['员工姓名', audit_data.get('employee_name', '未指定')],
            ['审计范围', audit_data.get('audit_range', '未指定')],
            ['审计时间', audit_data.get('audit_time_range', '未指定')],
            ['风险等级', audit_data.get('risk_level', {}).get('level', '未评估')]
        ]
        
        table = Table(info_data, colWidths=[100, 400])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.darkblue),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, -1), 'Chinese'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        
        elements.append(table)
        elements.append(Spacer(1, 12))
    
    def _add_risk_summary(self, elements, audit_data):
        elements.append(Paragraph('二、风险评估结果', self.heading1_style))
        
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
                    ParagraphStyle(f'FindingRow_{idx}', textColor=severity_color, fontSize=11, fontName='Chinese')
                ))
                elements.append(Paragraph(f'   描述：{finding.get("description", "")}', self.small_style))
                elements.append(Spacer(1, 5))
        
        elements.append(Spacer(1, 12))
    
    def _add_findings(self, elements, audit_data):
        elements.append(Paragraph('三、详细审计发现', self.heading1_style))
        
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
                
                data = [['序号', '文件名', '修改时间', '发现内容']]
                for idx, finding in enumerate(type_findings[:20], 1):
                    data.append([
                        str(idx),
                        finding.get('file_name', ''),
                        finding.get('modify_time', '').strftime('%Y-%m-%d %H:%M') if hasattr(finding.get('modify_time'), 'strftime') else '',
                        finding.get('description', '')[:50] + '...' if len(finding.get('description', '')) > 50 else finding.get('description', '')
                    ])
                
                table = Table(data, colWidths=[40, 150, 120, 200])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Chinese'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('GRID', (0, 0), (-1, -1), 0.3, colors.grey)
                ]))
                
                elements.append(table)
                if len(type_findings) > 20:
                    elements.append(Paragraph(f'... 还有 {len(type_findings) - 20} 条记录未显示', self.small_style))
                elements.append(Spacer(1, 8))
        
        elements.append(Spacer(1, 12))
    
    def _add_timeline(self, elements, audit_data):
        elements.append(Paragraph('四、事件时间线', self.heading1_style))
        
        timeline = audit_data.get('timeline', [])
        if timeline:
            data = [['时间', '事件类型', '描述']]
            
            for event in timeline[:50]:
                timestamp = event.get('timestamp')
                time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(timestamp, 'strftime') else ''
                
                event_type = event.get('event_type', '')
                description = ''
                
                if event_type == 'file':
                    description = event.get('file_name', '')
                elif event_type == 'content':
                    description = event.get('description', '')[:30]
                elif event_type == 'usb':
                    description = event.get('device_name', '') or 'USB设备操作'
                elif event_type == 'browser':
                    description = event.get('url', '')[:30]
                
                data.append([time_str, event_type, description])
            
            table = Table(data, colWidths=[130, 80, 300])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, -1), 'Chinese'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('GRID', (0, 0), (-1, -1), 0.3, colors.grey)
            ]))
            
            elements.append(table)
            if len(timeline) > 50:
                elements.append(Paragraph(f'... 还有 {len(timeline) - 50} 条事件未显示', self.small_style))
        else:
            elements.append(Paragraph('暂无事件记录', self.normal_style))
        
        elements.append(Spacer(1, 12))
    
    def _add_evidence_list(self, elements, audit_data):
        elements.append(Paragraph('五、证据清单', self.heading1_style))
        
        all_evidence = []
        
        file_scan_results = audit_data.get('file_scan_results', [])
        for file in file_scan_results:
            all_evidence.append({
                'type': '文件',
                'path': file.get('file_path', ''),
                'size': file.get('file_size_human', ''),
                'modify_time': file.get('modify_time')
            })
        
        content_findings = audit_data.get('content_findings', [])
        for finding in content_findings:
            all_evidence.append({
                'type': f'内容发现({finding.get("type", "")})',
                'path': finding.get('file_path', ''),
                'size': '',
                'modify_time': finding.get('modify_time')
            })
        
        if all_evidence:
            data = [['序号', '类型', '路径', '大小', '修改时间']]
            for idx, evidence in enumerate(all_evidence[:30], 1):
                modify_time = evidence.get('modify_time')
                time_str = modify_time.strftime('%Y-%m-%d %H:%M') if hasattr(modify_time, 'strftime') else ''
                
                data.append([
                    str(idx),
                    evidence.get('type', ''),
                    evidence.get('path', '')[:80] + '...' if len(evidence.get('path', '')) > 80 else evidence.get('path', ''),
                    evidence.get('size', ''),
                    time_str
                ])
            
            table = Table(data, colWidths=[40, 80, 300, 60, 130])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, -1), 'Chinese'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('GRID', (0, 0), (-1, -1), 0.3, colors.grey)
            ]))
            
            elements.append(table)
            if len(all_evidence) > 30:
                elements.append(Paragraph(f'... 还有 {len(all_evidence) - 30} 条证据未显示', self.small_style))
        else:
            elements.append(Paragraph('暂无证据记录', self.normal_style))
        
        elements.append(Spacer(1, 12))
    
    def _add_appendix(self, elements):
        elements.append(Paragraph('六、附录', self.heading1_style))
        
        elements.append(Paragraph('1. 审计规则说明', self.heading2_style))
        rules = [
            ('R001', '非工作时间密集文件操作', '夜间（0-6点）文件操作超过200次', 30),
            ('R002', 'U盘异常使用', '30天内U盘插入超过5次且文件拷贝超过100次', 25),
            ('R003', '聊天记录泄露', '发现3个以上泄露相关关键词', 40),
            ('R004', '访问网盘/邮箱', '访问云存储或个人邮箱超过10次', 20),
            ('R005', '大量文件打包', '创建超过5个大型压缩包', 15)
        ]
        
        data = [['规则ID', '规则名称', '触发条件', '风险评分']]
        data.extend(rules)
        
        table = Table(data, colWidths=[60, 150, 200, 80])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, -1), 'Chinese'),
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
        elements.append(Paragraph('报告生成时间：' + datetime.now().strftime('%Y年%m月%d日 %H:%M:%S'), self.small_style))
    
    def _get_severity_color(self, severity):
        severity_colors = {
            'critical': colors.red,
            'high': colors.red,
            'medium': colors.orange,
            'low': colors.yellow
        }
        return severity_colors.get(severity, colors.black)