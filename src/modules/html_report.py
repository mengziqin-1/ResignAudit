import os
import json
from datetime import datetime

class HTMLReportGenerator:
    def __init__(self):
        self.template_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'templates',
            'report.html'
        )
    
    def generate_report(self, audit_data, output_path=None):
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            employee_name = audit_data["employee_name"]
            report_name = f'离职安全审计报告_{employee_name}_{timestamp}.html'
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'reports')
            employee_dir = os.path.join(reports_dir, employee_name)
            os.makedirs(employee_dir, exist_ok=True)
            output_path = os.path.join(employee_dir, report_name)
        
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        with open(self.template_path, 'r', encoding='utf-8') as f:
            template = f.read()
        
        serialized_data = self._serialize_audit_data(audit_data)
        report_html = template.replace('{{REPORT_DATA_JSON}}', serialized_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        return output_path
    
    def _serialize_audit_data(self, audit_data):
        data = {}
        
        for key, value in audit_data.items():
            if key == 'timeline':
                data[key] = self._serialize_timeline(value)
            elif key == 'content_findings':
                data[key] = self._serialize_content_findings(value)
            elif key == 'file_scan_results':
                data[key] = self._serialize_file_scan_results(value)
            elif key == 'risk_level':
                data[key] = value
            elif key == 'findings':
                data[key] = value
            elif key == 'data_sources':
                data[key] = {str(k): str(v) for k, v in value.items()}
            elif isinstance(value, (str, int, float, bool)):
                data[key] = value
            else:
                try:
                    data[key] = str(value)
                except Exception:
                    data[key] = ''
        
        return json.dumps(data, ensure_ascii=False, indent=2)
    
    def _serialize_timeline(self, timeline):
        result = []
        for event in timeline:
            serialized = {}
            for key, value in event.items():
                if isinstance(value, datetime):
                    serialized[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                elif isinstance(value, (str, int, float, bool)):
                    serialized[key] = value
                else:
                    try:
                        serialized[key] = str(value)
                    except Exception:
                        serialized[key] = ''
            result.append(serialized)
        return result
    
    def _serialize_content_findings(self, findings):
        result = []
        for finding in findings:
            serialized = {}
            for key, value in finding.items():
                if isinstance(value, datetime):
                    serialized[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                elif isinstance(value, (str, int, float, bool)):
                    serialized[key] = value
                else:
                    try:
                        serialized[key] = str(value)
                    except Exception:
                        serialized[key] = ''
            result.append(serialized)
        return result
    
    def _serialize_file_scan_results(self, results):
        result = []
        for file in results:
            serialized = {}
            for key, value in file.items():
                if isinstance(value, datetime):
                    serialized[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                elif isinstance(value, (str, int, float, bool)):
                    serialized[key] = value
                else:
                    try:
                        serialized[key] = str(value)
                    except Exception:
                        serialized[key] = ''
            result.append(serialized)
        return result