import os
import sys
import json
import time
import threading
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from modules.file_scanner import FileScanner
from modules.content_analyzer import ContentAnalyzer
from modules.usb_auditor import USBAuditor
from modules.browser_analyzer import BrowserAnalyzer
from modules.chat_auditor import ChatAuditor
from modules.timeline_aggregator import TimelineAggregator
from modules.rule_engine import RuleEngine
from modules.pdf_report import PDFReportGenerator

app = Flask(__name__)
CORS(app)

audit_tasks = {}

def run_audit(task_id, employee_name, directory_path, start_date, end_date):
    try:
        audit_tasks[task_id]['status'] = 'running'
        audit_tasks[task_id]['progress'] = 5
        audit_tasks[task_id]['message'] = '初始化审计模块...'
        
        file_scanner = FileScanner()
        content_analyzer = ContentAnalyzer()
        usb_auditor = USBAuditor()
        browser_analyzer = BrowserAnalyzer()
        chat_auditor = ChatAuditor()
        timeline_aggregator = TimelineAggregator()
        rule_engine = RuleEngine()
        
        audit_tasks[task_id]['progress'] = 10
        audit_tasks[task_id]['message'] = '① 文件扫描：扫描指定目录下所有文件...'
        time.sleep(1)
        
        file_results = file_scanner.scan_directory(directory_path, start_date, end_date)
        
        audit_tasks[task_id]['progress'] = 25
        audit_tasks[task_id]['message'] = '② 内容分析：提取文档文本并匹配敏感关键词...'
        time.sleep(1)
        
        content_findings = content_analyzer.analyze_files(file_results)
        
        audit_tasks[task_id]['progress'] = 40
        audit_tasks[task_id]['message'] = '③ 聊天记录审计：解析微信/QQ/Skype聊天数据库...'
        time.sleep(1)
        
        chat_records = chat_auditor.audit_chat_records()
        
        audit_tasks[task_id]['progress'] = 55
        audit_tasks[task_id]['message'] = '④ USB设备审计：读取注册表提取U盘插拔记录...'
        time.sleep(1)
        
        usb_devices, usb_operations = usb_auditor.audit_usb_devices()
        
        audit_tasks[task_id]['progress'] = 70
        audit_tasks[task_id]['message'] = '⑤ 浏览器行为分析：提取历史记录匹配外传渠道...'
        time.sleep(1)
        
        browser_history, cloud_visits, email_visits = browser_analyzer.analyze_browsers()
        
        audit_tasks[task_id]['progress'] = 85
        audit_tasks[task_id]['message'] = '⑥ 时间线聚合：将所有事件按时间排序...'
        time.sleep(1)
        
        timeline_aggregator.add_events(file_results, 'file')
        timeline_aggregator.add_events(content_findings, 'content')
        timeline_aggregator.add_events(usb_devices, 'usb')
        timeline_aggregator.add_events(browser_history, 'browser')
        timeline_aggregator.add_events(chat_records, 'chat')
        timeline = timeline_aggregator.build_timeline()
        
        audit_tasks[task_id]['progress'] = 90
        audit_tasks[task_id]['message'] = '规则引擎汇总分析：计算风险评分...'
        time.sleep(1)
        
        scan_results = {
            'night_time_file_operations': file_scanner.get_night_time_operations(),
            'usb_insertions_last_30_days': usb_auditor.get_usb_insertions_count(30),
            'usb_file_copies': len(usb_operations),
            'chat_leak_keywords_found': chat_auditor.get_leak_keywords_count(),
            'browser_cloud_visits': browser_analyzer.get_cloud_visits_count(30),
            'large_archives_created': len(file_scanner.get_large_archives())
        }
        
        risk_assessment = rule_engine.assess_risk(employee_name, scan_results)
        
        audit_tasks[task_id]['progress'] = 95
        audit_tasks[task_id]['message'] = '生成PDF报告...'
        time.sleep(1)
        
        browser_findings = browser_analyzer.get_findings()
        all_findings = content_findings + browser_findings
        
        report_data = {
            'employee_name': employee_name,
            'audit_range': directory_path,
            'audit_time_range': f"{start_date.strftime('%Y-%m-%d')} 至 {end_date.strftime('%Y-%m-%d')}",
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
        
        audit_tasks[task_id]['progress'] = 100
        audit_tasks[task_id]['message'] = '审计完成！'
        audit_tasks[task_id]['status'] = 'completed'
        audit_tasks[task_id]['result'] = report_data
        
    except Exception as e:
        audit_tasks[task_id]['status'] = 'failed'
        audit_tasks[task_id]['message'] = f'审计失败: {str(e)}'
        audit_tasks[task_id]['error'] = str(e)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/start-audit', methods=['POST'])
def start_audit():
    data = request.get_json()
    
    employee_name = data.get('employee_name', '')
    directory_path = data.get('directory_path', '')
    start_date_str = data.get('start_date', '')
    end_date_str = data.get('end_date', '')
    
    if not employee_name or not directory_path:
        return jsonify({'error': '请填写员工姓名和目录路径'}), 400
    
    if not os.path.exists(directory_path):
        return jsonify({'error': '指定的目录不存在'}), 400
    
    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None
    except:
        return jsonify({'error': '日期格式错误'}), 400
    
    task_id = f'task_{int(time.time())}'
    audit_tasks[task_id] = {
        'status': 'pending',
        'progress': 0,
        'message': '等待开始',
        'employee_name': employee_name,
        'directory_path': directory_path
    }
    
    thread = threading.Thread(target=run_audit, args=(task_id, employee_name, directory_path, start_date, end_date))
    thread.start()
    
    return jsonify({'task_id': task_id})

@app.route('/api/audit-status/<task_id>', methods=['GET'])
def audit_status(task_id):
    if task_id not in audit_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    task = audit_tasks[task_id]
    response = {
        'task_id': task_id,
        'status': task['status'],
        'progress': task['progress'],
        'message': task['message']
    }
    
    if 'result' in task:
        result = task['result']
        response['result'] = {
            'employee_name': result['employee_name'],
            'risk_level': result['risk_level'],
            'findings': result['findings'],
            'file_summary': result['file_summary'],
            'chat_summary': result['chat_summary'],
            'browser_summary': result['browser_summary'],
            'usb_summary': result['usb_summary'],
            'scan_results': result['scan_results'],
            'report_path': os.path.basename(result['report_path'])
        }
        response['result']['content_findings'] = []
        for f in result.get('content_findings', []):
            f_copy = f.copy()
            if 'modify_time' in f_copy and hasattr(f_copy['modify_time'], 'strftime'):
                f_copy['modify_time'] = f_copy['modify_time'].strftime('%Y-%m-%d %H:%M:%S')
            response['result']['content_findings'].append(f_copy)
        response['result']['timeline'] = []
        for event in result.get('timeline', []):
            e_copy = event.copy()
            if 'timestamp' in e_copy and hasattr(e_copy['timestamp'], 'strftime'):
                e_copy['timestamp'] = e_copy['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            response['result']['timeline'].append(e_copy)
    
    if 'error' in task:
        response['error'] = task['error']
    
    return jsonify(response)

@app.route('/api/download-report/<task_id>', methods=['GET'])
def download_report(task_id):
    if task_id not in audit_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    task = audit_tasks[task_id]
    if task['status'] != 'completed':
        return jsonify({'error': '报告尚未生成'}), 400
    
    result = task['result']
    report_path = result['report_path']
    
    if not os.path.exists(report_path):
        return jsonify({'error': '报告文件不存在'}), 404
    
    return send_file(report_path, as_attachment=True)

@app.route('/api/open-file', methods=['POST'])
def open_file():
    data = request.get_json()
    file_path = data.get('file_path', '')
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': '文件不存在'}), 400
    
    try:
        os.startfile(file_path)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)