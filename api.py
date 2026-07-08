import os
import sys
import time
import threading
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from modules.audit_orchestrator import AuditOrchestrator

app = Flask(__name__)
CORS(app)

audit_tasks = {}

def run_audit(task_id, employee_name, directory_path, start_date, end_date, chat_db_path=''):
    """线程目标函数：调用 AuditOrchestrator 执行审计，实时更新任务状态。"""
    def progress_callback(progress, message):
        if progress == -1:
            audit_tasks[task_id]['status'] = 'failed'
            audit_tasks[task_id]['message'] = message
            audit_tasks[task_id]['error'] = message
        else:
            audit_tasks[task_id]['progress'] = progress
            audit_tasks[task_id]['message'] = message

    try:
        audit_tasks[task_id]['status'] = 'running'
        audit_tasks[task_id]['progress'] = 0
        audit_tasks[task_id]['message'] = '任务已启动'

        orchestrator = AuditOrchestrator(
            employee_name,
            directory_path,
            start_date,
            end_date,
            chat_db_path
        )

        report_data = orchestrator.run(progress_callback=progress_callback)

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
    chat_db_path = data.get('chat_db_path', '')
    start_date_str = data.get('start_date', '')
    end_date_str = data.get('end_date', '')

    if not employee_name or not directory_path:
        return jsonify({'error': '请填写员工姓名和目录路径'}), 400

    if not os.path.exists(directory_path):
        return jsonify({'error': '指定的目录不存在'}), 400

    if chat_db_path and not os.path.exists(chat_db_path):
        return jsonify({'error': '指定的聊天记录样本不存在'}), 400

    if start_date_str and end_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
            if start_date > end_date:
                return jsonify({'error': '开始日期不能大于结束日期'}), 400
        except:
            return jsonify({'error': '日期格式错误'}), 400
    else:
        start_date = None
        end_date = None

    task_id = f'task_{int(time.time())}'
    audit_tasks[task_id] = {
        'status': 'pending',
        'progress': 0,
        'message': '等待开始',
        'employee_name': employee_name,
        'directory_path': directory_path
    }

    thread = threading.Thread(target=run_audit, args=(task_id, employee_name, directory_path, start_date, end_date, chat_db_path))
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
            'report_path': os.path.basename(result['report_path'])
        }
        
        scan_results_copy = result['scan_results'].copy()
        if 'archive_inspection' in scan_results_copy:
            archive_inspection_copy = []
            for archive in scan_results_copy['archive_inspection']:
                a_copy = archive.copy()
                if 'modify_time' in a_copy and hasattr(a_copy['modify_time'], 'strftime'):
                    a_copy['modify_time'] = a_copy['modify_time'].strftime('%Y-%m-%d %H:%M:%S')
                archive_inspection_copy.append(a_copy)
            scan_results_copy['archive_inspection'] = archive_inspection_copy
        response['result']['scan_results'] = scan_results_copy
        
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

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
