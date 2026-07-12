import os
import sys
import time
import threading
import secrets
import uuid
import subprocess
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from modules.audit_orchestrator import AuditOrchestrator

app = Flask(__name__)
LOCAL_ACCESS_TOKEN = os.environ.get('RESIGNAUDIT_TOKEN') or secrets.token_urlsafe(24)

audit_tasks = {}

def _is_authorized_request():
    token = request.headers.get('X-Local-Token') or request.args.get('token')
    return token == LOCAL_ACCESS_TOKEN

def _require_local_token():
    if not _is_authorized_request():
        return jsonify({'error': '本地访问令牌无效，请从系统首页重新打开'}), 403
    return None

def _collect_allowed_evidence_paths(result):
    allowed = set()

    for file_info in result.get('file_scan_results', []):
        path = file_info.get('file_path')
        if path:
            allowed.add(os.path.abspath(path))

    for finding in result.get('content_findings', []):
        path = finding.get('file_path')
        if path and not path.startswith(('http://', 'https://')):
            allowed.add(os.path.abspath(path))

    return allowed

def _json_safe(value):
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    return value

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
    return render_template('index.html', local_access_token=LOCAL_ACCESS_TOKEN)

@app.route('/api/start-audit', methods=['POST'])
def start_audit():
    auth_error = _require_local_token()
    if auth_error:
        return auth_error

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

    task_id = f'task_{int(time.time())}_{uuid.uuid4().hex[:8]}'
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
    auth_error = _require_local_token()
    if auth_error:
        return auth_error

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
            'evidence_type_summary': result.get('evidence_type_summary', []),
            'evidence_events': _json_safe(result.get('evidence_events', [])),
            'evidence_chains': _json_safe(result.get('evidence_chains', [])),
            'scoring_breakdown': _json_safe(result.get('scoring_breakdown', [])),
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
    auth_error = _require_local_token()
    if auth_error:
        return auth_error

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

@app.route('/api/reveal-path/<task_id>', methods=['POST'])
def reveal_path(task_id):
    auth_error = _require_local_token()
    if auth_error:
        return auth_error

    if task_id not in audit_tasks:
        return jsonify({'error': '任务不存在'}), 404

    task = audit_tasks[task_id]
    if task['status'] != 'completed':
        return jsonify({'error': '审计尚未完成，不能定位证据路径'}), 400

    data = request.get_json() or {}
    requested_path = data.get('file_path', '')
    if not requested_path or requested_path.startswith(('http://', 'https://')):
        return jsonify({'error': '不是可定位的本地文件路径'}), 400

    abs_path = os.path.abspath(requested_path)
    allowed_paths = _collect_allowed_evidence_paths(task['result'])
    if abs_path not in allowed_paths:
        return jsonify({'error': '该路径不属于当前审计任务的证据清单'}), 403

    if not os.path.exists(abs_path):
        return jsonify({'error': '文件不存在或已被移动'}), 404

    try:
        if os.path.isdir(abs_path):
            subprocess.Popen(['explorer', abs_path])
        else:
            subprocess.Popen(['explorer', '/select,', abs_path])
    except Exception as exc:
        return jsonify({'error': f'无法打开所在文件夹: {exc}'}), 500

    return jsonify({'ok': True})

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
