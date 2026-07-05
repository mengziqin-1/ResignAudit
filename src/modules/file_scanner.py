import os
import stat
import time
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

class FileScanner:
    def __init__(self):
        self.scan_results = []
        self.total_files = 0
        self.scan_start_time = None
        self.MAX_FILE_SIZE = 50 * 1024 * 1024
        self.EXCLUDED_DIR_NAMES = {
            '.git', '__pycache__', 'venv', '.venv', 'env', 'node_modules',
            'reports', 'dist', 'build', '.idea', '.vscode'
        }
        self.EXCLUDED_FILE_KEYWORDS = [
            '离职安全审计报告', '审计报告', 'audit_report', 'report_'
        ]
        
    def scan_directory(self, directory, audit_start_date, audit_end_date, progress_callback=None):
        self.scan_results = []
        self.total_files = 0
        self.scan_start_time = datetime.now()
        
        if not os.path.exists(directory):
            raise ValueError(f"目录不存在: {directory}")
        
        if not os.path.isdir(directory):
            raise ValueError(f"不是有效的目录: {directory}")
        
        file_count = 0
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not self._should_skip_dir(d)]
            for filename in files:
                if self._should_skip_file(filename):
                    continue
                file_path = os.path.join(root, filename)
                try:
                    file_info = self._get_file_info(file_path, audit_start_date, audit_end_date)
                    if file_info:
                        self.scan_results.append(file_info)
                        self.total_files += 1
                    file_count += 1
                    if progress_callback and file_count % 100 == 0:
                        progress_callback(f"扫描文件: {file_count}")
                except (PermissionError, OSError):
                    continue
        
        return self.scan_results

    def _should_skip_dir(self, dirname):
        return dirname.lower() in self.EXCLUDED_DIR_NAMES

    def _should_skip_file(self, filename):
        lower_name = filename.lower()
        if lower_name.endswith(('.tmp', '.log', '.pyc')):
            return True
        return any(keyword.lower() in lower_name for keyword in self.EXCLUDED_FILE_KEYWORDS)
    
    def _get_file_info(self, file_path, audit_start_date, audit_end_date):
        try:
            file_stat = os.stat(file_path)
        except (PermissionError, OSError):
            return None
        
        file_size = file_stat.st_size
        
        if file_size > self.MAX_FILE_SIZE:
            return None
        
        create_time = datetime.fromtimestamp(file_stat.st_ctime)
        modify_time = datetime.fromtimestamp(file_stat.st_mtime)
        access_time = datetime.fromtimestamp(file_stat.st_atime)
        
        if audit_start_date and modify_time.date() < audit_start_date:
            return None
        if audit_end_date and modify_time.date() > audit_end_date:
            return None
        
        file_ext = os.path.splitext(file_path)[1].lower()
        file_name = os.path.basename(file_path)
        
        file_hash = None
        if file_size < 10 * 1024 * 1024:
            try:
                file_hash = self._calculate_hash(file_path)
            except:
                file_hash = None
        
        is_hidden = False
        if os.name == 'nt' and hasattr(stat, 'FILE_ATTRIBUTE_HIDDEN') and hasattr(file_stat, 'st_file_attributes'):
            is_hidden = bool(file_stat.st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
        
        return {
            'file_path': file_path,
            'file_name': file_name,
            'file_ext': file_ext,
            'file_size': file_size,
            'file_size_human': self._format_size(file_size),
            'create_time': create_time,
            'modify_time': modify_time,
            'access_time': access_time,
            'file_hash': file_hash,
            'is_hidden': is_hidden,
            'file_type': self._classify_file_type(file_ext)
        }
    
    def _calculate_hash(self, file_path, hash_type='md5', chunk_size=8192):
        hash_obj = hashlib.new(hash_type)
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    
    def _format_size(self, size):
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.2f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.2f} GB"
    
    def _classify_file_type(self, ext):
        document_exts = ('.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                         '.pdf', '.csv', '.json', '.xml', '.html', '.htm', '.md',
                         '.rtf', '.odt', '.ods', '.odp', '.eml', '.msg')
        image_exts = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.ico')
        archive_exts = ('.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab', '.iso')
        code_exts = ('.py', '.java', '.cpp', '.c', '.h', '.js', '.ts', '.html', '.css',
                     '.php', '.sql', '.xml', '.json', '.yaml', '.yml')
        exe_exts = ('.exe', '.dll', '.sys', '.com', '.bat', '.cmd')
        
        if ext in document_exts:
            return 'document'
        elif ext in image_exts:
            return 'image'
        elif ext in archive_exts:
            return 'archive'
        elif ext in code_exts:
            return 'code'
        elif ext in exe_exts:
            return 'executable'
        else:
            return 'other'
    
    def get_night_time_operations(self, start_date=None, end_date=None):
        night_ops = 0
        for file in self.scan_results:
            modify_time = file['modify_time']
            if start_date and modify_time < start_date:
                continue
            if end_date and modify_time > end_date:
                continue
            if 0 <= modify_time.hour < 6:
                night_ops += 1
        return night_ops
    
    def get_large_archives(self, min_size_mb=50):
        large_archives = []
        min_size_bytes = min_size_mb * 1024 * 1024
        for file in self.scan_results:
            if file['file_type'] == 'archive' and file['file_size'] >= min_size_bytes:
                large_archives.append(file)
        return large_archives
    
    def get_recently_modified(self, days=7):
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_files = []
        for file in self.scan_results:
            if file['modify_time'] >= cutoff_date:
                recent_files.append(file)
        return recent_files
    
    def get_summary(self):
        file_types = {}
        total_size = 0
        for file in self.scan_results:
            file_type = file['file_type']
            file_types[file_type] = file_types.get(file_type, 0) + 1
            total_size += file['file_size']
        
        scan_time_str = self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S') if self.scan_start_time else None
        duration = datetime.now() - self.scan_start_time if self.scan_start_time else None
        duration_str = str(duration) if duration else None
        
        return {
            'total_files': self.total_files,
            'total_size': self._format_size(total_size),
            'file_types': file_types,
            'scan_time': scan_time_str,
            'scan_duration': duration_str
        }
