import os
import re
import sqlite3
import shutil
from datetime import datetime

class ChatAuditor:
    def __init__(self):
        self.chat_records = []
        self.leak_keywords = []
        self.load_keywords()
    
    def load_keywords(self):
        keywords_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'keywords')
        
        sensitive_file = os.path.join(keywords_dir, 'sensitive_keywords.txt')
        if os.path.exists(sensitive_file):
            with open(sensitive_file, 'r', encoding='utf-8') as f:
                self.leak_keywords = [line.strip().lower() for line in f if line.strip()]
    
    def audit_chat_records(self, progress_callback=None):
        self.chat_records = []
        
        chat_paths = {
            'wechat': [
                os.path.expanduser(r'~\Documents\WeChat Files'),
                os.path.expanduser(r'~\AppData\Roaming\Tencent\WeChat')
            ],
            'qq': [
                os.path.expanduser(r'~\Documents\Tencent Files'),
                os.path.expanduser(r'~\AppData\Roaming\Tencent\QQ')
            ],
            'skype': [
                os.path.expanduser(r'~\AppData\Roaming\Skype')
            ]
        }
        
        for chat_type, paths in chat_paths.items():
            for path in paths:
                if os.path.exists(path):
                    try:
                        records = self._scan_chat_directory(path, chat_type)
                        self.chat_records.extend(records)
                    except Exception:
                        continue
        
        if progress_callback:
            progress_callback(f"聊天记录审计完成，共发现 {len(self.chat_records)} 条记录")
        
        return self.chat_records
    
    def _scan_chat_directory(self, directory, chat_type):
        records = []
        
        for root, dirs, files in os.walk(directory):
            for filename in files:
                if filename.endswith('.db') or filename.endswith('.sqlite'):
                    db_path = os.path.join(root, filename)
                    try:
                        records.extend(self._parse_chat_database(db_path, chat_type))
                    except Exception:
                        continue
        
        return records
    
    def _parse_chat_database(self, db_path, chat_type):
        records = []
        
        temp_path = db_path + '.tmp'
        try:
            shutil.copy2(db_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            conn.text_factory = bytes
            cursor = conn.cursor()
            
            try:
                tables = []
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                for row in cursor.fetchall():
                    tables.append(row[0])
                
                for table in tables:
                    try:
                        cursor.execute(f"SELECT * FROM {table} LIMIT 100")
                        columns = [desc[0] for desc in cursor.description]
                        
                        for row in cursor.fetchall():
                            record = {
                                'chat_type': chat_type,
                                'table_name': table,
                                'timestamp': datetime.now()
                            }
                            
                            for i, col in enumerate(columns):
                                try:
                                    value = row[i]
                                    if isinstance(value, bytes):
                                        try:
                                            value = value.decode('utf-8')
                                        except:
                                            try:
                                                value = value.decode('gbk')
                                            except:
                                                value = str(value)
                                    record[col] = value
                                except:
                                    continue
                            
                            if 'content' in record or 'msg' in record or 'message' in record:
                                content = record.get('content', '') or record.get('msg', '') or record.get('message', '')
                                record['content'] = content
                                record['has_leak_keywords'] = self._check_leak_keywords(content)
                                if record['has_leak_keywords']:
                                    record['matched_keywords'] = self._find_matched_keywords(content)
                            
                            records.append(record)
                    except Exception:
                        continue
            finally:
                conn.close()
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
        
        return records
    
    def _check_leak_keywords(self, content):
        if not content:
            return False
        content_lower = content.lower()
        for keyword in self.leak_keywords:
            if keyword in content_lower:
                return True
        return False
    
    def _find_matched_keywords(self, content):
        if not content:
            return []
        content_lower = content.lower()
        matched = []
        for keyword in self.leak_keywords:
            if keyword in content_lower:
                matched.append(keyword)
        return matched
    
    def get_leak_keywords_count(self):
        count = 0
        for record in self.chat_records:
            if record.get('has_leak_keywords', False):
                count += len(record.get('matched_keywords', []))
        return count
    
    def get_leak_records(self):
        return [r for r in self.chat_records if r.get('has_leak_keywords', False)]
    
    def get_summary(self):
        leak_records = self.get_leak_records()
        return {
            'total_records': len(self.chat_records),
            'leak_records_count': len(leak_records),
            'leak_keywords_found': self.get_leak_keywords_count()
        }