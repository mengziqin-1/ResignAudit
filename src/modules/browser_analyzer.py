import os
import re
import sqlite3
import shutil
import pandas as pd
from datetime import datetime

class BrowserAnalyzer:
    def __init__(self):
        self.history_records = []
        self.cloud_visits = []
        self.email_visits = []
        self.load_keywords()
    
    def load_keywords(self):
        keywords_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'keywords')
        
        self.cloud_keywords = []
        cloud_file = os.path.join(keywords_dir, 'cloud_storage_keywords.txt')
        if os.path.exists(cloud_file):
            with open(cloud_file, 'r', encoding='utf-8') as f:
                self.cloud_keywords = [line.strip().lower() for line in f if line.strip()]
        
        self.email_keywords = []
        email_file = os.path.join(keywords_dir, 'email_keywords.txt')
        if os.path.exists(email_file):
            with open(email_file, 'r', encoding='utf-8') as f:
                self.email_keywords = [line.strip().lower() for line in f if line.strip()]
    
    def analyze_browsers(self, progress_callback=None):
        self.history_records = []
        self.cloud_visits = []
        self.email_visits = []
        
        browsers = ['chrome', 'edge', 'firefox']
        for browser in browsers:
            try:
                records = self._analyze_browser(browser)
                self.history_records.extend(records)
                
                for record in records:
                    if self._is_cloud_storage(record):
                        self.cloud_visits.append(record)
                    if self._is_email_service(record):
                        self.email_visits.append(record)
            except Exception:
                continue
        
        if progress_callback:
            progress_callback(f"浏览器历史记录分析完成，共发现 {len(self.history_records)} 条记录")
        
        return self.history_records, self.cloud_visits, self.email_visits
    
    def _analyze_browser(self, browser_name):
        records = []
        
        if browser_name == 'chrome':
            history_path = os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\History')
            records = self._parse_chrome_history(history_path)
        elif browser_name == 'edge':
            history_path = os.path.expanduser(r'~\AppData\Local\Microsoft\Edge\User Data\Default\History')
            records = self._parse_chrome_history(history_path)
        elif browser_name == 'firefox':
            profiles_dir = os.path.expanduser(r'~\AppData\Roaming\Mozilla\Firefox\Profiles')
            records = self._parse_firefox_history(profiles_dir)
        
        return records
    
    def _parse_chrome_history(self, history_path):
        records = []
        
        if not os.path.exists(history_path):
            return records
        
        temp_path = history_path + '.tmp'
        try:
            shutil.copy2(history_path, temp_path)
        except (PermissionError, OSError):
            return records
            
        try:
            conn = sqlite3.connect(temp_path, timeout=5)
            cursor = conn.cursor()
            
            try:
                cursor.execute('SELECT url, title, last_visit_time, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 500')
                for row in cursor.fetchall():
                    url = row[0]
                    title = row[1]
                    last_visit_time = self._convert_chrome_time(row[2])
                    visit_count = row[3]
                    
                    records.append({
                        'browser': 'chrome/edge',
                        'url': url,
                        'title': title,
                        'last_visit_time': last_visit_time,
                        'visit_count': visit_count,
                        'domain': self._extract_domain(url)
                    })
            finally:
                conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
        
        return records
    
    def _parse_firefox_history(self, profiles_dir):
        records = []
        
        if not os.path.exists(profiles_dir):
            return records
        
        for profile in os.listdir(profiles_dir):
            profile_path = os.path.join(profiles_dir, profile)
            places_path = os.path.join(profile_path, 'places.sqlite')
            
            if not os.path.exists(places_path):
                continue
            
            temp_path = places_path + '.tmp'
            try:
                shutil.copy2(places_path, temp_path)
            except (PermissionError, OSError):
                continue
                
            try:
                conn = sqlite3.connect(temp_path, timeout=5)
                cursor = conn.cursor()
                
                try:
                    cursor.execute('SELECT url, title, last_visit_date, visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT 500')
                    for row in cursor.fetchall():
                        url = row[0]
                        title = row[1]
                        last_visit_time = self._convert_firefox_time(row[2])
                        visit_count = row[3]
                        
                        records.append({
                            'browser': 'firefox',
                            'url': url,
                            'title': title,
                            'last_visit_time': last_visit_time,
                            'visit_count': visit_count,
                            'domain': self._extract_domain(url)
                        })
                finally:
                    conn.close()
            except Exception:
                pass
            finally:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
        
        return records
    
    def _convert_chrome_time(self, chrome_time):
        if chrome_time == 0:
            return None
        epoch_start = datetime(1601, 1, 1)
        try:
            return epoch_start + pd.Timedelta(microseconds=chrome_time)
        except:
            return None
    
    def _convert_firefox_time(self, firefox_time):
        if firefox_time == 0:
            return None
        try:
            return datetime.fromtimestamp(firefox_time / 1000000)
        except:
            return None
    
    def _extract_domain(self, url):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return url
    
    def _is_cloud_storage(self, record):
        url = record['url'].lower()
        title = record['title'].lower() if record['title'] else ''
        domain = record['domain'].lower() if record['domain'] else ''
        
        for keyword in self.cloud_keywords:
            if keyword in url or keyword in title or keyword in domain:
                return True
        
        cloud_domains = ['baidu.com', 'aliyun.com', 'tencent.com', 'huaweicloud.com',
                         'onedrive.com', 'sharepoint.com', 'google.com', 'dropbox.com',
                         'icloud.com', 'box.com', 'mega.nz', 'pcloud.com', 'sync.com']
        for domain_suffix in cloud_domains:
            if domain_suffix in domain:
                return True
        
        return False
    
    def _is_email_service(self, record):
        url = record['url'].lower()
        title = record['title'].lower() if record['title'] else ''
        domain = record['domain'].lower() if record['domain'] else ''
        
        for keyword in self.email_keywords:
            if keyword in url or keyword in title or keyword in domain:
                return True
        
        email_domains = ['mail.', 'email.', 'smtp.', 'pop.', 'imap.',
                         'qq.com', '163.com', '126.com', 'sina.com',
                         'hotmail.com', 'outlook.com', 'live.com',
                         'gmail.com', 'icloud.com', 'yahoo.com']
        for domain_suffix in email_domains:
            if domain_suffix in domain:
                return True
        
        return False
    
    def get_cloud_visits_count(self, days=30):
        cutoff_date = datetime.now() - pd.Timedelta(days=days)
        count = 0
        for visit in self.cloud_visits:
            if visit['last_visit_time'] and visit['last_visit_time'] >= cutoff_date:
                count += 1
        return count
    
    def get_email_visits_count(self, days=30):
        cutoff_date = datetime.now() - pd.Timedelta(days=days)
        count = 0
        for visit in self.email_visits:
            if visit['last_visit_time'] and visit['last_visit_time'] >= cutoff_date:
                count += 1
        return count
    
    def get_summary(self):
        return {
            'total_history_records': len(self.history_records),
            'cloud_visits_count': len(self.cloud_visits),
            'email_visits_count': len(self.email_visits),
            'recent_cloud_visits': self.get_cloud_visits_count(30),
            'recent_email_visits': self.get_email_visits_count(30)
        }