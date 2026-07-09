import os
import re
import sqlite3
import shutil
import pandas as pd
from datetime import datetime, timedelta

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
        
        self.sensitive_keywords = []
        browser_sensitive_file = os.path.join(keywords_dir, 'browser_sensitive_keywords.txt')
        if os.path.exists(browser_sensitive_file):
            with open(browser_sensitive_file, 'r', encoding='utf-8') as f:
                self.sensitive_keywords = [line.strip().lower() for line in f if line.strip()]
        else:
            sensitive_file = os.path.join(keywords_dir, 'sensitive_keywords.txt')
            if os.path.exists(sensitive_file):
                with open(sensitive_file, 'r', encoding='utf-8') as f:
                    self.sensitive_keywords = [line.strip().lower() for line in f if line.strip()]
    
    def analyze_browsers(self, progress_callback=None):
        self.history_records = []
        self.cloud_visits = []
        self.email_visits = []
        self.sensitive_visits = []
        
        browsers = ['chrome', 'edge', 'firefox']
        for browser in browsers:
            try:
                records = self._analyze_browser(browser)
                self.history_records.extend(records)
                
                for record in records:
                    cloud_keywords = self._is_cloud_storage(record)
                    if cloud_keywords:
                        record['matched_keywords'] = cloud_keywords
                        self.cloud_visits.append(record)
                    
                    email_keywords = self._is_email_service(record)
                    if email_keywords:
                        record['matched_keywords'] = email_keywords
                        self.email_visits.append(record)
                    
                    sensitive_keywords = self._contains_sensitive_keyword(record)
                    if sensitive_keywords:
                        record['matched_keywords'] = sensitive_keywords
                        self.sensitive_visits.append(record)
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
            print(f"[浏览器分析] 警告：无法读取 {history_path}，浏览器可能正在运行，请关闭浏览器后重试")
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
        except Exception as e:
            print(f"[浏览器分析] 错误：解析数据库失败 - {str(e)}")
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
                print(f"[浏览器分析] 警告：无法读取 {places_path}，Firefox 可能正在运行，请关闭浏览器后重试")
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
            except Exception as e:
                print(f"[浏览器分析] 错误：解析 Firefox 数据库失败 - {str(e)}")
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
            return epoch_start + timedelta(microseconds=chrome_time)
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
        
        cloud_subdomains = [
            'pan.baidu.com', 'cloud.baidu.com',
            'www.aliyundrive.com', 'drive.aliyun.com', 'pan.aliyun.com',
            'www.weiyun.com', 'share.weiyun.com', 'pan.weixin.qq.com',
            'www.huaweicloud.com', 'cloud.huawei.com',
            'www.jianguoyun.com',
            'onedrive.com', 'sharepoint.com',
            'drive.google.com',
            'www.dropbox.com',
            'www.icloud.com',
            'www.box.com',
            'mega.nz',
            'www.pcloud.com',
            'www.sync.com',
            'www.backblaze.com',
            'www.carbonite.com',
            'www.acronis.com',
            'www.idrive.com',
            'www.seafile.com',
            'www.owncloud.org',
            'www.nextcloud.com'
        ]
        
        matched_keywords = []
        
        for subdomain in cloud_subdomains:
            if domain == subdomain or domain.endswith('.' + subdomain):
                matched_keywords.append(subdomain)
        
        for keyword in self.cloud_keywords:
            keyword_lower = keyword.lower()
            if keyword_lower in title:
                matched_keywords.append(keyword)
        
        return matched_keywords if matched_keywords else None
    
    def _is_email_service(self, record):
        url = record['url'].lower()
        title = record['title'].lower() if record['title'] else ''
        domain = record['domain'].lower() if record['domain'] else ''
        
        email_subdomains = [
            'mail.qq.com', 'email.qq.com', 'mail.163.com', 'mail.126.com',
            'mail.sina.com', 'mail.sina.cn',
            'mail.yahoo.com', 'mail.yahoo.cn',
            'outlook.live.com', 'www.outlook.com',
            'mail.google.com', 'mail.gmail.com',
            'www.icloud.com',
            'mail.protonmail.com', 'mail.yandex.com',
            'mail.ru', 'www.mail.com',
            'mail.zoho.com', 'mail.aol.com',
            'mail.msn.com'
        ]
        
        matched_keywords = []
        
        for subdomain in email_subdomains:
            if domain == subdomain or domain.endswith('.' + subdomain):
                matched_keywords.append(subdomain)
        
        email_hosts = ['mail.', 'email.', 'webmail.', 'mailbox.']
        for host_prefix in email_hosts:
            if domain.startswith(host_prefix):
                matched_keywords.append(domain)
        
        for keyword in self.email_keywords:
            if keyword in title:
                matched_keywords.append(keyword)
        
        return matched_keywords if matched_keywords else None
    
    def _contains_sensitive_keyword(self, record):
        url = record['url'].lower()
        title = record['title'].lower() if record['title'] else ''
        domain = record['domain'].lower() if record['domain'] else ''
        
        matched_keywords = []
        for keyword in self.sensitive_keywords:
            if keyword in title:
                matched_keywords.append(keyword)
        
        return matched_keywords if matched_keywords else None
    
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
    
    def get_findings(self):
        findings = []
        
        def add_visit_group(visits, visit_type, description_prefix):
            grouped = {}
            for visit in visits:
                title = visit['title'] or visit['url']
                if title not in grouped:
                    grouped[title] = {
                        'visits': [],
                        'keywords': set(),
                        'first_time': visit['last_visit_time'],
                        'url': visit['url']
                    }
                grouped[title]['visits'].append(visit)
                grouped[title]['keywords'].update(visit.get('matched_keywords', []))
                if visit['last_visit_time'] and grouped[title]['first_time']:
                    if visit['last_visit_time'] > grouped[title]['first_time']:
                        grouped[title]['first_time'] = visit['last_visit_time']
                elif visit['last_visit_time']:
                    grouped[title]['first_time'] = visit['last_visit_time']
            
            for title, data in grouped.items():
                visit_count = len(data['visits'])
                keywords_str = ', '.join(data['keywords'])
                count_suffix = f' (访问{visit_count}次)' if visit_count > 1 else ''
                findings.append({
                    'type': visit_type,
                    'file_path': data['url'],
                    'file_name': title,
                    'modify_time': data['first_time'],
                    'severity': 'medium',
                    'evidence_strength': '环境记录',
                    'keyword_score': min(20, 5 + visit_count),
                    'keyword_categories': {'transfer_channel': len(data['keywords']) or 1},
                    'description': f"{description_prefix}{count_suffix}: 匹配关键词: {keywords_str}（证据强度：环境记录）"
                })
        
        add_visit_group(self.cloud_visits, 'cloud_storage', '访问云存储服务')
        add_visit_group(self.email_visits, 'email', '访问邮箱服务')
        add_visit_group(self.sensitive_visits, 'sensitive_keyword', '浏览器访问包含敏感词')
        
        return findings
