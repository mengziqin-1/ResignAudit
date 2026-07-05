import os
from datetime import datetime, timedelta

class RuleEngine:
    def __init__(self):
        self.rules = [
            self._rule_sensitive_content,
            self._rule_night_time_operations,
            self._rule_usb_abnormal_usage,
            self._rule_chat_leak_keywords,
            self._rule_browser_cloud_visits,
            self._rule_large_archives,
            self._rule_combined_exfiltration
        ]
    
    def assess_risk(self, employee_name, scan_results):
        risk_score = 0
        findings = []
        
        for rule in self.rules:
            score, finding = rule(scan_results)
            risk_score += score
            if finding:
                findings.append(finding)
        
        risk_score = min(risk_score, 100)
        risk_level = self._determine_risk_level(risk_score)
        
        return {
            'employee_name': employee_name,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'findings': findings,
            'assessment_time': datetime.now()
        }
    
    def _rule_sensitive_content(self, scan_results):
        score = 0
        finding = None

        sensitive_findings = scan_results.get('content_sensitive_findings', 0)
        if sensitive_findings > 0:
            score = min(20, 5 + sensitive_findings * 5)
            finding = {
                'rule_id': 'R000',
                'rule_name': '敏感内容命中',
                'severity': 'medium' if score < 20 else 'high',
                'score': score,
                'description': f"指定目录中发现 {sensitive_findings} 个敏感内容证据，已按单类证据设置评分上限，避免单个报告类文件造成过度评分",
                'evidence_count': sensitive_findings
            }

        return score, finding

    def _rule_night_time_operations(self, scan_results):
        score = 0
        finding = None
        
        night_ops = scan_results.get('night_time_file_operations', 0)
        if night_ops > 50:
            score = 20 if night_ops <= 200 else 30
            finding = {
                'rule_id': 'R001',
                'rule_name': '非工作时间密集文件操作',
                'severity': 'high',
                'score': score,
                'description': f"审计时间范围内夜间文件操作较多（{night_ops}次），疑似非工作时间集中处理文件",
                'evidence_count': night_ops
            }
        
        return score, finding
    
    def _rule_usb_abnormal_usage(self, scan_results):
        score = 0
        finding = None
        
        usb_insertions = scan_results.get('usb_insertions_last_30_days', 0)
        usb_file_copies = scan_results.get('usb_file_copies', 0)
        
        if usb_insertions >= 2 or usb_file_copies >= 50:
            score = 15
            if usb_insertions > 5 or usb_file_copies > 100:
                score = 25
            finding = {
                'rule_id': 'R002',
                'rule_name': 'U盘异常使用',
                'severity': 'high' if score >= 25 else 'medium',
                'score': score,
                'description': f"频繁使用U盘（{usb_insertions}次插入）并大量拷贝文件（{usb_file_copies}次），存在数据外传风险",
                'evidence_count': usb_insertions + usb_file_copies
            }
        
        return score, finding
    
    def _rule_chat_leak_keywords(self, scan_results):
        score = 0
        finding = None
        
        chat_leak_keywords = scan_results.get('chat_leak_keywords_found', 0)
        if chat_leak_keywords >= 3:
            score = 40
            finding = {
                'rule_id': 'R003',
                'rule_name': '聊天记录泄露',
                'severity': 'critical',
                'score': score,
                'description': f"聊天记录中发现明确的数据泄露意图（{chat_leak_keywords}个关键词）",
                'evidence_count': chat_leak_keywords
            }
        
        return score, finding
    
    def _rule_browser_cloud_visits(self, scan_results):
        score = 0
        finding = None
        
        cloud_visits = scan_results.get('browser_cloud_visits', 0)
        if cloud_visits > 0:
            score = 10 if cloud_visits <= 10 else 20
            finding = {
                'rule_id': 'R004',
                'rule_name': '访问网盘/邮箱',
                'severity': 'medium',
                'score': score,
                'description': f"频繁访问云存储/个人邮箱（{cloud_visits}次），可能用于数据传输",
                'evidence_count': cloud_visits
            }
        
        return score, finding
    
    def _rule_large_archives(self, scan_results):
        score = 0
        finding = None
        
        large_archives = scan_results.get('large_archives_created', 0)
        if large_archives > 0:
            score = 10 if large_archives <= 5 else 15
            finding = {
                'rule_id': 'R005',
                'rule_name': '大量文件打包',
                'severity': 'medium',
                'score': score,
                'description': f"创建大量压缩包（{large_archives}个），可能用于打包带走数据",
                'evidence_count': large_archives
            }
        
        return score, finding

    def _rule_combined_exfiltration(self, scan_results):
        evidence = []
        if scan_results.get('content_sensitive_findings', 0) > 0:
            evidence.append('敏感文件')
        if scan_results.get('large_archives_created', 0) > 0:
            evidence.append('压缩包')
        if scan_results.get('usb_insertions_last_30_days', 0) > 0 or scan_results.get('usb_file_copies', 0) > 0:
            evidence.append('USB使用')
        if scan_results.get('browser_cloud_visits', 0) > 0:
            evidence.append('网盘/邮箱访问')
        if scan_results.get('chat_leak_keywords_found', 0) > 0:
            evidence.append('聊天泄露意图')

        if len(evidence) >= 3:
            score = 25
            return score, {
                'rule_id': 'R006',
                'rule_name': '多源证据组合风险',
                'severity': 'high',
                'score': score,
                'description': f"同时出现 {', '.join(evidence)} 等多类证据，疑似存在数据外传链路",
                'evidence_count': len(evidence)
            }

        return 0, None
    
    def _determine_risk_level(self, score):
        if score >= 60:
            return {'level': '高风险', 'color': '#FF0000', 'score': score}
        elif score >= 30:
            return {'level': '中风险', 'color': '#FFA500', 'score': score}
        elif score > 0:
            return {'level': '低风险', 'color': '#FFFF00', 'score': score}
        else:
            return {'level': '无风险', 'color': '#00FF00', 'score': score}
    
    def get_rules_summary(self):
        return [
            {'rule_id': 'R000', 'name': '敏感内容命中', 'max_score': 20, 'severity': 'medium'},
            {'rule_id': 'R001', 'name': '非工作时间密集文件操作', 'max_score': 30, 'severity': 'high'},
            {'rule_id': 'R002', 'name': 'U盘异常使用', 'max_score': 25, 'severity': 'high'},
            {'rule_id': 'R003', 'name': '聊天记录泄露', 'max_score': 40, 'severity': 'critical'},
            {'rule_id': 'R004', 'name': '访问网盘/邮箱', 'max_score': 20, 'severity': 'medium'},
            {'rule_id': 'R005', 'name': '大量文件打包', 'max_score': 15, 'severity': 'medium'},
            {'rule_id': 'R006', 'name': '多源证据组合风险', 'max_score': 25, 'severity': 'high'}
        ]
