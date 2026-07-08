import os
from datetime import datetime, timedelta

class RuleEngine:
    """规则引擎：渐进式评分，不封顶，严重性与分数对齐。

    P0 修复说明：
    - P0-3: 7 条规则全部从断崖式二值评分改为渐进式分级评分
    - P0-4: 移除 min(risk_score, 100) 全局封顶，保留 raw_score 用于排序
    - P0-5: R003 max_score 从 40 提高到 60，使 severity='critical' 与高风险阈值对齐
    """

    # 严重性 → 最低分数贡献映射（保证 severity 标签与 risk_level 不矛盾）
    # critical: 该规则触发后分数应能推动总分达到高风险(>=60)
    # high:     应能推动到中风险(>=30)
    # medium:   中等贡献
    # low:      轻微贡献
    SEVERITY_MIN_SCORE = {
        'critical': 60,
        'high': 30,
        'medium': 15,
        'low': 5,
    }

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

        # P0-4: 移除 min(risk_score, 100) 封顶
        # raw_score 可超过 100，保留排序区分度
        # display_score 仅用于展示，不影响风险等级判定
        display_score = min(risk_score, 100)
        risk_level = self._determine_risk_level(risk_score)

        return {
            'employee_name': employee_name,
            'risk_score': risk_score,          # 原始分，可 >100
            'display_score': display_score,     # 展示分，封顶 100
            'risk_level': risk_level,
            'findings': findings,
            'assessment_time': datetime.now()
        }

    # ------------------------------------------------------------------ #
    #  R000 — 敏感内容命中 (max 20)
    # ------------------------------------------------------------------ #
    def _rule_sensitive_content(self, scan_results):
        score = 0
        finding = None

        sensitive_findings = scan_results.get('content_sensitive_findings', 0)
        if sensitive_findings > 0:
            # 渐进评分: 每个命中 +5 分，基础 0 分，上限 20
            score = min(20, sensitive_findings * 5)
            # 1→5, 2→10, 3→15, 4→20
            finding = {
                'rule_id': 'R000',
                'rule_name': '敏感内容命中',
                'severity': 'high' if score >= 15 else 'medium',
                'score': score,
                'description': (
                    f"指定目录中发现 {sensitive_findings} 个敏感内容证据，"
                    f"评分随命中数递增（上限20分）"
                ),
                'evidence_count': sensitive_findings
            }

        return score, finding

    # ------------------------------------------------------------------ #
    #  R001 — 非工作时间密集文件操作 (max 30)
    # ------------------------------------------------------------------ #
    def _rule_night_time_operations(self, scan_results):
        score = 0
        finding = None

        night_ops = scan_results.get('night_time_file_operations', 0)
        if night_ops > 0:
            # 渐进评分: 基础 3 分 + 每次操作 0.15 分，上限 30
            # 1→3, 10→4, 50→10, 100→18, 150→25, 200+→30
            score = min(30, 3 + int(night_ops * 0.15))
            severity = 'high' if score >= 20 else ('medium' if score >= 10 else 'low')
            finding = {
                'rule_id': 'R001',
                'rule_name': '非工作时间密集文件操作',
                'severity': severity,
                'score': score,
                'description': (
                    f"审计时间范围内夜间文件操作 {night_ops} 次，"
                    f"评分按操作频率渐进计算（上限30分）"
                ),
                'evidence_count': night_ops
            }

        return score, finding

    # ------------------------------------------------------------------ #
    #  R002 — U盘异常使用 (max 25)
    # ------------------------------------------------------------------ #
    def _rule_usb_abnormal_usage(self, scan_results):
        score = 0
        finding = None

        usb_insertions = scan_results.get('usb_insertions_last_30_days', 0)
        usb_file_copies = scan_results.get('usb_file_copies', 0)
        short_time_insertions = scan_results.get('usb_short_time_insertions', 0)

        reasons = []
        sub_score = 0

        # 插入次数: 每次插入 +2 分，上限 10
        if usb_insertions > 0:
            sub_score += min(10, usb_insertions * 2)
            reasons.append(f"{usb_insertions}次插入")

        # 文件复制: 每10次 +1 分，上限 8
        if usb_file_copies > 0:
            sub_score += min(8, int(usb_file_copies * 0.1))
            reasons.append(f"{usb_file_copies}次文件复制")

        # 短时间密集插入: 每次 +2 分，上限 7
        if short_time_insertions > 0:
            sub_score += min(7, short_time_insertions * 2)
            reasons.append(f"{short_time_insertions}次短时间密集插入")

        if sub_score > 0:
            score = min(25, sub_score)
            severity = 'high' if score >= 20 else ('medium' if score >= 10 else 'low')
            description = f"U盘异常使用：{', '.join(reasons)}，存在数据外传风险"
            finding = {
                'rule_id': 'R002',
                'rule_name': 'U盘异常使用',
                'severity': severity,
                'score': score,
                'description': description,
                'evidence_count': usb_insertions + usb_file_copies + short_time_insertions
            }

        return score, finding

    # ------------------------------------------------------------------ #
    #  R003 — 聊天记录泄露 (max 60)
    #  P0-5: max_score 从 40 提高到 60，使 critical 严重性与高风险阈值对齐
    # ------------------------------------------------------------------ #
    def _rule_chat_leak_keywords(self, scan_results):
        score = 0
        finding = None

        chat_leak_keywords = scan_results.get('chat_leak_keywords_found', 0)
        if chat_leak_keywords > 0:
            # 渐进评分: 基础 10 分 + 每个关键词 12 分，上限 60
            # 1→22, 2→34, 3→46, 4→58, 5+→60
            # P0-5: max=60 使 severity='critical' 时总分管入高风险(>=60)
            score = min(60, 10 + chat_leak_keywords * 12)
            # severity 随分数递增: 低分→high，高分→critical
            severity = 'critical' if score >= 46 else 'high'
            finding = {
                'rule_id': 'R003',
                'rule_name': '聊天记录泄露',
                'severity': severity,
                'score': score,
                'description': (
                    f"聊天记录中发现数据泄露意图（{chat_leak_keywords}个关键词），"
                    f"评分随关键词数递增（上限60分）"
                ),
                'evidence_count': chat_leak_keywords
            }

        return score, finding

    # ------------------------------------------------------------------ #
    #  R004 — 访问网盘/邮箱 (max 20)
    # ------------------------------------------------------------------ #
    def _rule_browser_cloud_visits(self, scan_results):
        score = 0
        finding = None

        cloud_visits = scan_results.get('browser_cloud_visits', 0)
        if cloud_visits > 0:
            # 渐进评分: 基础 5 分 + 每次访问 1.5 分，上限 20
            # 1→5, 5→7, 10→15, 14+→20
            score = min(20, max(5, int(cloud_visits * 1.5)))
            severity = 'medium' if score >= 10 else 'low'
            finding = {
                'rule_id': 'R004',
                'rule_name': '访问网盘/邮箱',
                'severity': severity,
                'score': score,
                'description': (
                    f"频繁访问云存储/个人邮箱（{cloud_visits}次），"
                    f"评分按访问频率渐进计算（上限20分）"
                ),
                'evidence_count': cloud_visits
            }

        return score, finding

    # ------------------------------------------------------------------ #
    #  R005 — 大量文件打包 (max 30)
    # ------------------------------------------------------------------ #
    def _rule_large_archives(self, scan_results):
        score = 0
        finding = None

        large_archives = scan_results.get('large_archives_created', 0)
        archive_inspection = scan_results.get('archive_inspection', [])

        suspicious_count = 0
        total_sensitive_hits = 0
        total_large_inner_count = 0
        evidence_details = []

        for archive in archive_inspection:
            if archive.get('sensitive_hit_count', 0) > 0:
                suspicious_count += 1
                total_sensitive_hits += archive['sensitive_hit_count']
                evidence_details.append(
                    f"{archive['archive_name']} 内含 {archive['sensitive_hit_count']} 个敏感文件"
                )

            if archive.get('inner_file_count', 0) > 50:
                total_large_inner_count += 1
                evidence_details.append(
                    f"{archive['archive_name']} 内含 {archive['inner_file_count']} 个文件"
                )

        if large_archives > 0 or suspicious_count > 0:
            sub_score = 0

            # 压缩包数量: 每个 +2 分，上限 10
            if large_archives > 0:
                sub_score += min(10, large_archives * 2)

            # 含敏感文件的压缩包: 每个 +5 分，上限 15
            if suspicious_count > 0:
                sub_score += min(15, suspicious_count * 5)

            # 大量内含文件的压缩包: 每个 +2 分，上限 5
            if total_large_inner_count > 0:
                sub_score += min(5, total_large_inner_count * 2)

            score = min(30, sub_score)

            severity = 'high' if score >= 20 else ('medium' if score >= 10 else 'low')

            description_parts = []
            if large_archives > 0:
                description_parts.append(f"发现 {large_archives} 个压缩包")
            if suspicious_count > 0:
                description_parts.append(
                    f"{suspicious_count} 个压缩包内含敏感文件"
                    f"（共 {total_sensitive_hits} 个敏感文件名）"
                )
            if total_large_inner_count > 0:
                description_parts.append(
                    f"{total_large_inner_count} 个压缩包内含大量文件（>50个）"
                )

            description = "、".join(description_parts) + "，可能用于打包带走数据"

            finding = {
                'rule_id': 'R005',
                'rule_name': '大量文件打包',
                'severity': severity,
                'score': score,
                'description': description,
                'evidence_count': large_archives + suspicious_count,
                'evidence_details': evidence_details[:10]
            }

        return score, finding

    # ------------------------------------------------------------------ #
    #  R006 — 多源证据组合风险 (max 25)
    # ------------------------------------------------------------------ #
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

        # P0-3: 渐进评分 — 2类证据即触发，每多1类 +8 分，上限 25
        # 2→8, 3→16, 4→24, 5→25(capped)
        if len(evidence) >= 2:
            score = min(25, (len(evidence) - 1) * 8)
            severity = 'high' if score >= 16 else 'medium'
            return score, {
                'rule_id': 'R006',
                'rule_name': '多源证据组合风险',
                'severity': severity,
                'score': score,
                'description': (
                    f"同时出现 {', '.join(evidence)} 等 {len(evidence)} 类证据，"
                    f"疑似存在数据外传链路"
                ),
                'evidence_count': len(evidence)
            }

        return 0, None

    # ------------------------------------------------------------------ #
    #  风险等级判定
    # ------------------------------------------------------------------ #
    def _determine_risk_level(self, score):
        """根据原始分数（可 >100）判定风险等级。

        score 字段为展示分（封顶100），raw_score 为原始分（用于排序）。
        """
        display = min(score, 100)
        if score >= 60:
            return {'level': '高风险', 'color': '#FF0000', 'score': display, 'raw_score': score}
        elif score >= 30:
            return {'level': '中风险', 'color': '#FFA500', 'score': display, 'raw_score': score}
        elif score > 0:
            return {'level': '低风险', 'color': '#FFFF00', 'score': display, 'raw_score': score}
        else:
            return {'level': '无风险', 'color': '#00FF00', 'score': display, 'raw_score': score}

    # ------------------------------------------------------------------ #
    #  规则摘要（供 UI/API 展示）
    # ------------------------------------------------------------------ #
    def get_rules_summary(self):
        return [
            {'rule_id': 'R000', 'name': '敏感内容命中', 'max_score': 20, 'severity': 'medium'},
            {'rule_id': 'R001', 'name': '非工作时间密集文件操作', 'max_score': 30, 'severity': 'high'},
            {'rule_id': 'R002', 'name': 'U盘异常使用', 'max_score': 25, 'severity': 'high'},
            {'rule_id': 'R003', 'name': '聊天记录泄露', 'max_score': 60, 'severity': 'critical'},
            {'rule_id': 'R004', 'name': '访问网盘/邮箱', 'max_score': 20, 'severity': 'medium'},
            {'rule_id': 'R005', 'name': '大量文件打包', 'max_score': 30, 'severity': 'high'},
            {'rule_id': 'R006', 'name': '多源证据组合风险', 'max_score': 25, 'severity': 'high'}
        ]
