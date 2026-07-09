import os
from datetime import datetime


class EvidenceEngine:
    """将多源分析结果统一为证据事件，并构建离职外传风险证据链。"""

    CHAIN_STAGE_LABELS = {
        'sensitive_asset': '敏感资产',
        'archive_package': '打包聚合',
        'intent_signal': '外传意图',
        'transfer_channel': '外传通道',
        'external_device': '外设条件',
    }

    def build(self, audit_data):
        events = []
        events.extend(self._file_asset_events(audit_data.get('file_scan_results', [])))
        events.extend(self._content_events(audit_data.get('content_findings', [])))
        events.extend(self._archive_events(audit_data.get('scan_results', {}).get('archive_inspection', [])))
        events.extend(self._chat_events(audit_data.get('chat_records', [])))
        events.extend(self._browser_events(audit_data.get('browser_records', [])))
        events.extend(self._usb_events(audit_data.get('usb_devices', []), audit_data.get('usb_operations', [])))

        events = self._dedupe_events(events)
        events.sort(key=lambda event: event.get('timestamp') or datetime.min)

        chains = self._build_chains(events)
        scoring_breakdown = self._build_scoring_breakdown(
            audit_data.get('findings', []),
            chains
        )

        return {
            'evidence_events': events,
            'evidence_chains': chains,
            'scoring_breakdown': scoring_breakdown,
        }

    def _file_asset_events(self, files):
        events = []
        for file_info in files:
            file_type = file_info.get('file_type', '')
            file_name = file_info.get('file_name', '')
            stage = 'archive_package' if file_type == 'archive' else 'sensitive_asset'
            strength = '确定证据' if file_type in ('document', 'archive') else '环境记录'
            events.append({
                'event_id': self._event_id('file', file_info.get('file_path', ''), file_info.get('modify_time')),
                'source': '文件系统',
                'stage': stage,
                'stage_label': self.CHAIN_STAGE_LABELS[stage],
                'title': file_name or '本地文件',
                'description': f"发现{file_type or '文件'}：{file_name}",
                'target': file_info.get('file_path', ''),
                'timestamp': file_info.get('modify_time'),
                'strength': strength,
                'confidence': 85 if file_type in ('document', 'archive') else 60,
                'keywords': [],
            })
        return events

    def _content_events(self, findings):
        events = []
        for finding in findings:
            finding_type = finding.get('type', '')
            stage = 'sensitive_asset'
            if finding_type in ('cloud_storage', 'email', 'email_address'):
                stage = 'transfer_channel'
            elif finding.get('evidence_strength') == '行为线索':
                stage = 'intent_signal'

            events.append({
                'event_id': self._event_id(f"content:{finding_type}", finding.get('file_path', ''), finding.get('modify_time')),
                'source': '内容分析',
                'stage': stage,
                'stage_label': self.CHAIN_STAGE_LABELS[stage],
                'title': finding.get('file_name') or finding.get('file_path') or '内容命中',
                'description': finding.get('description', ''),
                'target': finding.get('file_path', ''),
                'timestamp': finding.get('modify_time'),
                'strength': finding.get('evidence_strength', '推测线索'),
                'confidence': self._confidence_from_strength(finding.get('evidence_strength')),
                'keywords': finding.get('matched_keywords', []),
            })
        return events

    def _archive_events(self, archives):
        events = []
        for archive in archives:
            if archive.get('sensitive_hit_count', 0) <= 0 and archive.get('inner_file_count', 0) <= 0:
                continue
            events.append({
                'event_id': self._event_id('archive', archive.get('archive_path', ''), archive.get('modify_time')),
                'source': '压缩包检查',
                'stage': 'archive_package',
                'stage_label': self.CHAIN_STAGE_LABELS['archive_package'],
                'title': archive.get('archive_name', '压缩包'),
                'description': (
                    f"压缩包内含 {archive.get('inner_file_count', 0)} 个文件，"
                    f"其中 {archive.get('sensitive_hit_count', 0)} 个文件名命中敏感特征"
                ),
                'target': archive.get('archive_path', ''),
                'timestamp': archive.get('modify_time'),
                'strength': '确定证据' if archive.get('sensitive_hit_count', 0) else '环境记录',
                'confidence': 88 if archive.get('sensitive_hit_count', 0) else 65,
                'keywords': archive.get('sensitive_inner_hits', []),
            })
        return events

    def _chat_events(self, records):
        events = []
        for record in records:
            if not record.get('has_leak_keywords'):
                continue
            sender = record.get('sender', '')
            receiver = record.get('receiver', '')
            content = record.get('content', '')
            events.append({
                'event_id': self._event_id('chat', content, record.get('timestamp')),
                'source': '聊天记录',
                'stage': 'intent_signal',
                'stage_label': self.CHAIN_STAGE_LABELS['intent_signal'],
                'title': f"{sender} -> {receiver}".strip(' ->') or '聊天记录',
                'description': content[:160],
                'target': record.get('table_name', 'messages'),
                'timestamp': record.get('timestamp'),
                'strength': record.get('evidence_strength', '行为线索'),
                'confidence': 78,
                'keywords': record.get('matched_keywords', []),
            })
        return events

    def _browser_events(self, records):
        events = []
        for record in records:
            keywords = record.get('matched_keywords', [])
            if not keywords:
                continue
            events.append({
                'event_id': self._event_id('browser', record.get('url', ''), record.get('last_visit_time')),
                'source': '浏览器记录',
                'stage': 'transfer_channel',
                'stage_label': self.CHAIN_STAGE_LABELS['transfer_channel'],
                'title': record.get('title') or record.get('domain') or '浏览器访问',
                'description': record.get('url', ''),
                'target': record.get('url', ''),
                'timestamp': record.get('last_visit_time'),
                'strength': '环境记录',
                'confidence': 62,
                'keywords': keywords,
            })
        return events

    def _usb_events(self, devices, operations):
        events = []
        for device in devices:
            events.append({
                'event_id': self._event_id('usb_device', device.get('device_path', ''), device.get('last_insert_time')),
                'source': 'USB记录',
                'stage': 'external_device',
                'stage_label': self.CHAIN_STAGE_LABELS['external_device'],
                'title': device.get('device_name') or device.get('device_type') or 'USB设备',
                'description': '发现USB设备使用痕迹',
                'target': device.get('device_path', ''),
                'timestamp': device.get('last_insert_time') or device.get('first_insert_time'),
                'strength': '环境记录',
                'confidence': 58,
                'keywords': [],
            })

        for operation in operations:
            if operation.get('operation_type') not in ('copy', 'write', 'archive_copy'):
                continue
            events.append({
                'event_id': self._event_id('usb_operation', operation.get('device_id', ''), operation.get('timestamp')),
                'source': 'USB记录',
                'stage': 'external_device',
                'stage_label': self.CHAIN_STAGE_LABELS['external_device'],
                'title': operation.get('operation_type', 'USB操作'),
                'description': operation.get('device_info', '疑似USB文件操作记录'),
                'target': operation.get('device_id', ''),
                'timestamp': operation.get('timestamp'),
                'strength': '行为线索',
                'confidence': 72,
                'keywords': [],
            })
        return events

    def _build_chains(self, events):
        by_stage = {}
        for event in events:
            by_stage.setdefault(event['stage'], []).append(event)

        stage_order = [
            'sensitive_asset',
            'archive_package',
            'intent_signal',
            'transfer_channel',
            'external_device',
        ]

        chain_events = []
        missing = []
        for stage in stage_order:
            candidates = by_stage.get(stage, [])
            if candidates:
                chain_events.append(self._best_event(candidates))
            else:
                missing.append(self.CHAIN_STAGE_LABELS[stage])

        present_stage_count = len(chain_events)
        completeness = int(present_stage_count / len(stage_order) * 100)
        confidence = min(95, sum(event.get('confidence', 0) for event in chain_events) // max(present_stage_count, 1))

        risk_level = '低'
        if completeness >= 80:
            risk_level = '高'
        elif completeness >= 50:
            risk_level = '中'

        if not chain_events:
            return []

        return [{
            'chain_id': 'CHAIN-001',
            'title': '离职数据外传风险链',
            'summary': self._chain_summary(chain_events, missing),
            'completeness': completeness,
            'confidence': confidence,
            'risk_level': risk_level,
            'present_stages': [event['stage_label'] for event in chain_events],
            'missing_stages': missing,
            'events': chain_events,
        }]

    def _build_scoring_breakdown(self, findings, chains):
        breakdown = []
        for finding in findings:
            breakdown.append({
                'rule_id': finding.get('rule_id', ''),
                'name': finding.get('rule_name', ''),
                'score': finding.get('score', 0),
                'severity': finding.get('severity', ''),
                'description': finding.get('description', ''),
                'basis': '规则评分',
            })

        for chain in chains:
            breakdown.append({
                'rule_id': chain['chain_id'],
                'name': '证据链完整度',
                'score': chain['completeness'],
                'severity': chain['risk_level'],
                'description': chain['summary'],
                'basis': '证据链分析',
            })

        return breakdown

    def _best_event(self, events):
        return sorted(
            events,
            key=lambda event: (event.get('confidence', 0), event.get('timestamp') or datetime.min),
            reverse=True
        )[0]

    def _chain_summary(self, events, missing):
        labels = ' -> '.join(event['stage_label'] for event in events)
        if missing:
            return f"已形成部分链路：{labels}；缺失环节：{', '.join(missing)}。"
        return f"已形成完整风险链路：{labels}。"

    def _confidence_from_strength(self, strength):
        return {
            '确定证据': 90,
            '行为线索': 78,
            '环境记录': 62,
            '推测线索': 48,
            '弱线索': 30,
        }.get(strength, 45)

    def _event_id(self, source, target, timestamp):
        raw = f"{source}|{target}|{timestamp}"
        return str(abs(hash(raw)))

    def _dedupe_events(self, events):
        seen = set()
        result = []
        for event in events:
            key = event.get('event_id')
            if key in seen:
                continue
            seen.add(key)
            result.append(event)
        return result
