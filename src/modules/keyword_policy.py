HIGH_RISK_KEYWORDS = {
    '客户名单', '客户资料', '客户信息', '报价表', '核心报价', '源代码', '数据库',
    '密码', '密钥', 'token', '商业计划书', '商业计划', '财务数据', '工资',
    '薪酬', '合同', '协议', '机密', '绝密', '内部资料'
}

ACTION_KEYWORDS = {
    '外传', '泄露', '发送', '上传', '打包', '拷贝', '复制', '转发', '下载',
    '带走', '发出去', '个人邮箱', '网盘', '云盘', 'U盘', '移动硬盘'
}

CHANNEL_KEYWORDS = {
    '百度网盘', '阿里云盘', '腾讯微云', '坚果云', '个人邮箱', 'qq邮箱',
    '网易邮箱', 'Gmail邮箱', 'Outlook邮箱', 'iCloud邮箱', '网盘', '云盘'
}

LOW_SIGNAL_KEYWORDS = {
    '项目', '任务', '问题', '优化', '配置', '环境', '流程', '方案', '计划',
    '开发', '测试', '上线', '运维', '维护'
}

CATEGORY_WEIGHT = {
    'high_risk_asset': 8,
    'exfiltration_action': 7,
    'transfer_channel': 5,
    'low_signal': 1,
    'generic_sensitive': 3,
}

CATEGORY_STRENGTH = {
    'high_risk_asset': '确定证据',
    'exfiltration_action': '行为线索',
    'transfer_channel': '环境记录',
    'low_signal': '弱线索',
    'generic_sensitive': '推测线索',
}


def classify_keyword(keyword):
    normalized = str(keyword).strip()
    if normalized in HIGH_RISK_KEYWORDS:
        return 'high_risk_asset'
    if normalized in ACTION_KEYWORDS:
        return 'exfiltration_action'
    if normalized in CHANNEL_KEYWORDS:
        return 'transfer_channel'
    if normalized in LOW_SIGNAL_KEYWORDS:
        return 'low_signal'
    return 'generic_sensitive'


def score_keywords(keywords):
    category_counts = {}
    total_score = 0
    strongest = '弱线索'

    for keyword in keywords:
        category = classify_keyword(keyword)
        category_counts[category] = category_counts.get(category, 0) + 1
        total_score += CATEGORY_WEIGHT[category]

    if category_counts.get('high_risk_asset'):
        strongest = '确定证据'
    elif category_counts.get('exfiltration_action'):
        strongest = '行为线索'
    elif category_counts.get('transfer_channel'):
        strongest = '环境记录'
    elif category_counts.get('generic_sensitive'):
        strongest = '推测线索'

    return {
        'keyword_score': total_score,
        'keyword_categories': category_counts,
        'evidence_strength': strongest,
    }
