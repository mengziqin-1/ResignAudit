import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
KEYWORDS_DIR = os.path.join(BASE_DIR, 'keywords')

DOCUMENT_EXTENSIONS = (
    '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.pdf', '.csv', '.json', '.xml', '.html', '.htm', '.md',
    '.rtf', '.odt', '.ods', '.odp', '.eml', '.msg'
)

IMAGE_EXTENSIONS = (
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.ico'
)

ARCHIVE_EXTENSIONS = (
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab', '.iso'
)

SENSITIVE_KEYWORDS_FILE = os.path.join(KEYWORDS_DIR, 'sensitive_keywords.txt')
CLOUD_STORAGE_KEYWORDS_FILE = os.path.join(KEYWORDS_DIR, 'cloud_storage_keywords.txt')
EMAIL_KEYWORDS_FILE = os.path.join(KEYWORDS_DIR, 'email_keywords.txt')

USB_REGISTRY_PATHS = [
    r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR',
    r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB',
    r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices'
]

BROWSER_PATHS = {
    'chrome': [
        os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\History'),
        os.path.expanduser(r'~\AppData\Local\Google\Chrome\User Data\Default\Cache')
    ],
    'edge': [
        os.path.expanduser(r'~\AppData\Local\Microsoft\Edge\User Data\Default\History'),
        os.path.expanduser(r'~\AppData\Local\Microsoft\Edge\User Data\Default\Cache')
    ],
    'firefox': [
        os.path.expanduser(r'~\AppData\Roaming\Mozilla\Firefox\Profiles')
    ]
}

CHAT_PATHS = {
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

REPORT_TEMPLATE = {
    'title': '离职场景电子数据取证分析报告',
    'font': 'SimHei',
    'font_size': 12,
    'header': [
        '审计项目', '面向离职风险的电子数据取证辅助系统',
        '审计日期', '{audit_date}',
        '员工姓名', '{employee_name}',
        '审计范围', '{audit_range}',
        '风险等级', '{risk_level}'
    ]
}

RISK_LEVELS = {
    'high': {'label': '高风险', 'color': '#FF0000', 'threshold': 60},
    'medium': {'label': '中风险', 'color': '#FFA500', 'threshold': 30},
    'low': {'label': '低风险', 'color': '#FFFF00', 'threshold': 1},
    'none': {'label': '无风险', 'color': '#00FF00', 'threshold': 0}
}
