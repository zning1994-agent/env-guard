"""敏感信息检测的常量定义"""

from typing import List, Pattern
import re

# 敏感键名模式（正则）
SENSITIVE_PATTERNS: List[str] = [
    r"^(api[_-]?key|apikey)$",
    r"^(secret|password|passwd|pwd)$",
    r"^(token|auth|bearer|jwt)$",
    r"^(private[_-]?key|privkey)$",
    r"^(access[_-]?key|aws[_-]?key)$",
    r"^.*(credential|secret|token|key|password|auth).*$",
]

# 编译后的敏感键名正则
SENSITIVE_REGEXES: List[Pattern] = [
    re.compile(pattern, re.IGNORECASE) for pattern in SENSITIVE_PATTERNS
]

# 常见泄露模式（用于扫描文件内容）
LEAK_PATTERNS: List[dict] = [
    {
        "name": "OpenAI API Key",
        "pattern": r"sk-[a-zA-Z0-9]{20,}",
        "severity": "critical",
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": r"ghp_[a-zA-Z0-9]{36,}",
        "severity": "critical",
    },
    {
        "name": "GitHub OAuth Token",
        "pattern": r"gho_[a-zA-Z0-9]{36,}",
        "severity": "critical",
    },
    {
        "name": "AWS Access Key ID",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
        "severity": "critical",
    },
    {
        "name": "Generic API Key",
        "pattern": r"(?i)(api[_-]?key|apikey).{0,20}['\"][0-9a-zA-Z]{20,}['\"]",
        "severity": "high",
    },
    {
        "name": "Generic Secret",
        "pattern": r"(?i)(secret|password|passwd|pwd).{0,20}['\"][^\s'\"]{8,}['\"]",
        "severity": "high",
    },
    {
        "name": "Bearer Token",
        "pattern": r"(?i)bearer\s+[a-zA-Z0-9\-_.~+\/]+",
        "severity": "high",
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[a-zA-Z0-9]{10,}\.eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9_-]+",
        "severity": "high",
    },
    {
        "name": "Private Key",
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "critical",
    },
]

# 编译后的泄露正则
LEAK_REGEXES: List[Pattern] = [
    re.compile(item["pattern"]) for item in LEAK_PATTERNS
]

# 常见的 .env 文件名
ENV_FILENAMES: List[str] = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.test",
    ".env.staging",
    ".env.example",
    ".flaskenv",
    ".gevent",
]

# 高风险文件模式（这些文件通常包含敏感信息）
HIGH_RISK_PATTERNS: List[str] = [
    r"\.env$",
    r"\.env\.",
    r"secrets\.yaml$",
    r"secrets\.yml$",
    r"credentials\.json$",
    r"\.pem$",
    r"\.key$",
    r"\.p12$",
    r"\.pfx$",
]

# 严重级别
SEVERITY_LEVELS = ["critical", "high", "medium", "low"]

# 严重级别颜色映射（用于 rich 输出）
SEVERITY_COLORS = {
    "critical": "red",
    "high": "orange1",
    "medium": "yellow",
    "low": "green",
}
