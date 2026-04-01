"""敏感信息检测的常量定义"""

import re

# 敏感键名模式（正则表达式，不区分大小写）
SENSITIVE_KEY_PATTERNS = [
    re.compile(r"^(api[_\-]?key|apikey)$", re.IGNORECASE),
    re.compile(r"^(secret|password|passwd|pwd)$", re.IGNORECASE),
    re.compile(r"^(token|auth|bearer|jwt)$", re.IGNORECASE),
    re.compile(r"^(private[_\-]?key|privkey)$", re.IGNORECASE),
    re.compile(r"^(access[_\-]?key|aws[_\-]?key)$", re.IGNORECASE),
    re.compile(r"^(github[_\-]?token|gh[_\-]?token)$", re.IGNORECASE),
    re.compile(r"^.*(credential|secret|token|key|password|auth).*$", re.IGNORECASE),
]

# 常见泄露模式（用于直接扫描文件内容）
LEAK_PATTERNS = [
    # OpenAI API Key
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    # GitHub Personal Access Token
    re.compile(r"ghp_[a-zA-Z0-9]{36,}"),
    # GitHub OAuth Access Token
    re.compile(r"gho_[a-zA-Z0-9]{36,}"),
    # AWS Access Key ID
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # AWS Secret Access Key (generic pattern)
    re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    # Private Key
    re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----"),
    # Generic API Key pattern
    re.compile(r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*['\"]?[a-zA-Z0-9]{20,}"),
    # Generic Secret pattern
    re.compile(r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}"),
    # JWT Token
    re.compile(r"eyJ[a-zA-Z0-9]{10,}\.eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9_-]{10,}"),
]

# 高风险关键词（用于快速过滤）
HIGH_RISK_KEYWORDS = [
    "api_key",
    "apikey",
    "secret_key",
    "secretkey",
    "private_key",
    "privatekey",
    "access_token",
    "access_token_secret",
    "aws_access_key",
    "aws_secret_key",
    "github_token",
    "gh_token",
]

# .env 文件名模式
ENV_FILENAME_PATTERNS = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.test",
    ".env.staging",
    ".env.example",
    ".env.sample",
    ".env.dev",
    ".env.prod",
    ".flaskenv",
    ".djangoenv",
]

# 注释符号
COMMENT_SYMBOLS = ["#", ";", "//"]

# 引号符号
QUOTE_SYMBOLS = ['"', "'"]
