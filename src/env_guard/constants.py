"""敏感信息检测常量定义"""

import re

# 敏感键名模式（正则表达式）
SENSITIVE_KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^(api[_\-]?key|apikey)$", re.IGNORECASE),
    re.compile(r"^(secret|password|passwd|pwd)$", re.IGNORECASE),
    re.compile(r"^(token|auth|bearer|jwt)$", re.IGNORECASE),
    re.compile(r"^(private[_\-]?key|privkey)$", re.IGNORECASE),
    re.compile(r"^(access[_\-]?key|aws[_\-]?key)$", re.IGNORECASE),
    re.compile(r"^.*(credential|secret|token|key).*$", re.IGNORECASE),
    re.compile(r"^(db[_\-]?host|database[_\-]?host)$", re.IGNORECASE),
    re.compile(r"^.*(secret|private|password|token|key).*$", re.IGNORECASE),
]

# 常见泄露模式（用于检测 git history 中的敏感信息）
LEAK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),  # OpenAI API key
    re.compile(r"ghp_[a-zA-Z0-9]{36,}"),  # GitHub PAT
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
    re.compile(r"[a-zA-Z0-9+/]{40,}=="),  # Base64 encoded secrets
    re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,}"),  # Slack tokens
    re.compile(r"sq0[a-z]{3}-[0-9A-Za-z]{22}"),  # Square OAuth
    re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}"),  # Square OAuth
    re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),  # Stripe live key
    re.compile(r"sk_test_[0-9a-zA-Z]{24,}"),  # Stripe test key
    re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),  # Stripe public key
    re.compile(r"pk_test_[0-9a-zA-Z]{24,}"),  # Stripe test public key
]

# 高风险关键词（精确匹配）
HIGH_RISK_KEYWORDS: set[str] = {
    "api_key",
    "apikey",
    "secret_key",
    "secretkey",
    "private_key",
    "privatekey",
    "access_key",
    "accesskey",
    "aws_key",
    "awskey",
}

# ENV 文件名模式
ENV_FILENAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\.env$", re.IGNORECASE),
    re.compile(r"^\.env\.[a-zA-Z0-9_]+$", re.IGNORECASE),
    re.compile(r"^\.envrc$", re.IGNORECASE),
    re.compile(r"^env\.[a-zA-Z0-9_]+\.local$", re.IGNORECASE),
]

# 安全（非敏感）键名模式
SAFE_KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^(debug|verbose|mode|env|environment)$", re.IGNORECASE),
    re.compile(r"^(port|host|domain|url|endpoint)$", re.IGNORECASE),
    re.compile(r"^(version|name|author)$", re.IGNORECASE),
    re.compile(r"^(log[_\-]?level|timezone)$", re.IGNORECASE),
]
