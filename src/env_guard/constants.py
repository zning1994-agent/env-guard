"""env-guard 敏感关键词和模式定义"""

import re
from typing import NamedTuple


class SensitivePattern(NamedTuple):
    """敏感模式定义"""

    pattern: str
    level: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str


# 敏感键名模式（正则表达式）
SENSITIVE_KEY_PATTERNS: list[re.Pattern[str]] = [
    # 严重级别 - 直接的密钥和 token
    re.compile(r"^(api[_-]?key|apikey)$", re.IGNORECASE),
    re.compile(r"^(secret|password|passwd|pwd)$", re.IGNORECASE),
    re.compile(r"^(token|auth|bearer|jwt)$", re.IGNORECASE),
    re.compile(r"^(private[_-]?key|privkey)$", re.IGNORECASE),
    re.compile(r"^(access[_-]?key|aws[_-]?key)$", re.IGNORECASE),
    # 高危级别
    re.compile(r"^(secret[_-]?key|secretkey)$", re.IGNORECASE),
    re.compile(r"^(client[_-]?secret)$", re.IGNORECASE),
    re.compile(r"^(encryption[_-]?key|enc[_-]?key)$", re.IGNORECASE),
    re.compile(r"^(master[_-]?key)$", re.IGNORECASE),
    # 中等级别
    re.compile(r"^.*(credential|secret|token|key).*$", re.IGNORECASE),
    re.compile(r"^(db[_-]?pass|db[_-]?password|database[_-]?pass)$", re.IGNORECASE),
    re.compile(r"^(mail[_-]?pass|smtp[_-]?pass|email[_-]?pass)$", re.IGNORECASE),
    # 低级别
    re.compile(r"^(username|user[_-]?name|login)$", re.IGNORECASE),
    re.compile(r"^(host|server|endpoint|url)$", re.IGNORECASE),
]

# 常见泄露模式（预编译正则）
LEAK_PATTERNS: list[SensitivePattern] = [
    # OpenAI API Key
    SensitivePattern(
        pattern=r"sk-[A-Za-z0-9_-]{20,}",
        level="CRITICAL",
        description="OpenAI API Key",
    ),
    # GitHub Personal Access Token
    SensitivePattern(
        pattern=r"ghp_[A-Za-z0-9]{36,}",
        level="CRITICAL",
        description="GitHub Personal Access Token",
    ),
    # GitHub OAuth Token
    SensitivePattern(
        pattern=r"gho_[A-Za-z0-9]{36,}",
        level="CRITICAL",
        description="GitHub OAuth Token",
    ),
    # AWS Access Key ID
    SensitivePattern(
        pattern=r"AKIA[0-9A-Z]{16}",
        level="CRITICAL",
        description="AWS Access Key ID",
    ),
    # AWS Secret Access Key
    SensitivePattern(
        pattern=r"[A-Za-z0-9/+=]{40}(?=['\"])",
        level="CRITICAL",
        description="AWS Secret Access Key pattern",
    ),
    # Stripe API Key
    SensitivePattern(
        pattern=r"sk_live_[A-Za-z0-9]{24,}",
        level="CRITICAL",
        description="Stripe Live API Key",
    ),
    SensitivePattern(
        pattern=r"sk_test_[A-Za-z0-9]{24,}",
        level="CRITICAL",
        description="Stripe Test API Key",
    ),
    # Slack Token
    SensitivePattern(
        pattern=r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}",
        level="CRITICAL",
        description="Slack Token",
    ),
    # Discord Token
    SensitivePattern(
        pattern=r"[A-Za-z\d]{24}\.[A-Za-z\d]{6}\.[A-Za-z_\-]{27,}",
        level="CRITICAL",
        description="Discord Token",
    ),
    # Generic API Key pattern
    SensitivePattern(
        pattern=r"['\"][A-Za-z0-9_-]{32,}['\"]",
        level="MEDIUM",
        description="Generic API Key",
    ),
]

# 高风险关键词（用于额外检测）
HIGH_RISK_KEYWORDS: list[str] = [
    "PRIVATE_KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PGP PRIVATE KEY",
    "-----END RSA PRIVATE KEY-----",
    "aws_secret_access_key",
    "google_api_key",
    "google_maps_key",
    "sendgrid_api_key",
    "mailgun_api_key",
    "twilio_api_key",
    "stripe_publishable_key",
]

# 常见的 .env 文件名模式
ENV_FILENAME_PATTERNS: list[str] = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.staging",
    ".env.production",
    ".env.test",
    ".env.example",
    ".env.sample",
    "*.env",
]

# 需要忽略扫描的目录
EXCLUDED_DIRS: set[str] = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".idea",
    ".vscode",
    "dist",
    "build",
    ".eggs",
    "*.egg-info",
}

# 常见的 gitignore 规则模板
GITIGNORE_TEMPLATES: dict[str, list[str]] = {
    "env_files": [
        "# Environment files",
        ".env",
        ".env.local",
        ".env.*.local",
    ],
    "secrets": [
        "# Secrets and credentials",
        "*.pem",
        "*.key",
        "credentials.json",
        "secrets.yaml",
        "secrets.yml",
    ],
}
