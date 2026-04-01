"""敏感信息检测相关的常量定义."""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Pattern

# ============================================================
# 敏感键名模式（正则表达式）
# ============================================================

SENSITIVE_KEY_PATTERNS: list[Pattern[str]] = [
    re.compile(r"^(api[_-]?key|apikey)$", re.IGNORECASE),
    re.compile(r"^(secret|password|passwd|pwd)$", re.IGNORECASE),
    re.compile(r"^(token|auth|bearer|jwt)$", re.IGNORECASE),
    re.compile(r"^(private[_-]?key|privkey)$", re.IGNORECASE),
    re.compile(r"^(access[_-]?key|aws[_-]?key)$", re.IGNORECASE),
    re.compile(r"^.*(credential|secret|token|key).*$", re.IGNORECASE),
]

# ============================================================
# 常见泄露模式（用于检测 git history 中的敏感信息）
# ============================================================

LEAK_PATTERNS: list[Pattern[str]] = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),  # OpenAI API key
    re.compile(r"ghp_[a-zA-Z0-9]{36,}"),  # GitHub PAT
    re.compile(r"ghs_[a-zA-Z0-9]{36,}"),  # GitHub Fine-grained PAT
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
    re.compile(r"[a-zA-Z0-9/+=]{40,}")

]

# ============================================================
# 高风险关键词（用于快速匹配）
# ============================================================

HIGH_RISK_KEYWORDS: set[str] = {
    "api_key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "pwd",
    "token",
    "private_key",
    "privatekey",
    "aws_access_key",
    "aws_secret_key",
    "ghp_",  # GitHub PAT prefix
    "sk-",  # OpenAI key prefix
}

# ============================================================
# .env 文件名模式
# ============================================================

ENV_FILENAME_PATTERNS: list[Pattern[str]] = [
    re.compile(r"^\.env$", re.IGNORECASE),
    re.compile(r"^\.env\.[a-zA-Z0-9_-]+$", re.IGNORECASE),
    re.compile(r"^\.envrc$", re.IGNORECASE),
]


class SensitivityLevel(Enum):
    """敏感等级枚举."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class SensitiveEntry:
    """敏感信息条目."""

    key: str
    value: str  # 自动遮蔽后的值
    line_number: int
    sensitivity_level: SensitivityLevel
    matched_pattern: str
    file_path: str


@dataclass
class LeakedSecret:
    """泄露的敏感信息（用于 git history）."""

    commit_hash: str | None  # None 表示 staged files
    file_path: str
    line_number: int
    content_preview: str  # 泄露内容的预览
    sensitivity_level: SensitivityLevel
    matched_pattern: str
