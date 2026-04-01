"""数据模型定义"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    """严重程度枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecretType(Enum):
    """敏感信息类型枚举"""
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"
    DATABASE_CREDENTIALS = "database_credentials"
    AWS_CREDENTIALS = "aws_credentials"
    GENERIC_SECRET = "generic_secret"
    SENSITIVE_VALUE = "sensitive_value"


@dataclass
class SensitiveEntry:
    """敏感条目"""
    file_path: Path
    line_number: int
    key: str
    value_preview: str
    severity: Severity = Severity.HIGH
    secret_type: SecretType = SecretType.GENERIC_SECRET
    suggestion: Optional[str] = None

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "key": self.key,
            "value_preview": self.value_preview,
            "severity": self.severity.value,
            "secret_type": self.secret_type.value,
            "suggestion": self.suggestion,
        }


@dataclass
class ValidationResult:
    """验证结果"""
    is_valid: bool
    file_path: Path
    message: str
    rule_name: Optional[str] = None
    suggestion: Optional[str] = None

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "is_valid": self.is_valid,
            "file_path": str(self.file_path),
            "message": self.message,
            "rule_name": self.rule_name,
            "suggestion": self.suggestion,
        }


@dataclass
class ScanResult:
    """扫描结果"""
    file_path: Path
    total_lines: int = 0
    sensitive_entries: list[SensitiveEntry] = field(default_factory=list)
    is_empty: bool = False
    is_binary: bool = False

    @property
    def risk_level(self) -> Severity:
        """计算风险等级"""
        if not self.sensitive_entries:
            return Severity.LOW
        max_severity = max(e.severity for e in self.sensitive_entries)
        count = len(self.sensitive_entries)
        if count >= 5 or max_severity == Severity.CRITICAL:
            return Severity.CRITICAL
        elif count >= 3 or max_severity == Severity.HIGH:
            return Severity.HIGH
        elif count >= 1 or max_severity == Severity.MEDIUM:
            return Severity.MEDIUM
        return Severity.LOW

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "file_path": str(self.file_path),
            "total_lines": self.total_lines,
            "sensitive_entries": [e.to_dict() for e in self.sensitive_entries],
            "is_empty": self.is_empty,
            "is_binary": self.is_binary,
            "risk_level": self.risk_level.value,
        }


@dataclass
class GitignoreValidationResult:
    """Gitignore 验证结果"""
    path: Path
    is_correct: bool
    has_env_rules: bool
    missing_rules: list[str] = field(default_factory=list)
    incorrect_rules: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "path": str(self.path),
            "is_correct": self.is_correct,
            "has_env_rules": self.has_env_rules,
            "missing_rules": self.missing_rules,
            "incorrect_rules": self.incorrect_rules,
            "suggestions": self.suggestions,
        }
