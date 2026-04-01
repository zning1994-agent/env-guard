"""env-guard 数据模型定义"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class SensitivityLevel(Enum):
    """敏感等级枚举"""

    CRITICAL = "CRITICAL"  # 严重：直接泄露的密钥、token 等
    HIGH = "HIGH"  # 高：密码、私钥等
    MEDIUM = "MEDIUM"  # 中：API key、access key 等
    LOW = "LOW"  # 低：可能包含敏感信息的配置


class ValidationStatus(Enum):
    """验证状态枚举"""

    VALID = "valid"  # 配置正确
    INVALID = "invalid"  # 配置错误
    MISSING = "missing"  # 缺少配置
    WARNING = "warning"  # 需要注意


@dataclass
class SensitiveEntry:
    """敏感信息条目"""

    key: str
    value: str  # 敏感值，已自动遮蔽
    line_number: int
    sensitivity_level: SensitivityLevel
    matched_pattern: str
    file_path: str

    def __post_init__(self) -> None:
        # 确保值被遮蔽
        if len(self.value) > 4:
            self.value = self.value[:2] + "*" * (len(self.value) - 4) + self.value[-2:]
        else:
            self.value = "*" * len(self.value)


@dataclass
class LeakResult:
    """泄露检测结果"""

    commit_hash: Optional[str]  # None 表示 staged files
    commit_message: Optional[str]
    file_path: str
    line_number: int
    content_preview: str  # 泄露内容预览，已遮蔽
    matched_pattern: str
    sensitivity_level: SensitivityLevel


@dataclass
class ValidationIssue:
    """验证问题"""

    rule: str
    status: ValidationStatus
    message: str
    file_path: Optional[str] = None
    suggestion: Optional[str] = None


@dataclass
class ValidationResult:
    """验证结果"""

    is_valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    checked_files: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.status == ValidationStatus.INVALID)

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.status == ValidationStatus.WARNING)


@dataclass
class ScanResult:
    """扫描结果"""

    scanned_files: list[str] = field(default_factory=list)
    sensitive_entries: list[SensitiveEntry] = field(default_factory=list)
    total_lines_scanned: int = 0

    @property
    def critical_count(self) -> int:
        return sum(
            1
            for e in self.sensitive_entries
            if e.sensitivity_level == SensitivityLevel.CRITICAL
        )

    @property
    def high_count(self) -> int:
        return sum(
            1
            for e in self.sensitive_entries
            if e.sensitivity_level == SensitivityLevel.HIGH
        )

    @property
    def has_secrets(self) -> bool:
        return len(self.sensitive_entries) > 0
