"""数据模型定义"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class SeverityLevel(Enum):
    """严重程度等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecretType(Enum):
    """敏感信息类型"""
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"
    AWS_KEY = "aws_key"
    DATABASE_CREDENTIAL = "database_credential"
    UNKNOWN = "unknown"


@dataclass
class SensitiveEntry:
    """敏感信息条目"""
    key: str
    value: str
    file_path: Path
    line_number: int
    secret_type: SecretType = SecretType.UNKNOWN
    severity: SeverityLevel = SeverityLevel.MEDIUM
    masked_value: str = ""

    def __post_init__(self) -> None:
        """初始化后处理"""
        if not self.masked_value:
            self.masked_value = self._mask_value()

    def _mask_value(self) -> str:
        """掩码处理值"""
        if len(self.value) <= 8:
            return "*" * len(self.value)
        # 显示前4后4，中间掩码
        return f"{self.value[:4]}{'*' * (len(self.value) - 8)}{self.value[-4:]}"


@dataclass
class LeakedSecret:
    """泄露的敏感信息"""
    secret_type: SecretType
    severity: SeverityLevel
    file_path: Optional[Path] = None
    commit_hash: Optional[str] = None
    commit_message: Optional[str] = None
    line_content: str = ""
    matched_pattern: str = ""
    remediation: str = ""

    def __post_init__(self) -> None:
        """初始化后处理"""
        if not self.remediation:
            self.remediation = self._get_default_remediation()

    def _get_default_remediation(self) -> str:
        """获取默认修复建议"""
        remedies = {
            SecretType.API_KEY: "立即轮换 API Key 并更新到安全存储（如 Vault 或云平台密钥管理）",
            SecretType.PASSWORD: "立即更改密码并审查账户访问日志",
            SecretType.TOKEN: "撤销泄露的 Token 并生成新的",
            SecretType.PRIVATE_KEY: "撤销私钥并生成新的密钥对",
            SecretType.AWS_KEY: "在 AWS IAM 控制台撤销密钥并创建新的访问密钥",
            SecretType.DATABASE_CREDENTIAL: "更新数据库密码并检查是否有异常访问",
            SecretType.UNKNOWN: "立即检查并移除暴露的敏感信息",
        }
        return remedies.get(self.secret_type, "检查并移除暴露的敏感信息")


@dataclass
class ValidationResult:
    """验证结果"""
    is_valid: bool
    file_path: Path
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """扫描结果汇总"""
    total_files: int = 0
    sensitive_entries: list[SensitiveEntry] = field(default_factory=list)
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0

    @property
    def has_issues(self) -> bool:
        """是否有安全问题"""
        return len(self.sensitive_entries) > 0

    @property
    def critical_count(self) -> int:
        """严重问题数量"""
        return sum(1 for e in self.sensitive_entries if e.severity == SeverityLevel.CRITICAL)
