"""env-guard - Git 敏感信息泄露检测与修复工具

用于检测 .env 文件、staged files 和 git history 中的敏感信息泄露
"""

__version__ = "0.1.0"
__author__ = "env-guard"
__license__ = "MIT"

from .constants import (
    ENV_FILENAMES,
    HIGH_RISK_PATTERNS,
    LEAK_PATTERNS,
    SEVERITY_COLORS,
    SEVERITY_LEVELS,
    SENSITIVE_PATTERNS,
)
from .git_checker import (
    GitCheckResult,
    GitChecker,
    LeakedSecret,
    SecretSeverity,
    SecretType,
)

__all__ = [
    # 版本信息
    "__version__",
    # 常量
    "SENSITIVE_PATTERNS",
    "LEAK_PATTERNS",
    "ENV_FILENAMES",
    "HIGH_RISK_PATTERNS",
    "SEVERITY_LEVELS",
    "SEVERITY_COLORS",
    # Git 检查器
    "GitChecker",
    "GitCheckResult",
    "LeakedSecret",
    "SecretType",
    "SecretSeverity",
]
