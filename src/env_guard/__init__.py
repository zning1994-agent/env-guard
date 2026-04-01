"""env-guard - Git 敏感信息泄露检测与修复工具"""

__version__ = "0.1.0"
__author__ = "env-guard contributors"

from .scanner import EnvScanner, LeakScanner, SensitiveEntry, ScanResult, SensitivityLevel, scan_env_files
from .constants import (
    SENSITIVE_KEY_PATTERNS,
    LEAK_PATTERNS,
    HIGH_RISK_KEYWORDS,
    ENV_FILENAME_PATTERNS,
)

__all__ = [
    # 版本
    "__version__",
    # 扫描器
    "EnvScanner",
    "LeakScanner",
    "scan_env_files",
    # 数据类
    "SensitiveEntry",
    "ScanResult",
    "SensitivityLevel",
    # 常量
    "SENSITIVE_KEY_PATTERNS",
    "LEAK_PATTERNS",
    "HIGH_RISK_KEYWORDS",
    "ENV_FILENAME_PATTERNS",
]
