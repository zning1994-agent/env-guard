"""环境变量文件扫描器"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from env_guard.constants import (
    ENV_FILENAME_PATTERNS,
    HIGH_RISK_KEYWORDS,
    LEAK_PATTERNS,
    SENSITIVE_KEY_PATTERNS,
)


class RiskLevel(Enum):
    """风险等级枚举"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class SensitiveEntry:
    """敏感信息条目"""
    key: str
    value: str  # 自动脱敏后的值
    line_number: int
    risk_level: RiskLevel
    matched_pattern: str
    file_path: Path
    context: Optional[str] = None  # 上下文信息
    
    @property
    def masked_value(self) -> str:
        """返回脱敏后的值"""
        if len(self.value) <= 4:
            return "*" * len(self.value)
        # 保留前两位和后两位
        return self.value[:2] + "*" * (len(self.value) - 4) + self.value[-2:]


@dataclass
class ScanResult:
    """扫描结果"""
    file_path: Path
    entries: list[SensitiveEntry] = field(default_factory=list)
    total_lines: int = 0
    is_empty: bool = False
    parse_error: Optional[str] = None


@dataclass
class ScanSummary:
    """扫描汇总"""
    total_files: int = 0
    total_entries: int = 0
    files_with_secrets: int = 0
    risk_counts: dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
    })


class EnvScanner:
    """环境变量文件扫描器"""
    
    def __init__(self, exclude_patterns: Optional[list[str]] = None):
        """
        初始化扫描器
        
        Args:
            exclude_patterns: 排除的文件模式列表
        """
        self._key_patterns = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_KEY_PATTERNS]
        self._leak_patterns = [re.compile(p) for p in LEAK_PATTERNS]
        self._env_patterns = [re.compile(p) for p in ENV_FILENAME_PATTERNS]
        self._exclude_patterns = exclude_patterns or []
    
    def is_env_file(self, path: Path) -> bool:
        """检查文件是否为环境变量文件"""
        name = path.name
        for pattern in self._env_patterns:
            if pattern.match(name):
                return True
        return False
    
    def scan_file(self, path: Path) -> ScanResult:
        """
        扫描单个环境变量文件
        
        Args:
            path: 文件路径
            
        Returns:
            ScanResult: 扫描结果
        """
        result = ScanResult(file_path=path)
        
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            result.parse_error = str(e)
            return result
        
        result.total_lines = len(lines)
        
        if result.total_lines == 0:
            result.is_empty = True
            return result
        
        for line_num, line in enumerate(lines, start=1):
            entry = self._parse_line(line, line_num, path)
            if entry:
                result.entries.append(entry)
        
        return result
    
    def _parse_line(self, line: str, line_num: int, file_path: Path) -> Optional[SensitiveEntry]:
        """解析单行内容"""
        line = line.strip()
        
        # 跳过注释和空行
        if not line or line.startswith("#"):
            return None
        
        # 解析 KEY=VALUE 格式
        if "=" not in line:
            return None
        
        # 处理多等号的情况（值中包含等号）
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        
        # 移除引号
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        
        # 检查键名是否敏感
        risk_level, matched_pattern = self._check_key_sensitivity(key)
        
        if risk_level:
            return SensitiveEntry(
                key=key,
                value=value,
                line_number=line_num,
                risk_level=risk_level,
                matched_pattern=matched_pattern,
                file_path=file_path,
            )
        
        # 检查值是否包含泄露模式
        if self._check_value_leak(value):
            return SensitiveEntry(
                key=key,
                value=value,
                line_number=line_num,
                risk_level=RiskLevel.CRITICAL,
                matched_pattern="value_contains_secret",
                file_path=file_path,
            )
        
        return None
    
    def _check_key_sensitivity(self, key: str) -> tuple[Optional[RiskLevel], str]:
        """检查键名的敏感程度"""
        key_lower = key.lower()
        
        # 先检查高风险关键词（完全匹配）
        for keyword in HIGH_RISK_KEYWORDS:
            if keyword.lower() in key_lower:
                return RiskLevel.HIGH, f"high_risk_keyword:{keyword}"
        
        # 检查正则模式匹配
        for i, pattern in enumerate(self._key_patterns):
            if pattern.match(key):
                if i < 3:  # 前三个是最严格的模式
                    return RiskLevel.CRITICAL, f"pattern:{pattern.pattern}"
                elif i < 5:  # 接下来两个是高风险
                    return RiskLevel.HIGH, f"pattern:{pattern.pattern}"
                else:
                    return RiskLevel.MEDIUM, f"pattern:{pattern.pattern}"
        
        return None, ""
    
    def _check_value_leak(self, value: str) -> bool:
        """检查值是否包含泄露模式"""
        for pattern in self._leak_patterns:
            if pattern.search(value):
                return True
        return False
    
    def scan_directory(self, root: Path) -> tuple[list[ScanResult], ScanSummary]:
        """
        递归扫描目录下所有环境变量文件
        
        Args:
            root: 根目录路径
            
        Returns:
            (扫描结果列表, 汇总信息)
        """
        results: list[ScanResult] = []
        summary = ScanSummary()
        
        exclude_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}
        
        for path in root.rglob("*"):
            # 跳过目录
            if path.is_dir():
                continue
            
            # 跳过排除的目录
            if any(excluded in path.parts for excluded in exclude_dirs):
                continue
            
            # 检查排除模式
            if any(pattern in str(path) for pattern in self._exclude_patterns):
                continue
            
            # 只扫描环境变量文件
            if not self.is_env_file(path):
                continue
            
            result = self.scan_file(path)
            results.append(result)
            
            # 更新汇总
            summary.total_files += 1
            if result.entries:
                summary.files_with_secrets += 1
                summary.total_entries += len(result.entries)
                for entry in result.entries:
                    summary.risk_counts[entry.risk_level.value] += 1
        
        return results, summary


# 便捷函数
def scan_env_files(path: Path, exclude_patterns: Optional[list[str]] = None) -> tuple[list[ScanResult], ScanSummary]:
    """扫描环境变量文件的便捷函数"""
    scanner = EnvScanner(exclude_patterns=exclude_patterns)
    return scanner.scan_directory(path)
