"""env-guard - .env 文件扫描器和敏感信息检测"""

import re
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator, List, Optional, Pattern


class SensitivityLevel(Enum):
    """敏感级别枚举"""
    CRITICAL = "critical"  # 高风险
    HIGH = "high"         # 高敏感
    MEDIUM = "medium"     # 中等敏感
    LOW = "low"           # 低敏感


@dataclass
class SensitiveEntry:
    """敏感条目数据类"""
    key: str
    value: str
    line_number: int
    sensitivity_level: SensitivityLevel
    matched_pattern: str
    file_path: Path
    is_likely_secret: bool = True
    
    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            "key": self.key,
            "value": self._mask_value(),
            "line_number": self.line_number,
            "sensitivity_level": self.sensitivity_level.value,
            "matched_pattern": self.matched_pattern,
            "file_path": str(self.file_path),
            "is_likely_secret": self.is_likely_secret,
        }
    
    def _mask_value(self) -> str:
        """遮蔽敏感值，只显示前后各2个字符"""
        if len(self.value) <= 4:
            return "*" * len(self.value)
        return self.value[:2] + "*" * (len(self.value) - 4) + self.value[-2:]


@dataclass
class ScanResult:
    """扫描结果数据类"""
    file_path: Path
    entries: List[SensitiveEntry] = field(default_factory=list)
    total_lines: int = 0
    error_message: Optional[str] = None
    
    @property
    def has_secrets(self) -> bool:
        """是否有检测到敏感信息"""
        return len(self.entries) > 0
    
    @property
    def critical_count(self) -> int:
        """高风险条目数量"""
        return sum(1 for e in self.entries if e.sensitivity_level == SensitivityLevel.CRITICAL)
    
    @property
    def high_count(self) -> int:
        """高敏感条目数量"""
        return sum(1 for e in self.entries if e.sensitivity_level == SensitivityLevel.HIGH)


class EnvScanner:
    """.env 文件扫描器"""
    
    def __init__(self, sensitive_patterns: Optional[List[Pattern]] = None):
        """
        初始化扫描器
        
        Args:
            sensitive_patterns: 自定义的敏感键名模式列表
        """
        from .constants import SENSITIVE_KEY_PATTERNS
        self._patterns = sensitive_patterns or SENSITIVE_KEY_PATTERNS
    
    def scan_file(self, path: Path) -> ScanResult:
        """
        扫描单个 .env 文件
        
        Args:
            path: .env 文件路径
            
        Returns:
            ScanResult: 扫描结果
        """
        result = ScanResult(file_path=path)
        
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                result.total_lines = len(lines)
                
                for line_num, line in enumerate(lines, start=1):
                    entry = self._parse_line(line, line_num, path)
                    if entry:
                        result.entries.append(entry)
                        
        except FileNotFoundError:
            result.error_message = f"文件不存在: {path}"
        except PermissionError:
            result.error_message = f"权限不足，无法读取: {path}"
        except Exception as e:
            result.error_message = f"读取文件出错: {str(e)}"
            
        return result
    
    def scan_directory(self, root: Path, recursive: bool = True) -> List[ScanResult]:
        """
        扫描目录下所有 .env 文件
        
        Args:
            root: 根目录路径
            recursive: 是否递归扫描子目录
            
        Returns:
            List[ScanResult]: 所有文件的扫描结果列表
        """
        from .constants import ENV_FILENAME_PATTERNS
        
        results = []
        
        # 使用 glob 匹配 .env 文件
        if recursive:
            patterns = [f"**/{p}" for p in ENV_FILENAME_PATTERNS]
        else:
            patterns = ENV_FILENAME_PATTERNS
            
        for pattern in patterns:
            for env_file in root.glob(pattern):
                if env_file.is_file():
                    # 排除 node_modules 和 .git 目录
                    if self._should_exclude(env_file):
                        continue
                    results.append(self.scan_file(env_file))
        
        return results
    
    def scan_content(self, content: str, file_path: Path = Path("stream")) -> ScanResult:
        """
        扫描字符串内容（用于 stdin 或内存内容）
        
        Args:
            content: .env 文件内容
            file_path: 虚拟文件路径
            
        Returns:
            ScanResult: 扫描结果
        """
        result = ScanResult(file_path=file_path)
        lines = content.splitlines()
        result.total_lines = len(lines)
        
        for line_num, line in enumerate(lines, start=1):
            entry = self._parse_line(line, line_num, file_path)
            if entry:
                result.entries.append(entry)
                
        return result
    
    def _parse_line(self, line: str, line_num: int, file_path: Path) -> Optional[SensitiveEntry]:
        """
        解析单行内容，检测敏感信息
        
        Args:
            line: 行内容
            line_num: 行号
            file_path: 文件路径
            
        Returns:
            Optional[SensitiveEntry]: 敏感条目或 None
        """
        # 去除首尾空白
        line = line.strip()
        
        # 跳过空行
        if not line:
            return None
            
        # 跳过注释行
        if self._is_comment(line):
            return None
        
        # 解析 key=value 格式
        key, value = self._parse_key_value(line)
        if not key:
            return None
        
        # 检查是否匹配敏感键名模式
        for pattern in self._patterns:
            if pattern.search(key):
                sensitivity = self._determine_sensitivity(key)
                return SensitiveEntry(
                    key=key,
                    value=value,
                    line_number=line_num,
                    sensitivity_level=sensitivity,
                    matched_pattern=pattern.pattern,
                    file_path=file_path,
                    is_likely_secret=True,
                )
        
        return None
    
    def _is_comment(self, line: str) -> bool:
        """检查是否为注释行"""
        from .constants import COMMENT_SYMBOLS
        for symbol in COMMENT_SYMBOLS:
            if line.startswith(symbol):
                return True
        return False
    
    def _parse_key_value(self, line: str) -> tuple:
        """
        解析 key=value 格式
        
        Args:
            line: 行内容
            
        Returns:
            tuple: (key, value)
        """
        from .constants import QUOTE_SYMBOLS
        
        # 支持多种分隔符
        for sep in ["=", ":", " "]:
            if sep in line:
                parts = line.split(sep, 1)
                key = parts[0].strip()
                value = parts[1].strip() if len(parts) > 1 else ""
                
                # 去除引号
                for quote in QUOTE_SYMBOLS:
                    if value.startswith(quote) and value.endswith(quote):
                        value = value[1:-1]
                        break
                        
                return key, value
                
        return "", ""
    
    def _determine_sensitivity(self, key: str) -> SensitivityLevel:
        """根据键名确定敏感级别"""
        from .constants import HIGH_RISK_KEYWORDS
        
        key_lower = key.lower()
        
        # 高风险关键词
        for keyword in HIGH_RISK_KEYWORDS:
            if keyword in key_lower:
                return SensitivityLevel.CRITICAL
        
        # 包含 private key
        if "private" in key_lower and "key" in key_lower:
            return SensitivityLevel.CRITICAL
            
        # 包含 token
        if "token" in key_lower:
            return SensitivityLevel.HIGH
            
        # 包含 secret
        if "secret" in key_lower:
            return SensitivityLevel.HIGH
            
        return SensitivityLevel.MEDIUM
    
    def _should_exclude(self, path: Path) -> bool:
        """检查是否应该排除该文件"""
        path_str = str(path)
        exclude_dirs = ["node_modules", ".git", "__pycache__", ".venv", "venv"]
        
        for exclude_dir in exclude_dirs:
            if f"/{exclude_dir}/" in path_str or path_str.endswith(f"/{exclude_dir}"):
                return True
        return False


class LeakScanner:
    """泄露模式扫描器 - 直接扫描文件内容中的泄露模式"""
    
    def __init__(self, patterns: Optional[List[Pattern]] = None):
        """
        初始化泄露扫描器
        
        Args:
            patterns: 自定义的泄露模式列表
        """
        from .constants import LEAK_PATTERNS
        self._patterns = patterns or LEAK_PATTERNS
    
    def scan_file(self, path: Path) -> List[SensitiveEntry]:
        """
        扫描文件中的泄露模式
        
        Args:
            path: 文件路径
            
        Returns:
            List[SensitiveEntry]: 检测到的泄露条目列表
        """
        entries = []
        
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
                entries = self.scan_content(content, path)
        except Exception:
            pass
            
        return entries
    
    def scan_content(self, content: str, file_path: Path = Path("stream")) -> List[SensitiveEntry]:
        """
        扫描内容中的泄露模式
        
        Args:
            content: 文件内容
            file_path: 虚拟文件路径
            
        Returns:
            List[SensitiveEntry]: 检测到的泄露条目列表
        """
        entries = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, start=1):
            for pattern in self._patterns:
                matches = list(pattern.finditer(line))
                for match in matches:
                    entries.append(SensitiveEntry(
                        key=self._identify_key_from_context(line, match.start()),
                        value=match.group(),
                        line_number=line_num,
                        sensitivity_level=SensitivityLevel.CRITICAL,
                        matched_pattern=pattern.pattern,
                        file_path=file_path,
                        is_likely_secret=True,
                    ))
                    
        return entries
    
    def _identify_key_from_context(self, line: str, match_pos: int) -> str:
        """从匹配位置附近识别可能的键名"""
        # 向前查找键名
        start = max(0, match_pos - 50)
        context = line[start:match_pos]
        
        # 尝试找到 = 或 : 前面的键名
        for sep in ["=", ":"]:
            if sep in context:
                parts = context.rsplit(sep, 1)
                if len(parts) > 1:
                    key = parts[1].strip()
                    # 去除可能的引号
                    for quote in ['"', "'"]:
                        if key.startswith(quote):
                            key = key[1:].strip()
                    if key:
                        return key
        
        # 如果找不到，返回通用标识
        return "detected_secret"


def scan_env_files(
    root: Path,
    recursive: bool = True,
    include_leaks: bool = True
) -> List[ScanResult]:
    """
    便捷函数：扫描目录下所有 .env 文件
    
    Args:
        root: 根目录路径
        recursive: 是否递归扫描
        include_leaks: 是否包含泄露模式扫描
        
    Returns:
        List[ScanResult]: 扫描结果列表
    """
    scanner = EnvScanner()
    results = scanner.scan_directory(root, recursive)
    
    if include_leaks:
        leak_scanner = LeakScanner()
        for result in results:
            leaks = leak_scanner.scan_file(result.file_path)
            # 合并泄露条目到结果中
            for leak in leaks:
                if not any(
                    e.line_number == leak.line_number and e.key == leak.key
                    for e in result.entries
                ):
                    result.entries.append(leak)
    
    return results
