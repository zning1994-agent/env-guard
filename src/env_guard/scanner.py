"""环境变量文件扫描器

扫描 .env 文件并识别敏感字段
"""

import re
from pathlib import Path
from typing import Iterator

from .constants import (
    SENSITIVE_KEY_PATTERNS,
    SAFE_KEY_PATTERNS,
    HIGH_RISK_KEYWORDS,
    LEAK_PATTERNS,
)
from .models import ScanResult, SecretType, SensitiveEntry, SeverityLevel


class EnvScanner:
    """扫描 .env 文件并识别敏感值"""

    def __init__(self, strict: bool = False) -> None:
        """
        初始化扫描器

        Args:
            strict: 严格模式，对低风险项也会报警
        """
        self.strict = strict
        self._comment_pattern = re.compile(r"^\s*#")
        self._empty_pattern = re.compile(r"^\s*$")
        self._export_pattern = re.compile(r"^\s*export\s+", re.IGNORECASE)
        self._key_value_pattern = re.compile(
            r'^[\'"]?(?P<key>[A-Za-z_][A-Za-z0-9_]*)[\'"]?\s*=\s*'
            r'[\'"]?(?P<value>.*?)[\'"]?\s*(?:#.*)?$'
        )

    def scan_file(self, path: Path) -> list[SensitiveEntry]:
        """
        扫描单个 .env 文件

        Args:
            path: .env 文件路径

        Returns:
            敏感条目列表
        """
        if not path.exists():
            return []
        if not path.is_file():
            return []

        entries: list[SensitiveEntry] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line_number, line in enumerate(f, start=1):
                    entry = self._parse_line(line, line_number, path)
                    if entry:
                        entries.append(entry)
        except (OSError, PermissionError):
            pass

        return entries

    def scan_directory(self, root: Path, recursive: bool = True) -> ScanResult:
        """
        递归扫描目录下所有 .env 文件

        Args:
            root: 根目录路径
            recursive: 是否递归扫描子目录

        Returns:
            扫描结果汇总
        """
        result = ScanResult()
        env_files = self._find_env_files(root, recursive)

        for env_file in env_files:
            entries = self.scan_file(env_file)
            result.sensitive_entries.extend(entries)
            result.total_files += 1

        # 统计风险等级
        for entry in result.sensitive_entries:
            if entry.severity == SeverityLevel.HIGH:
                result.high_risk_count += 1
            elif entry.severity == SeverityLevel.MEDIUM:
                result.medium_risk_count += 1
            elif entry.severity == SeverityLevel.LOW:
                result.low_risk_count += 1

        return result

    def scan_content(self, content: str, source_name: str = "stdin") -> list[SensitiveEntry]:
        """
        扫描字符串内容（用于测试或 stdin）

        Args:
            content: 文件内容
            source_name: 来源名称

        Returns:
            敏感条目列表
        """
        entries: list[SensitiveEntry] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            entry = self._parse_line(line, line_number, Path(source_name))
            if entry:
                entries.append(entry)
        return entries

    def is_sensitive_key(self, key: str) -> bool:
        """
        检查键名是否为敏感键

        Args:
            key: 键名

        Returns:
            是否敏感
        """
        key_lower = key.lower()

        # 先检查是否为安全键
        for pattern in SAFE_KEY_PATTERNS:
            if pattern.match(key_lower):
                return False

        # 检查是否为高风险关键词
        if key_lower in HIGH_RISK_KEYWORDS:
            return True

        # 检查是否匹配敏感模式
        for pattern in SENSITIVE_KEY_PATTERNS:
            if pattern.match(key_lower):
                return True

        return False

    def detect_secret_type(self, key: str, value: str = "") -> SecretType:
        """
        检测敏感信息类型

        Args:
            key: 键名
            value: 值（可选，用于进一步判断）

        Returns:
            敏感类型
        """
        key_lower = key.lower()

        # AWS 密钥
        if "aws" in key_lower or "access_key" in key_lower:
            return SecretType.AWS_KEY

        # API 密钥
        if "api_key" in key_lower or "apikey" in key_lower:
            return SecretType.API_KEY

        # 私钥
        if "private" in key_lower or "privkey" in key_lower:
            return SecretType.PRIVATE_KEY

        # Token
        if "token" in key_lower or "bearer" in key_lower or "jwt" in key_lower:
            return SecretType.TOKEN

        # 密码
        if "password" in key_lower or "passwd" in key_lower or "pwd" in key_lower:
            return SecretType.PASSWORD

        # 数据库凭证
        if "db_" in key_lower or "database" in key_lower or "mysql" in key_lower:
            return SecretType.DATABASE_CREDENTIAL

        # 检查值中的泄露模式
        if value:
            for pattern in LEAK_PATTERNS:
                if pattern.search(value):
                    if "AKIA" in value:
                        return SecretType.AWS_KEY
                    elif value.startswith("sk-"):
                        return SecretType.API_KEY
                    elif value.startswith("ghp_"):
                        return SecretType.API_KEY

        return SecretType.UNKNOWN

    def get_severity(self, key: str, value: str = "") -> SeverityLevel:
        """
        获取敏感级别

        Args:
            key: 键名
            value: 值

        Returns:
            严重程度
        """
        key_lower = key.lower()

        # 最高风险
        if any(k in key_lower for k in ["secret_key", "private_key", "api_key"]):
            return SeverityLevel.CRITICAL

        # 高风险
        if any(k in key_lower for k in ["password", "token", "credential", "secret"]):
            return SeverityLevel.HIGH

        # 检查值是否为空
        if not value or value.strip() == "":
            return SeverityLevel.LOW

        # 中等风险
        return SeverityLevel.MEDIUM

    def _parse_line(self, line: str, line_number: int, file_path: Path) -> SensitiveEntry | None:
        """
        解析单行内容

        Args:
            line: 行内容
            line_number: 行号
            file_path: 文件路径

        Returns:
            敏感条目，无则返回 None
        """
        stripped = line.strip()

        # 跳过注释和空行
        if self._comment_pattern.match(stripped) or self._empty_pattern.match(stripped):
            return None

        # 移除 export 前缀
        stripped = self._export_pattern.sub("", stripped)

        # 解析键值对
        match = self._key_value_pattern.match(stripped)
        if not match:
            return None

        key = match.group("key")
        value = match.group("value")

        # 检查是否为敏感键
        if not self.is_sensitive_key(key):
            return None

        # 获取敏感类型和严重程度
        secret_type = self.detect_secret_type(key, value)
        severity = self.get_severity(key, value)

        # 严格模式下，低风险也报告
        if severity == SeverityLevel.LOW and not self.strict:
            return None

        return SensitiveEntry(
            key=key,
            value=value,
            file_path=file_path,
            line_number=line_number,
            secret_type=secret_type,
            severity=severity,
        )

    def _find_env_files(self, root: Path, recursive: bool) -> Iterator[Path]:
        """
        查找目录下的 .env 文件

        Args:
            root: 根目录
            recursive: 是否递归

        Yields:
            .env 文件路径
        """
        env_pattern = re.compile(r"^\.env$|^\.env\.[a-zA-Z0-9_]+$|^\.envrc$", re.IGNORECASE)

        if recursive:
            for path in root.rglob(".env*"):
                if path.is_file() and env_pattern.match(path.name):
                    yield path
        else:
            for path in root.iterdir():
                if path.is_file() and env_pattern.match(path.name):
                    yield path
