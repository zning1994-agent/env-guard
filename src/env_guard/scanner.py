"""文件扫描器 - 扫描 .env 文件并识别敏感信息."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from .constants import (
    ENV_FILENAME_PATTERNS,
    SENSITIVE_KEY_PATTERNS,
    HIGH_RISK_KEYWORDS,
    SensitivityLevel,
    SensitiveEntry,
)


class EnvScanner:
    """扫描 .env 文件并识别敏感值."""

    # 排除的目录
    EXCLUDE_DIRS: frozenset[str] = frozenset({
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        ".tox",
    })

    def __init__(self) -> None:
        """初始化扫描器."""
        self.entries: list[SensitiveEntry] = []

    def is_env_file(self, path: Path) -> bool:
        """检查路径是否匹配 .env 文件名模式."""
        name = path.name
        return any(pattern.match(name) for pattern in ENV_FILENAME_PATTERNS)

    def should_exclude_dir(self, dirname: str) -> bool:
        """检查目录是否应该被排除."""
        return dirname in self.EXCLUDE_DIRS

    def mask_value(self, value: str, visible_chars: int = 4) -> str:
        """遮蔽敏感值，只显示前 N 个字符."""
        if len(value) <= visible_chars:
            return "*" * len(value)
        return value[:visible_chars] + "*" * (len(value) - visible_chars)

    def determine_sensitivity(self, key: str) -> SensitivityLevel:
        """根据键名确定敏感等级."""
        key_lower = key.lower()

        # CRITICAL: 已知的高风险关键词
        if key_lower in HIGH_RISK_KEYWORDS:
            return SensitivityLevel.CRITICAL

        # HIGH: 匹配高风险模式
        for pattern in SENSITIVE_KEY_PATTERNS[:5]:
            if pattern.match(key):
                return SensitivityLevel.HIGH

        # MEDIUM: 匹配一般敏感模式
        for pattern in SENSITIVE_KEY_PATTERNS[5:]:
            if pattern.match(key):
                return SensitivityLevel.MEDIUM

        return SensitivityLevel.LOW

    def find_matched_pattern(self, key: str) -> str:
        """找到匹配的模式的名称."""
        for pattern in SENSITIVE_KEY_PATTERNS:
            if pattern.match(key):
                return pattern.pattern
        return "unknown"

    def scan_content(self, content: str, file_path: str) -> Iterator[SensitiveEntry]:
        """扫描内容中的敏感信息."""
        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()

            # 跳过空行和注释
            if not line or line.startswith("#"):
                continue

            # 解析 KEY=VALUE 格式
            if "=" not in line:
                continue

            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()

            # 移除可能的引号
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]

            if not key:
                continue

            # 检查是否匹配敏感键名模式
            is_sensitive = any(pattern.match(key) for pattern in SENSITIVE_KEY_PATTERNS)

            if is_sensitive:
                yield SensitiveEntry(
                    key=key,
                    value=self.mask_value(value),
                    line_number=line_num,
                    sensitivity_level=self.determine_sensitivity(key),
                    matched_pattern=self.find_matched_pattern(key),
                    file_path=file_path,
                )

    def scan_file(self, path: Path) -> list[SensitiveEntry]:
        """扫描单个 .env 文件."""
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            # 跳过无法读取的文件
            return []

        return list(self.scan_content(content, str(path)))

    def scan_directory(self, root: Path) -> list[SensitiveEntry]:
        """递归扫描目录下所有 .env 文件."""
        all_entries: list[SensitiveEntry] = []

        for path in root.rglob(".env*"):
            # 排除目录
            if path.is_dir():
                continue

            # 排除特定目录
            if any(self.should_exclude_dir(p) for p in path.parts):
                continue

            entries = self.scan_file(path)
            all_entries.extend(entries)

        return all_entries
