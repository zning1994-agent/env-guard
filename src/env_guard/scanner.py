"""env-guard .env 文件扫描器"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from env_guard.constants import (
    ENV_FILENAME_PATTERNS,
    EXCLUDED_DIRS,
    HIGH_RISK_KEYWORDS,
    LEAK_PATTERNS,
    SENSITIVE_KEY_PATTERNS,
)
from env_guard.models import (
    ScanResult,
    SensitivityLevel,
    SensitiveEntry,
)


class EnvScanner:
    """扫描 .env 文件并识别敏感信息"""

    def __init__(self) -> None:
        self._leak_regexes = [re.compile(p.pattern) for p in LEAK_PATTERNS]

    def scan_file(self, path: Path) -> list[SensitiveEntry]:
        """扫描单个 .env 文件"""
        entries: list[SensitiveEntry] = []

        if not path.exists():
            return entries

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return entries

        lines = content.split("\n")
        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # 解析 key=value 格式
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                # 移除引号
                if value and len(value) >= 2:
                    if (value[0] == '"' and value[-1] == '"') or (
                        value[0] == "'" and value[-1] == "'"
                    ):
                        value = value[1:-1]

                # 检查键名是否敏感
                level = self._check_key_sensitivity(key)
                if level:
                    entries.append(
                        SensitiveEntry(
                            key=key,
                            value=value,
                            line_number=line_num,
                            sensitivity_level=level,
                            matched_pattern=self._get_key_pattern_name(level),
                            file_path=str(path),
                        )
                    )

                # 检查值是否包含泄露模式
                for regex, pattern_info in zip(self._leak_regexes, LEAK_PATTERNS):
                    if regex.search(value):
                        entries.append(
                            SensitiveEntry(
                                key=key,
                                value=value,
                                line_number=line_num,
                                sensitivity_level=SensitivityLevel.CRITICAL,
                                matched_pattern=pattern_info.description,
                                file_path=str(path),
                            )
                        )

                # 检查高风险关键词
                for keyword in HIGH_RISK_KEYWORDS:
                    if keyword.lower() in line.lower():
                        entries.append(
                            SensitiveEntry(
                                key=key,
                                value=value,
                                line_number=line_num,
                                sensitivity_level=SensitivityLevel.CRITICAL,
                                matched_pattern=f"High-risk keyword: {keyword}",
                                file_path=str(path),
                            )
                        )

        return entries

    def scan_directory(self, root: Path) -> ScanResult:
        """递归扫描目录下所有 .env 文件"""
        result = ScanResult()
        env_files = self._find_env_files(root)

        for env_file in env_files:
            entries = self.scan_file(env_file)
            result.sensitive_entries.extend(entries)
            result.scanned_files.append(str(env_file))

            # 统计行数
            try:
                result.total_lines_scanned += len(
                    env_file.read_text(encoding="utf-8", errors="ignore").split("\n")
                )
            except Exception:
                pass

        return result

    def scan_content(self, content: str) -> list[SensitiveEntry]:
        """扫描字符串内容中的敏感信息"""
        entries: list[SensitiveEntry] = []

        lines = content.split("\n")
        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                # 移除引号
                if value and len(value) >= 2:
                    if (value[0] == '"' and value[-1] == '"') or (
                        value[0] == "'" and value[-1] == "'"
                    ):
                        value = value[1:-1]

                level = self._check_key_sensitivity(key)
                if level:
                    entries.append(
                        SensitiveEntry(
                            key=key,
                            value=value,
                            line_number=line_num,
                            sensitivity_level=level,
                            matched_pattern=self._get_key_pattern_name(level),
                            file_path="<content>",
                        )
                    )

        return entries

    def _find_env_files(self, root: Path) -> Iterator[Path]:
        """查找目录下的 .env 文件"""
        for pattern in ENV_FILENAME_PATTERNS:
            if pattern.startswith("*."):
                # 通配符模式，如 *.env
                suffix = pattern[1:]
                for path in root.rglob(f"*{suffix}"):
                    if path.is_file() and not self._is_excluded(path):
                        yield path
            else:
                # 精确匹配
                path = root / pattern
                if path.exists() and path.is_file():
                    yield path

    def _is_excluded(self, path: Path) -> bool:
        """检查路径是否应该被排除"""
        parts = path.parts
        for excluded in EXCLUDED_DIRS:
            if excluded in parts:
                return True
        return False

    def _check_key_sensitivity(self, key: str) -> SensitivityLevel | None:
        """检查键名的敏感等级"""
        key_lower = key.lower()

        for pattern in SENSITIVE_KEY_PATTERNS:
            if pattern.match(key):
                # 根据模式确定敏感等级
                pattern_str = pattern.pattern
                if any(
                    p in pattern_str.lower()
                    for p in ["password", "secret", "key", "token"]
                ):
                    if "private" in pattern_str.lower() or "secret" in pattern_str.lower():
                        return SensitivityLevel.HIGH
                    elif "password" in pattern_str.lower():
                        return SensitivityLevel.HIGH
                    return SensitivityLevel.MEDIUM
                return SensitivityLevel.MEDIUM

        return None

    def _get_key_pattern_name(self, level: SensitivityLevel) -> str:
        """获取键名对应的模式名称"""
        names = {
            SensitivityLevel.CRITICAL: "Critical sensitive key",
            SensitivityLevel.HIGH: "High-risk sensitive key",
            SensitivityLevel.MEDIUM: "Medium-risk sensitive key",
            SensitivityLevel.LOW: "Low-risk sensitive key",
        }
        return names.get(level, "Unknown")
