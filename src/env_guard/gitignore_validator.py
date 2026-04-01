"""env-guard .gitignore 验证器"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from env_guard.models import (
    ValidationIssue,
    ValidationResult,
    ValidationStatus,
)


class GitignoreValidator:
    """验证 .gitignore 配置"""

    # 需要被 .gitignore 排除的 .env 相关文件模式
    REQUIRED_PATTERNS: list[str] = [
        ".env",
        ".env.local",
        ".env.*.local",
    ]

    # 敏感文件模式
    SENSITIVE_PATTERNS: list[str] = [
        "*.pem",
        "*.key",
        "credentials.json",
        "secrets.yaml",
        "*.secret",
    ]

    # 可能意外提交的配置文件
    CONFIG_PATTERNS: list[str] = [
        "config.py",
        "settings.py",
        "*.config.js",
        "*.config.ts",
    ]

    def __init__(self) -> None:
        self._env_pattern = re.compile(r"^\.env(\..+)?$|\.env(\..+)?\.local$")

    def validate(self, root: Path) -> ValidationResult:
        """验证 .gitignore 配置

        Args:
            root: 项目根目录

        Returns:
            ValidationResult: 验证结果
        """
        gitignore_path = root / ".gitignore"
        issues: list[ValidationIssue] = []
        checked_files: list[str] = []

        # 检查 .gitignore 是否存在
        if not gitignore_path.exists():
            issues.append(
                ValidationIssue(
                    rule="gitignore_exists",
                    status=ValidationStatus.MISSING,
                    message=".gitignore 文件不存在",
                    file_path=str(gitignore_path),
                    suggestion=self._generate_gitignore_suggestion(),
                )
            )
            # 即使没有 .gitignore，也检查是否有 .env 文件需要保护
            result = ValidationResult(
                is_valid=False,
                issues=issues,
                checked_files=checked_files,
            )
            self._check_env_files_without_gitignore(root, issues)
            return result

        checked_files.append(str(gitignore_path))

        # 读取并解析 .gitignore
        try:
            content = gitignore_path.read_text(encoding="utf-8")
            lines = [
                line.strip()
                for line in content.split("\n")
                if line.strip() and not line.strip().startswith("#")
            ]
        except Exception as e:
            issues.append(
                ValidationIssue(
                    rule="gitignore_readable",
                    status=ValidationStatus.INVALID,
                    message=f"无法读取 .gitignore: {e}",
                    file_path=str(gitignore_path),
                )
            )
            return ValidationResult(is_valid=False, issues=issues)

        # 检查 .env 相关规则
        self._check_env_patterns(lines, issues)

        # 检查敏感文件规则
        self._check_sensitive_patterns(lines, issues)

        # 检查配置文件的忽略规则
        self._check_config_patterns(lines, issues)

        # 检查是否有排除 .env 但又强制添加的情况
        self._check_negated_patterns(lines, issues, content)

        # 检查项目中的 .env 文件
        env_files = self._find_env_files(root)
        checked_files.extend([str(f) for f in env_files])

        # 如果存在 .env 文件但没有被正确忽略
        if env_files:
            self._check_env_files_coverage(lines, env_files, issues)

        is_valid = not any(
            i.status in (ValidationStatus.INVALID, ValidationStatus.MISSING)
            for i in issues
        )

        return ValidationResult(
            is_valid=is_valid,
            issues=issues,
            checked_files=checked_files,
        )

    def _check_env_patterns(
        self, lines: list[str], issues: list[ValidationIssue]
    ) -> None:
        """检查 .env 相关模式"""
        has_basic_env = False
        has_local = False

        for line in lines:
            line_lower = line.lower()
            # 检查基本 .env 规则
            if self._env_pattern.match(line_lower):
                has_basic_env = True
            # 检查 .env.local 规则
            if ".env.local" in line_lower or ".env.*.local" in line_lower:
                has_local = True

        if not has_basic_env:
            issues.append(
                ValidationIssue(
                    rule="env_pattern",
                    status=ValidationStatus.INVALID,
                    message="缺少 .env 文件的忽略规则",
                    suggestion='添加 ".env" 到 .gitignore',
                )
            )

        if not has_local:
            issues.append(
                ValidationIssue(
                    rule="env_local_pattern",
                    status=ValidationStatus.WARNING,
                    message="缺少 .env.local 文件的忽略规则",
                    suggestion='添加 ".env.local" 或 ".env.*.local" 到 .gitignore',
                )
            )

    def _check_sensitive_patterns(
        self, lines: list[str], issues: list[ValidationIssue]
    ) -> None:
        """检查敏感文件模式"""
        missing_patterns: list[str] = []

        for pattern in self.SENSITIVE_PATTERNS:
            pattern_lower = pattern.lower()
            if not any(
                pattern_lower in line.lower() for line in lines
            ):
                missing_patterns.append(pattern)

        if missing_patterns:
            issues.append(
                ValidationIssue(
                    rule="sensitive_patterns",
                    status=ValidationStatus.WARNING,
                    message=f"建议添加敏感文件的忽略规则: {', '.join(missing_patterns)}",
                    suggestion="\n".join(f'添加 "{p}"' for p in missing_patterns),
                )
            )

    def _check_config_patterns(
        self, lines: list[str], issues: list[ValidationIssue]
    ) -> None:
        """检查配置文件模式"""
        # 这是一个可选检查，不添加严重问题
        pass

    def _check_negated_patterns(
        self,
        lines: list[str],
        issues: list[ValidationIssue],
        full_content: str,
    ) -> None:
        """检查否定模式（如 !.env.example）"""
        for line in lines:
            if line.startswith("!"):
                negated = line[1:]
                if ".env" in negated.lower():
                    issues.append(
                        ValidationIssue(
                            rule="negated_pattern",
                            status=ValidationStatus.INVALID,
                            message=f"发现否定模式 '{line}'，这可能导致敏感文件被提交",
                            suggestion=f"移除 '{line}' 或确保不覆盖敏感文件规则",
                        )
                    )

    def _check_env_files_coverage(
        self,
        lines: list[str],
        env_files: list[Path],
        issues: list[ValidationIssue],
    ) -> None:
        """检查 .env 文件是否被正确覆盖"""
        # 简化检查：如果有 *.env* 或类似的通配符规则，应该没问题
        has_wildcard = any("*" in line and ".env" in line.lower() for line in lines)

        if not has_wildcard and env_files:
            issues.append(
                ValidationIssue(
                    rule="env_files_coverage",
                    status=ValidationStatus.WARNING,
                    message=f"项目中存在 {len(env_files)} 个 .env 文件，请确保它们被正确忽略",
                    file_path=", ".join(str(f) for f in env_files[:5]),
                )
            )

    def _check_env_files_without_gitignore(
        self, root: Path, issues: list[ValidationIssue]
    ) -> None:
        """在没有 .gitignore 的情况下检查 .env 文件"""
        env_files = self._find_env_files(root)
        if env_files:
            issues.append(
                ValidationIssue(
                    rule="env_files_exist",
                    status=ValidationStatus.CRITICAL,
                    message=f"发现 {len(env_files)} 个 .env 文件，但 .gitignore 不存在！",
                    file_path=", ".join(str(f) for f in env_files[:5]),
                    suggestion=self._generate_gitignore_suggestion(),
                )
            )

    def _find_env_files(self, root: Path) -> list[Path]:
        """查找目录下的 .env 文件"""
        env_files: list[Path] = []
        patterns = [
            ".env",
            ".env.local",
            ".env.*",
            "*.env",
        ]

        for pattern in patterns:
            if pattern.startswith("*"):
                for path in root.rglob(pattern):
                    if path.is_file() and path.name.startswith(".env"):
                        env_files.append(path)
            else:
                path = root / pattern
                if path.exists() and path.is_file():
                    env_files.append(path)

        return list(set(env_files))  # 去重

    def _generate_gitignore_suggestion(self) -> str:
        """生成 .gitignore 建议内容"""
        return """# .env files
.env
.env.local
.env.*.local

# Sensitive files
*.pem
*.key
credentials.json
secrets.yaml

# IDE
.idea/
.vscode/

# OS
.DS_Store
Thumbs.db
"""

    def generate_gitignore(self, root: Path) -> Path:
        """生成标准的 .gitignore 文件"""
        gitignore_path = root / ".gitignore"

        # 读取现有的 .gitignore
        existing_content = ""
        if gitignore_path.exists():
            try:
                existing_content = gitignore_path.read_text(encoding="utf-8")
            except Exception:
                existing_content = ""

        # 追加 env-guard 建议的规则
        new_content = existing_content.rstrip("\n")

        if new_content:
            new_content += "\n\n# === env-guard additions ===\n"
        else:
            new_content = "# === env-guard additions ===\n"

        new_content += self._generate_gitignore_suggestion()

        gitignore_path.write_text(new_content, encoding="utf-8")
        return gitignore_path
