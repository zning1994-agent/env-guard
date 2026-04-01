"""Gitignore 验证器 - 检查 .gitignore 配置是否正确保护敏感文件."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator

from .constants import ENV_FILENAME_PATTERNS


class ValidationStatus(Enum):
    """验证状态."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    MISSING = "MISSING"


@dataclass
class ValidationIssue:
    """验证问题条目."""

    rule: str
    status: ValidationStatus
    message: str
    line_number: int | None = None


@dataclass
class GitignoreValidationResult:
    """Gitignore 验证结果."""

    gitignore_path: Path | None
    status: ValidationStatus
    is_valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    existing_rules: list[str] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        """通过的检查数量."""
        return sum(1 for issue in self.issues if issue.status == ValidationStatus.PASS)

    @property
    def fail_count(self) -> int:
        """失败的检查数量."""
        return sum(1 for issue in self.issues if issue.status == ValidationStatus.FAIL)

    @property
    def warning_count(self) -> int:
        """警告数量."""
        return sum(1 for issue in self.issues if issue.status == ValidationStatus.WARNING)


class GitignoreValidator:
    """验证 .gitignore 配置是否正确保护 .env 文件."""

    # 需要保护的 .env 文件模式
    PROTECTED_PATTERNS: list[tuple[str, str]] = [
        (".env", "基础 .env 文件"),
        (".env.*", "环境特定 .env 文件"),
        (".env.local", "本地覆盖 .env 文件"),
        (".env.production", "生产环境 .env 文件"),
        (".env.development", "开发环境 .env 文件"),
        (".envrc", "direnv 配置文件"),
    ]

    # 有问题的模式（可能误报或遗漏）
    PROBLEMATIC_PATTERNS: list[tuple[str, str]] = [
        (r"env$", "以 env 结尾可能误匹配其他文件"),
        (r"\.env/", ".env/ 会匹配目录而非文件，可能遗漏"),
        (r"\.env\..*\.local", "过于具体的模式可能遗漏其他变体"),
    ]

    def __init__(self, root: Path | str = Path(".")) -> None:
        """初始化验证器.

        Args:
            root: 要验证的项目根目录
        """
        self.root = Path(root)
        self.gitignore_path = self.root / ".gitignore"

    def _parse_gitignore(self) -> Iterator[tuple[str, int]]:
        """解析 .gitignore 文件，返回 (规则, 行号) 对.

        Yields:
            (规则字符串, 行号) 元组
        """
        if not self.gitignore_path.exists():
            return

        try:
            content = self.gitignore_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return

        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()

            # 跳过空行和注释
            if not stripped or stripped.startswith("#"):
                continue

            # 移除行尾注释
            rule = stripped.split("#")[0].strip()
            if rule:
                yield rule, line_num

    def _matches_env_pattern(self, rule: str) -> bool:
        """检查规则是否匹配 .env 相关模式."""
        rule = rule.rstrip("/")  # 目录规则

        # 检查是否精确匹配已知 .env 模式
        for pattern, _ in self.PROTECTED_PATTERNS:
            if rule == pattern or rule == f"*/{pattern}" or rule == f"**/{pattern}":
                return True

        # 检查是否使用通配符匹配
        if rule.startswith(".env"):
            return True

        # 检查是否匹配正则模式
        for pattern, _ in self.PROBLEMATIC_PATTERNS:
            if re.match(pattern, rule):
                return True

        return False

    def _is_correct_rule(self, rule: str) -> bool:
        """检查规则是否正确.

        正确的规则应该是:
        - .env (精确匹配)
        - .env.* (匹配所有扩展)
        - .env.local, .env.production 等具体名称
        """
        # 精确匹配
        if rule in {".env", ".envrc"}:
            return True

        # 匹配 .env.*
        if re.match(r"^\.env\.[a-zA-Z0-9_-]+$", rule):
            return True

        # 匹配通配符形式
        if re.match(r"^(\*\*/)?\.env(\.[a-zA-Z0-9_-]+)?$", rule):
            return True

        return False

    def _has_negation(self, rule: str, all_rules: list[str]) -> bool:
        """检查是否存在对应的否定规则 (!.env.local)."""
        negation = f"!{rule}"
        return negation in all_rules

    def validate(self) -> GitignoreValidationResult:
        """验证 .gitignore 配置.

        Returns:
            验证结果
        """
        issues: list[ValidationIssue] = []
        recommendations: list[str] = []
        existing_rules: list[str] = []

        # 收集现有规则
        env_rules: dict[str, tuple[int, str]] = {}  # rule -> (line_number, original_rule)

        for rule, line_num in self._parse_gitignore():
            existing_rules.append(rule)

            if self._matches_env_pattern(rule):
                env_rules[rule] = (line_num, rule)

        # 检查 .gitignore 是否存在
        if not self.gitignore_path.exists():
            issues.append(ValidationIssue(
                rule=".gitignore",
                status=ValidationStatus.MISSING,
                message="未找到 .gitignore 文件，建议创建一个来保护敏感文件",
            ))
            recommendations.append("创建 .gitignore 文件并添加 .env 相关规则")

            return GitignoreValidationResult(
                gitignore_path=None,
                status=ValidationStatus.FAIL,
                is_valid=False,
                issues=issues,
                recommendations=recommendations,
                existing_rules=existing_rules,
            )

        # 检查是否包含 .env 规则
        if not env_rules:
            issues.append(ValidationIssue(
                rule=".env",
                status=ValidationStatus.MISSING,
                message="未找到 .env 相关规则，敏感文件可能被提交到 git",
            ))
            recommendations.append("添加 .env 和 .env.* 到 .gitignore")

            return GitignoreValidationResult(
                gitignore_path=self.gitignore_path,
                status=ValidationStatus.FAIL,
                is_valid=False,
                issues=issues,
                recommendations=recommendations,
                existing_rules=existing_rules,
            )

        # 检查每个规则是否正确
        for rule, (line_num, _) in env_rules.items():
            if self._is_correct_rule(rule):
                # 检查是否有否定规则
                if self._has_negation(rule, existing_rules):
                    issues.append(ValidationIssue(
                        rule=rule,
                        status=ValidationStatus.WARNING,
                        message=f"规则 {rule} 同时存在否定规则 !{rule}，可能已被取消忽略",
                        line_number=line_num,
                    ))
                else:
                    issues.append(ValidationIssue(
                        rule=rule,
                        status=ValidationStatus.PASS,
                        message=f"规则 {rule} 配置正确",
                        line_number=line_num,
                    ))
            else:
                issues.append(ValidationIssue(
                    rule=rule,
                    status=ValidationStatus.WARNING,
                    message=f"规则 {rule} 可能不正确，建议使用更明确的模式",
                    line_number=line_num,
                ))

        # 检查是否缺少关键规则
        has_basic_env = ".env" in env_rules or ".env*" in env_rules
        has_env_ext = any(
            re.match(r"^\.env\.[a-zA-Z0-9_-]+$", r)
            for r in env_rules
        )

        if not has_basic_env:
            issues.append(ValidationIssue(
                rule=".env",
                status=ValidationStatus.WARNING,
                message="建议添加 .env 来忽略基础环境配置文件",
            ))
            recommendations.append("添加 .env 规则以忽略基础配置文件")

        if not has_env_ext:
            issues.append(ValidationIssue(
                rule=".env.*",
                status=ValidationStatus.WARNING,
                message="建议添加 .env.* 来忽略所有环境特定的配置文件",
            ))
            recommendations.append("添加 .env.* 规则以忽略环境特定配置")

        # 检查 .env.local 是否被排除（这是本地覆盖文件，通常需要排除）
        has_local_exclusion = ".env.local" in env_rules or ".env.*" in env_rules

        if not has_local_exclusion:
            issues.append(ValidationIssue(
                rule=".env.local",
                status=ValidationStatus.WARNING,
                message=".env.local 通常包含本地敏感覆盖值，建议排除",
            ))
            recommendations.append("添加 .env.local 或确保 .env.* 能匹配它")

        # 确定最终状态
        has_fail = any(issue.status in (ValidationStatus.FAIL, ValidationStatus.MISSING)
                       for issue in issues)
        has_warning = any(issue.status == ValidationStatus.WARNING
                          for issue in issues)

        if has_fail:
            final_status = ValidationStatus.FAIL
            is_valid = False
        elif has_warning:
            final_status = ValidationStatus.WARNING
            is_valid = True
        else:
            final_status = ValidationStatus.PASS
            is_valid = True

        return GitignoreValidationResult(
            gitignore_path=self.gitignore_path,
            status=final_status,
            is_valid=is_valid,
            issues=issues,
            recommendations=recommendations,
            existing_rules=existing_rules,
        )

    def generate_correct_config(self) -> str:
        """生成正确的 .gitignore 配置.

        Returns:
            建议的 .gitignore 配置内容
        """
        return """# Environment files
.env
.env.*
!.env.example
!.env.sample

# Local overrides (uncomment if you want to track examples)
# .env.local
"""

    def check_file_in_git(self, file_path: Path) -> bool:
        """检查文件是否已被 git 跟踪.

        Args:
            file_path: 要检查的文件路径

        Returns:
            如果文件已被 git 跟踪返回 True
        """
        import subprocess

        try:
            result = subprocess.run(
                ["git", "ls-files", "--error-unmatch", str(file_path)],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def check_untracked_secrets(self) -> list[Path]:
        """检查是否有未跟踪的敏感文件.

        Returns:
            未跟踪的敏感文件列表
        """
        untracked: list[Path] = []

        for pattern in ENV_FILENAME_PATTERNS:
            for path in self.root.glob(f"*{pattern.pattern[1:]}*"):
                if path.is_file() and not self.check_file_in_git(path):
                    untracked.append(path)

        return untracked
