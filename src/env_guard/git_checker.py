"""Git 敏感信息检查器

检查 staged files 和 git history 中的敏感信息泄露
"""

import re
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional, Set, Tuple

import git

from .constants import (
    ENV_FILENAMES,
    HIGH_RISK_PATTERNS,
    LEAK_PATTERNS,
    LEAK_REGEXES,
    SENSITIVE_REGEXES,
)


class SecretType(Enum):
    """敏感信息类型"""
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"
    AWS_CREDENTIAL = "aws_credential"
    GENERIC_SECRET = "generic_secret"
    SENSITIVE_FILE = "sensitive_file"


class SecretSeverity(Enum):
    """敏感信息严重级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class LeakedSecret:
    """泄露的敏感信息"""
    secret_type: SecretType
    severity: SecretSeverity
    file_path: str
    line_number: Optional[int] = None
    content_preview: str = ""
    commit_hash: Optional[str] = None
    commit_message: Optional[str] = None
    commit_date: Optional[datetime] = None
    is_staged: bool = False
    matched_pattern: str = ""
    redacted_value: str = ""

    def __post_init__(self):
        """生成脱敏后的值"""
        if self.content_preview:
            self.redacted_value = self._redact_content()

    def _redact_content(self) -> str:
        """脱敏内容，只显示前后部分"""
        if len(self.content_preview) <= 20:
            return "***REDACTED***"
        return self.content_preview[:10] + "..." + self.content_preview[-4:]


@dataclass
class GitCheckResult:
    """Git 检查结果"""
    staged_secrets: List[LeakedSecret] = field(default_factory=list)
    history_secrets: List[LeakedSecret] = field(default_factory=list)
    is_git_repo: bool = True
    error_message: Optional[str] = None

    @property
    def total_secrets(self) -> int:
        return len(self.staged_secrets) + len(self.history_secrets)

    @property
    def has_leaks(self) -> bool:
        return self.total_secrets > 0

    @property
    def critical_count(self) -> int:
        return sum(
            1 for s in self.staged_secrets + self.history_secrets
            if s.severity == SecretSeverity.CRITICAL
        )

    def get_summary(self) -> dict:
        """获取摘要统计"""
        return {
            "total": self.total_secrets,
            "staged": len(self.staged_secrets),
            "in_history": len(self.history_secrets),
            "critical": self.critical_count,
            "is_git_repo": self.is_git_repo,
        }


class GitChecker:
    """Git 敏感信息检查器"""

    def __init__(self, repo_path: Optional[Path] = None):
        """初始化检查器

        Args:
            repo_path: Git 仓库路径，默认为当前目录
        """
        self.repo_path = repo_path or Path.cwd()
        self.repo: Optional[git.Repo] = None
        self._init_repo()

    def _init_repo(self) -> None:
        """初始化 Git 仓库"""
        try:
            self.repo = git.Repo(self.repo_path)
        except git.InvalidGitRepositoryError:
            self.repo = None

    def is_git_repo(self) -> bool:
        """检查是否为 Git 仓库"""
        return self.repo is not None

    def _is_binary_file(self, blob) -> bool:
        """检查文件是否为二进制文件"""
        try:
            return b"\x00" in blob.data_stream.read(8192)
        except Exception:
            return True

    def _check_content_for_secrets(
        self, content: str, file_path: str
    ) -> List[LeakedSecret]:
        """检查内容中的敏感信息

        Args:
            content: 文件内容
            file_path: 文件路径

        Returns:
            检测到的敏感信息列表
        """
        secrets = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            # 检查是否包含敏感键名
            if "=" in line:
                key = line.split("=", 1)[0].strip()
                for regex in SENSITIVE_REGEXES:
                    if regex.match(key):
                        secrets.append(LeakedSecret(
                            secret_type=SecretType.GENERIC_SECRET,
                            severity=SecretSeverity.HIGH,
                            file_path=file_path,
                            line_number=line_num,
                            content_preview=line,
                            matched_pattern=f"sensitive_key:{key}",
                        ))
                        break

            # 检查泄露模式
            for regex, pattern_info in zip(LEAK_REGEXES, LEAK_PATTERNS):
                matches = regex.finditer(line)
                for match in matches:
                    matched_text = match.group(0)
                    secret_type = self._get_secret_type_from_pattern(
                        pattern_info["name"]
                    )
                    severity = SecretSeverity(pattern_info["severity"])

                    secrets.append(LeakedSecret(
                        secret_type=secret_type,
                        severity=severity,
                        file_path=file_path,
                        line_number=line_num,
                        content_preview=matched_text,
                        matched_pattern=pattern_info["name"],
                    ))

        return secrets

    def _get_secret_type_from_pattern(self, pattern_name: str) -> SecretType:
        """根据模式名称获取敏感类型"""
        name_lower = pattern_name.lower()
        if "openai" in name_lower or "api key" in name_lower:
            return SecretType.API_KEY
        elif "github" in name_lower:
            return SecretType.TOKEN
        elif "aws" in name_lower:
            return SecretType.AWS_CREDENTIAL
        elif "private key" in name_lower:
            return SecretType.PRIVATE_KEY
        elif "password" in name_lower:
            return SecretType.PASSWORD
        elif "jwt" in name_lower or "bearer" in name_lower or "token" in name_lower:
            return SecretType.TOKEN
        else:
            return SecretType.GENERIC_SECRET

    def _is_sensitive_file(self, file_path: str) -> bool:
        """检查文件是否为敏感文件"""
        basename = os.path.basename(file_path)

        # 检查是否为 .env 文件
        if basename in ENV_FILENAMES:
            return True

        # 检查高风险模式
        for pattern in HIGH_RISK_PATTERNS:
            if re.search(pattern, file_path):
                return True

        return False

    def check_staged_files(self) -> List[LeakedSecret]:
        """检查 staged files 中的敏感信息

        Returns:
            检测到的敏感信息列表
        """
        secrets: List[LeakedSecret] = []

        if not self.repo:
            return secrets

        try:
            # 获取 staged 文件（相对于 HEAD）
            staged_diff = self.repo.index.diff("HEAD")
            # 也检查新 staged 的文件（未提交的）
            staged_new = self.repo.index.diff(None)

            all_staged = set()
            for item in staged_diff + staged_new:
                file_path = item.a_path or item.b_path
                if file_path:
                    all_staged.add(file_path)

            # 检查工作区的 staged 内容
            for file_path in all_staged:
                if self._is_sensitive_file(file_path):
                    try:
                        # 尝试读取工作区的文件内容
                        full_path = self.repo_path / file_path
                        if full_path.exists():
                            with open(full_path, "r", encoding="utf-8",
                                      errors="ignore") as f:
                                content = f.read()
                            file_secrets = self._check_content_for_secrets(
                                content, file_path
                            )
                            for secret in file_secrets:
                                secret.is_staged = True
                            secrets.extend(file_secrets)
                    except Exception:
                        # 如果无法读取，跳过
                        pass

            # 也检查已 staged 的 blob 内容
            for item in self.repo.index.diff("HEAD"):
                file_path = item.a_path
                if not file_path:
                    continue

                try:
                    # 获取 staged 的内容
                    if item.b_blob:
                        blob_data = item.b_blob.data_stream.read()
                        try:
                            content = blob_data.decode("utf-8", errors="ignore")
                            file_secrets = self._check_content_for_secrets(
                                content, file_path
                            )
                            for secret in file_secrets:
                                secret.is_staged = True
                            secrets.extend(file_secrets)
                        except Exception:
                            pass
                except Exception:
                    continue

        except Exception as e:
            # 如果出错，返回空列表
            pass

        return secrets

    def check_history(
        self,
        max_commits: int = 100,
        file_patterns: Optional[List[str]] = None,
    ) -> List[LeakedSecret]:
        """扫描 git history 中的敏感信息

        Args:
            max_commits: 最大扫描的 commit 数量
            file_patterns: 要检查的文件模式列表，None 表示检查所有文件

        Returns:
            检测到的敏感信息列表
        """
        secrets: List[LeakedSecret] = []

        if not self.repo:
            return secrets

        try:
            commits = list(self.repo.iter_commits(max_count=max_commits))

            for commit in commits:
                # 获取 commit 中修改的文件
                try:
                    parent = commit.parents[0] if commit.parents else None
                    diff = commit.diff(parent)

                    for item in diff:
                        file_path = item.a_path or item.b_path
                        if not file_path:
                            continue

                        # 如果指定了文件模式，过滤
                        if file_patterns:
                            matched = False
                            for pattern in file_patterns:
                                if re.search(pattern, file_path):
                                    matched = True
                                    break
                            if not matched:
                                continue

                        # 检查是否为敏感文件或包含敏感内容
                        if self._is_sensitive_file(file_path):
                            # 敏感文件，检查整个 blob
                            try:
                                if item.b_blob:
                                    blob_data = item.b_blob.data_stream.read()
                                    try:
                                        content = blob_data.decode(
                                            "utf-8", errors="ignore"
                                        )
                                        file_secrets = self._check_content_for_secrets(
                                            content, file_path
                                        )
                                        for secret in file_secrets:
                                            secret.commit_hash = commit.hexsha
                                            secret.commit_message = commit.message
                                            secret.commit_date = datetime.fromtimestamp(
                                                commit.committed_date
                                            )
                                        secrets.extend(file_secrets)
                                    except Exception:
                                        pass
                            except Exception:
                                continue
                        else:
                            # 非敏感文件，只检查 diff 中的内容
                            try:
                                if item.diff:
                                    diff_text = item.diff.decode(
                                        "utf-8", errors="ignore"
                                    )
                                    if diff_text:
                                        file_secrets = self._check_content_for_secrets(
                                            diff_text, file_path
                                        )
                                        for secret in file_secrets:
                                            secret.commit_hash = commit.hexsha
                                            secret.commit_message = commit.message
                                            secret.commit_date = datetime.fromtimestamp(
                                                commit.committed_date
                                            )
                                        secrets.extend(file_secrets)
                            except Exception:
                                continue

                except Exception:
                    # 某些 commit 可能会出错，跳过
                    continue

        except Exception:
            # 如果出错，返回空列表
            pass

        return secrets

    def check_all(
        self,
        max_history_commits: int = 100,
        check_staged: bool = True,
        check_history: bool = True,
    ) -> GitCheckResult:
        """执行所有检查

        Args:
            max_history_commits: 最大扫描的 history commit 数量
            check_staged: 是否检查 staged files
            check_history: 是否检查 history

        Returns:
            GitCheckResult: 检查结果
        """
        result = GitCheckResult()

        if not self.is_git_repo():
            result.is_git_repo = False
            result.error_message = "Not a git repository"
            return result

        try:
            if check_staged:
                result.staged_secrets = self.check_staged_files()

            if check_history:
                result.history_secrets = self.check_history(
                    max_commits=max_history_commits
                )

        except Exception as e:
            result.error_message = str(e)

        return result

    def get_commit_range_secrets(
        self,
        start_ref: str,
        end_ref: str,
    ) -> List[LeakedSecret]:
        """检查指定 commit 范围内的敏感信息

        Args:
            start_ref: 起始引用（如 HEAD~10）
            end_ref: 结束引用（如 HEAD）

        Returns:
            检测到的敏感信息列表
        """
        secrets: List[LeakedSecret] = []

        if not self.repo:
            return secrets

        try:
            start_commit = self.repo.commit(start_ref)
            end_commit = self.repo.commit(end_ref)

            diff = start_commit.diff(end_commit)
            commits = list(self.repo.iter_commits(
                f"{start_ref}..{end_ref}",
                max_count=100
            ))

            # 检查 diff
            for item in diff:
                file_path = item.b_path or item.a_path
                if not file_path:
                    continue

                try:
                    if item.diff:
                        diff_text = item.diff.decode("utf-8", errors="ignore")
                        if diff_text:
                            file_secrets = self._check_content_for_secrets(
                                diff_text, file_path
                            )
                            secrets.extend(file_secrets)
                except Exception:
                    continue

            # 检查 commit 历史
            for commit in commits:
                try:
                    parent = commit.parents[0] if commit.parents else None
                    commit_diff = commit.diff(parent)

                    for item in commit_diff:
                        file_path = item.b_path or item.a_path
                        if not file_path:
                            continue

                        try:
                            if item.b_blob:
                                blob_data = item.b_blob.data_stream.read()
                                content = blob_data.decode("utf-8", errors="ignore")
                                file_secrets = self._check_content_for_secrets(
                                    content, file_path
                                )
                                for secret in file_secrets:
                                    secret.commit_hash = commit.hexsha
                                    secret.commit_message = commit.message
                                    secret.commit_date = datetime.fromtimestamp(
                                        commit.committed_date
                                    )
                                secrets.extend(file_secrets)
                        except Exception:
                            continue

                except Exception:
                    continue

        except Exception:
            pass

        return secrets
