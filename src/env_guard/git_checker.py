"""Git 敏感信息检查模块

检查 staged files 和 git history 中的敏感信息泄露。
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from git import Repo, GitCommandError
from git.exc import InvalidGitRepositoryError

from .constants import LEAK_PATTERNS, SENSITIVE_KEY_PATTERNS


@dataclass
class LeakedSecret:
    """泄露的敏感信息"""
    file_path: str
    line_number: int
    content_preview: str
    secret_type: str
    commit_hash: Optional[str] = None
    commit_message: Optional[str] = None
    is_staged: bool = False

    def __str__(self) -> str:
        location = "staged" if self.is_staged else f"commit {self.commit_hash[:7]}"
        return f"{self.file_path}:{self.line_number} [{location}] {self.secret_type}: {self.content_preview}"


class GitChecker:
    """检查 git 中的敏感信息泄露"""

    def __init__(self, repo_path: Optional[Path] = None):
        """初始化 GitChecker
        
        Args:
            repo_path: Git 仓库路径，默认为当前目录
        """
        self.repo_path = repo_path or Path.cwd()
        self._repo: Optional[Repo] = None
        self._compiled_leak_patterns = [re.compile(p) for p in LEAK_PATTERNS]
        self._compiled_sensitive_patterns = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_KEY_PATTERNS]

    @property
    def repo(self) -> Repo:
        """获取 Git 仓库对象"""
        if self._repo is None:
            try:
                self._repo = Repo(self.repo_path)
            except InvalidGitRepositoryError:
                raise NotAGitRepositoryError(f"'{self.repo_path}' is not a git repository")
        return self._repo

    def is_git_repo(self) -> bool:
        """检查路径是否为 Git 仓库"""
        try:
            _ = self.repo
            return True
        except NotAGitRepositoryError:
            return False

    def check_staged_files(self) -> list[LeakedSecret]:
        """检查 staged files 中的敏感信息
        
        Returns:
            泄露的敏感信息列表
        """
        if not self.is_git_repo():
            return []

        leaked_secrets: list[LeakedSecret] = []
        
        try:
            # 获取 staged 文件的 diff
            diff_index = self.repo.index.diff("HEAD")
        except GitCommandError:
            # 首次提交时没有 HEAD，使用当前索引
            diff_index = self.repo.index.diff(None)

        for diff_item in diff_index:
            # 获取 staged 文件的新内容（添加和修改）
            if diff_item.b_path:  # staged 后的文件路径
                file_path = diff_item.b_path
            else:
                file_path = diff_item.a_path

            # 获取 staged 的内容
            staged_content = diff_item.b_blob.data_stream.read().decode('utf-8', errors='ignore') if diff_item.b_blob else ""
            
            # 检查 .env 相关文件
            if self._is_env_file(file_path):
                leaked_secrets.extend(
                    self._check_content(file_path, staged_content, is_staged=True)
                )

        # 也检查当前索引中新增的文件
        for item in self.repo.index.added:
            if self._is_env_file(item.path):
                try:
                    content = self.repo.index.blobs[item.path].data_stream.read().decode('utf-8', errors='ignore')
                    leaked_secrets.extend(
                        self._check_content(item.path, content, is_staged=True)
                    )
                except (AttributeError, OSError):
                    pass

        return leaked_secrets

    def check_history(
        self,
        max_commits: int = 100,
        file_patterns: Optional[list[str]] = None
    ) -> list[LeakedSecret]:
        """检查 git history 中的敏感信息
        
        Args:
            max_commits: 最大扫描的提交数
            file_patterns: 要检查的文件模式列表，None 表示检查所有 .env 文件
            
        Returns:
            泄露的敏感信息列表
        """
        if not self.is_git_repo():
            return []

        leaked_secrets: list[LeakedSecret] = []
        file_patterns = file_patterns or ['*.env', '.env*']

        try:
            commits = list(self.repo.iter_commits(max_count=max_commits))
        except GitCommandError:
            return []

        for commit in commits:
            try:
                # 检查提交中的文件
                for parent_path, blobs in commit.stats.blobs.items():
                    if not self._matches_patterns(parent_path, file_patterns):
                        continue

                    try:
                        # 获取该提交时文件的内容
                        file_content = commit.tree[parent_path].data_stream.read().decode('utf-8', errors='ignore')
                        secrets = self._check_content(
                            parent_path,
                            file_content,
                            is_staged=False,
                            commit_hash=commit.hexsha,
                            commit_message=commit.message
                        )
                        leaked_secrets.extend(secrets)
                    except KeyError:
                        # 文件在该提交中可能是删除的
                        pass
                    except (OSError, GitCommandError):
                        pass
            except GitCommandError:
                # 某些提交可能无法访问
                continue

        return leaked_secrets

    def check_file_in_history(
        self,
        file_path: str,
        max_commits: int = 100
    ) -> list[LeakedSecret]:
        """检查特定文件在 git history 中的敏感信息
        
        Args:
            file_path: 要检查的文件路径
            max_commits: 最大扫描的提交数
            
        Returns:
            泄露的敏感信息列表
        """
        if not self.is_git_repo():
            return []

        leaked_secrets: list[LeakedSecret] = []

        try:
            commits_with_file = list(self.repo.iter_commits(paths=file_path, max_count=max_commits))
        except GitCommandError:
            return []

        for commit in commits_with_file:
            try:
                file_content = commit.tree[file_path].data_stream.read().decode('utf-8', errors='ignore')
                secrets = self._check_content(
                    file_path,
                    file_content,
                    is_staged=False,
                    commit_hash=commit.hexsha,
                    commit_message=commit.message
                )
                leaked_secrets.extend(secrets)
            except KeyError:
                pass
            except (OSError, GitCommandError):
                continue

        return leaked_secrets

    def get_staged_files(self) -> list[str]:
        """获取所有 staged 文件列表
        
        Returns:
            staged 文件路径列表
        """
        if not self.is_git_repo():
            return []

        staged_files = []
        try:
            diff_index = self.repo.index.diff("HEAD")
        except GitCommandError:
            diff_index = self.repo.index.diff(None)

        for diff_item in diff_index:
            if diff_item.b_path:
                staged_files.append(diff_item.b_path)
            elif diff_item.a_path:
                staged_files.append(diff_item.a_path)

        return staged_files

    def get_env_files_in_history(self, max_commits: int = 100) -> set[str]:
        """获取 git history 中所有 .env 相关文件
        
        Args:
            max_commits: 最大扫描的提交数
            
        Returns:
            .env 文件路径集合
        """
        if not self.is_git_repo():
            return set()

        env_files: set[str] = set()

        try:
            for commit in self.repo.iter_commits(max_count=max_commits):
                try:
                    for parent_path in commit.stats.blobs:
                        if self._is_env_file(parent_path):
                            env_files.add(parent_path)
                except GitCommandError:
                    continue
        except GitCommandError:
            pass

        return env_files

    def _is_env_file(self, file_path: str) -> bool:
        """检查文件是否为 .env 相关文件"""
        path_lower = file_path.lower()
        env_patterns = ['.env', 'env.', 'env_']
        return any(p in path_lower for p in env_patterns)

    def _matches_patterns(self, file_path: str, patterns: list[str]) -> bool:
        """检查文件路径是否匹配任意模式"""
        path_lower = file_path.lower()
        for pattern in patterns:
            pattern_lower = pattern.lower()
            if pattern_lower.startswith('*'):
                # 简单的通配符匹配
                suffix = pattern_lower[1:]
                if path_lower.endswith(suffix):
                    return True
            elif pattern_lower in path_lower:
                return True
        return self._is_env_file(file_path)

    def _check_content(
        self,
        file_path: str,
        content: str,
        is_staged: bool = False,
        commit_hash: Optional[str] = None,
        commit_message: Optional[str] = None
    ) -> list[LeakedSecret]:
        """检查内容中的敏感信息
        
        Args:
            file_path: 文件路径
            content: 文件内容
            is_staged: 是否为 staged 文件
            commit_hash: 提交哈希
            commit_message: 提交信息
            
        Returns:
            泄露的敏感信息列表
        """
        leaked_secrets: list[LeakedSecret] = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, start=1):
            # 跳过注释和空行
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            # 检查泄露模式（如 API key）
            for pattern in self._compiled_leak_patterns:
                match = pattern.search(line)
                if match:
                    secret_type = self._detect_secret_type(match.group())
                    leaked_secrets.append(LeakedSecret(
                        file_path=file_path,
                        line_number=line_num,
                        content_preview=match.group()[:50] + ('...' if len(match.group()) > 50 else ''),
                        secret_type=secret_type,
                        commit_hash=commit_hash,
                        commit_message=commit_message,
                        is_staged=is_staged
                    ))
                    continue

            # 检查敏感键名模式
            if '=' in line:
                key = line.split('=', 1)[0].strip()
                for pattern in self._compiled_sensitive_patterns:
                    if pattern.match(key):
                        # 检查值是否看起来像敏感信息
                        value = line.split('=', 1)[1].strip()
                        if self._looks_like_secret(key, value):
                            leaked_secrets.append(LeakedSecret(
                                file_path=file_path,
                                line_number=line_num,
                                content_preview=f"{key}=***",
                                secret_type="SENSITIVE_VALUE",
                                commit_hash=commit_hash,
                                commit_message=commit_message,
                                is_staged=is_staged
                            ))
                        break

        return leaked_secrets

    def _detect_secret_type(self, secret: str) -> str:
        """检测敏感信息类型"""
        if secret.startswith('sk-'):
            return "OPENAI_API_KEY"
        elif secret.startswith('ghp_'):
            return "GITHUB_PAT"
        elif secret.startswith('AKIA'):
            return "AWS_ACCESS_KEY"
        elif len(secret) > 40:
            return "GENERIC_SECRET"
        return "SECRET"

    def _looks_like_secret(self, key: str, value: str) -> bool:
        """判断值是否看起来像敏感信息"""
        if not value or len(value) < 3:
            return False
        
        # 跳过明显的非敏感值
        if value in ('true', 'false', 'null', 'none', '0', '1', '""', "''", '""'):
            return False
            
        # 跳过 URL
        if value.startswith(('http://', 'https://', 'mysql://', 'postgres://')):
            return False
            
        # 检查是否有足够的长度和复杂性
        if len(value) >= 8 and any(c.isdigit() for c in value):
            return True
            
        return False


class NotAGitRepositoryError(Exception):
    """不是 Git 仓库异常"""
    pass
