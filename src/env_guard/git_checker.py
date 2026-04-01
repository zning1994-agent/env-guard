"""env-guard Git 检查器

检查 staged files 和 git history 中的敏感信息泄露
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, Optional

import git
from git import Repo

from env_guard.constants import LEAK_PATTERNS
from env_guard.models import LeakResult, SensitivityLevel


class GitChecker:
    """检查 git 中的敏感信息泄露"""

    def __init__(self, repo_path: Optional[Path] = None) -> None:
        self.repo_path = repo_path or Path.cwd()
        self._leak_regexes = [re.compile(p.pattern) for p in LEAK_PATTERNS]

    def _is_git_repo(self) -> bool:
        """检查是否为 git 仓库"""
        try:
            Repo(self.repo_path)
            return True
        except Exception:
            return False

    def check_staged_files(self) -> list[LeakResult]:
        """检查 staged files 中的敏感信息"""
        if not self._is_git_repo():
            return []

        leaks: list[LeakResult] = []
        repo = Repo(self.repo_path)

        try:
            # 获取 staged files
            staged = repo.index.diff("HEAD")
            if not staged:
                # 如果没有 HEAD（初始提交），检查暂存区
                staged = repo.index.diff(None)

            for diff in staged:
                if diff.a_file:
                    file_path = diff.a_path
                    # 获取文件的 staged 内容
                    blob = diff.b_blob
                    if blob:
                        content = blob.data_stream.read().decode("utf-8", errors="ignore")
                        file_leaks = self._scan_content(
                            content,
                            file_path,
                            commit_hash=None,
                            commit_message=None,
                        )
                        leaks.extend(file_leaks)

            # 也检查新添加的文件（未跟踪但已 staged）
            for item in repo.index.entries:
                file_path = str(item)
                if self._is_env_file(file_path):
                    try:
                        # 直接读取工作区文件（已 staged）
                        full_path = self.repo_path / file_path
                        if full_path.exists():
                            content = full_path.read_text(encoding="utf-8", errors="ignore")
                            file_leaks = self._scan_content(
                                content,
                                file_path,
                                commit_hash=None,
                                commit_message=None,
                            )
                            leaks.extend(file_leaks)
                    except Exception:
                        pass

        except Exception:
            pass

        return leaks

    def check_history(self, max_commits: int = 100) -> list[LeakResult]:
        """检查 git history 中的敏感信息"""
        if not self._is_git_repo():
            return []

        leaks: list[LeakResult] = []
        repo = Repo(self.repo_path)

        try:
            commits = list(repo.iter_commits(max_count=max_commits))

            for commit in commits:
                if commit.stats:
                    # 检查本次提交修改的文件
                    for file_path in commit.stats.files:
                        if self._is_env_file(file_path):
                            try:
                                # 获取文件在提交时的内容
                                file_content = self._get_file_at_commit(commit, file_path)
                                if file_content:
                                    file_leaks = self._scan_content(
                                        file_content,
                                        file_path,
                                        commit_hash=commit.hexsha,
                                        commit_message=commit.message,
                                    )
                                    leaks.extend(file_leaks)
                            except Exception:
                                pass

        except Exception:
            pass

        return leaks

    def check_file_history(self, file_path: str, max_commits: int = 50) -> list[LeakResult]:
        """检查特定文件的历史"""
        if not self._is_git_repo():
            return []

        leaks: list[LeakResult] = []
        repo = Repo(self.repo_path)

        try:
            commits = list(repo.iter_commits(paths=file_path, max_count=max_commits))

            for commit in commits:
                try:
                    file_content = self._get_file_at_commit(commit, file_path)
                    if file_content:
                        file_leaks = self._scan_content(
                            file_content,
                            file_path,
                            commit_hash=commit.hexsha,
                            commit_message=commit.message,
                        )
                        leaks.extend(file_leaks)
                except Exception:
                    pass

        except Exception:
            pass

        return leaks

    def _scan_content(
        self,
        content: str,
        file_path: str,
        commit_hash: Optional[str],
        commit_message: Optional[str],
    ) -> list[LeakResult]:
        """扫描内容中的敏感信息"""
        leaks: list[LeakResult] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            for regex, pattern_info in zip(self._leak_regexes, LEAK_PATTERNS):
                matches = regex.findall(line)
                if matches:
                    for match in matches:
                        leaks.append(
                            LeakResult(
                                commit_hash=commit_hash,
                                commit_message=commit_message,
                                file_path=file_path,
                                line_number=line_num,
                                content_preview=self._mask_secret(line, match),
                                matched_pattern=pattern_info.description,
                                sensitivity_level=SensitivityLevel.CRITICAL,
                            )
                        )

        return leaks

    def _get_file_at_commit(self, commit: "Commit", file_path: str) -> Optional[str]:  # noqa: F821
        """获取特定提交时文件的内容"""
        try:
            blob = commit.tree[file_path]
            return blob.data_stream.read().decode("utf-8", errors="ignore")
        except Exception:
            return None

    def _is_env_file(self, file_path: str) -> bool:
        """检查文件路径是否为 .env 相关文件"""
        env_patterns = [
            ".env",
            ".env.local",
            ".env.development",
            ".env.staging",
            ".env.production",
            ".env.test",
            ".env.example",
        ]
        return any(file_path.endswith(p) or file_path == p for p in env_patterns)

    def _mask_secret(self, line: str, match: str) -> str:
        """遮蔽敏感信息"""
        if len(match) <= 4:
            return line.replace(match, "*" * len(match))
        # 保留前后各2个字符
        masked = match[:2] + "*" * (len(match) - 4) + match[-2:]
        return line.replace(match, masked)

    def get_repo_info(self) -> dict[str, str]:
        """获取仓库信息"""
        if not self._is_git_repo():
            return {}

        repo = Repo(self.repo_path)
        return {
            "name": repo.working_dir.split("/")[-1] if repo.working_dir else "unknown",
            "branch": repo.active_branch.name if repo.active_branch else "unknown",
            "is_dirty": repo.is_dirty(),
            "remote_url": self._get_remote_url(repo),
        }

    def _get_remote_url(self, repo: Repo) -> str:
        """获取远程仓库 URL"""
        try:
            if repo.remotes:
                return repo.remotes[0].url
        except Exception:
            pass
        return "unknown"
