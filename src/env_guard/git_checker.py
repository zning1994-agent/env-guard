"""Git 仓库敏感信息检查器"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from env_guard.constants import LEAK_PATTERNS
from env_guard.scanner import RiskLevel


@dataclass
class LeakedSecret:
    """泄露的敏感信息"""
    secret_type: str  # e.g., "github_token", "openai_key", "aws_key"
    value: str  # 脱敏后的值
    location: str  # 文件路径或 commit hash
    commit_hash: Optional[str] = None
    commit_message: Optional[str] = None
    commit_date: Optional[datetime] = None
    author: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.CRITICAL
    line_preview: Optional[str] = None  # 包含敏感信息的行预览
    diff_content: Optional[str] = None  # 变更内容的 diff


@dataclass
class GitCheckResult:
    """Git 检查结果"""
    staged_files: list[LeakedSecret] = field(default_factory=list)
    history_secrets: list[LeakedSecret] = field(default_factory=list)
    repo_path: Path
    
    @property
    def total_secrets(self) -> int:
        return len(self.staged_files) + len(self.history_secrets)
    
    @property
    def has_leaks(self) -> bool:
        return self.total_secrets > 0


@dataclass
class GitCheckSummary:
    """Git 检查汇总"""
    total_staged: int = 0
    total_history: int = 0
    commits_scanned: int = 0
    files_checked: int = 0
    risk_counts: dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
    })


class GitChecker:
    """Git 仓库敏感信息检查器"""
    
    def __init__(self, repo_path: Optional[Path] = None):
        """
        初始化检查器
        
        Args:
            repo_path: Git 仓库路径，默认为当前目录
        """
        self.repo_path = repo_path or Path.cwd()
        self._leak_patterns = [re.compile(p) for p in LEAK_PATTERNS]
        self._secret_type_map = {
            r"sk\-[a-zA-Z0-9]{20,}": ("OpenAI API Key", RiskLevel.CRITICAL),
            r"sk\-[a-zA-Z0-9\-]{48}": ("OpenAI Project Key", RiskLevel.CRITICAL),
            r"ghp_[a-zA-Z0-9]{36,}": ("GitHub PAT", RiskLevel.CRITICAL),
            r"ghs_[a-zA-Z0-9]{36,}": ("GitHub Server Token", RiskLevel.CRITICAL),
            r"ghu_[a-zA-Z0-9]{36,}": ("GitHub User Token", RiskLevel.CRITICAL),
            r"AKIA[0-9A-Z]{16}": ("AWS Access Key", RiskLevel.CRITICAL),
            r"(?i)amzn\.[a-zA-Z0-9]{20,}": ("AWS Secret Key", RiskLevel.CRITICAL),
            r"xox[baprs]\-[a-zA-Z0-9]{10,}": ("Slack Token", RiskLevel.HIGH),
            r"msteams_[a-zA-Z0-9]{20,}": ("Microsoft Teams Token", RiskLevel.HIGH),
            r"sq0[a-z]{3}\-[a-zA-Z0-9]{22}": ("Square OAuth", RiskLevel.HIGH),
        }
    
    def is_git_repo(self) -> bool:
        """检查路径是否为 Git 仓库"""
        try:
            import git
            git.Repo(self.repo_path)
            return True
        except Exception:
            return False
    
    def check_staged_files(self) -> list[LeakedSecret]:
        """
        检查 staged files 中的敏感信息
        
        Returns:
            list[LeakedSecret]: 发现的敏感信息列表
        """
        try:
            import git
        except ImportError:
            return []
        
        try:
            repo = git.Repo(self.repo_path)
        except Exception:
            return []
        
        secrets: list[LeakedSecret] = []
        
        # 获取 staged 文件
        try:
            staged_diff = repo.index.diff("HEAD")
        except Exception:
            # 如果是初始提交，使用当前 staged 文件
            staged_diff = repo.index.diff(None)
        
        for diff in staged_diff:
            # 检查新增或修改的文件
            file_path = diff.b_path or diff.a_path
            if not file_path:
                continue
            
            # 获取完整 diff 内容
            try:
                diff_content = diff.diff.decode("utf-8", errors="replace") if diff.diff else ""
            except Exception:
                diff_content = str(diff.diff) if diff.diff else ""
            
            # 检查 diff 内容中的敏感信息
            found_secrets = self._scan_text_for_secrets(
                diff_content,
                location=file_path,
                diff_content=diff_content
            )
            secrets.extend(found_secrets)
        
        # 也检查新 staged 的文件内容
        for item in repo.index.iter_blobs():
            path = item.path
            try:
                # 获取该文件在 HEAD 中的内容
                if repo.head.is_valid():
                    content = repo.git.show(f"HEAD:{path}")
                else:
                    # 初始提交的情况
                    content = repo.git.show(f":{path}")
                
                found_secrets = self._scan_text_for_secrets(
                    content,
                    location=path
                )
                secrets.extend(found_secrets)
            except Exception:
                pass
        
        return secrets
    
    def check_history(self, max_commits: int = 100, file_patterns: Optional[list[str]] = None) -> list[LeakedSecret]:
        """
        检查 git history 中的敏感信息
        
        Args:
            max_commits: 最大扫描的 commit 数量
            file_patterns: 只检查匹配这些模式的文件
            
        Returns:
            list[LeakedSecret]: 发现的敏感信息列表
        """
        try:
            import git
        except ImportError:
            return []
        
        try:
            repo = git.Repo(self.repo_path)
        except Exception:
            return []
        
        secrets: list[LeakedSecret] = []
        file_patterns_re = [re.compile(p) for p in file_patterns] if file_patterns else None
        
        commits_checked = 0
        
        try:
            for commit in repo.iter_commits(max_count=max_commits):
                commits_checked += 1
                
                # 检查提交消息中的敏感信息
                msg_secrets = self._check_commit_message(commit)
                secrets.extend(msg_secrets)
                
                # 检查提交中的文件
                for parent, child in zip([None] + list(commit.parents), [commit] * (len(list(commit.parents)) + 1)):
                    if parent is None:
                        # 初始提交，检查所有文件
                        for item in commit.tree.traverse():
                            if item.type == "blob":
                                secrets.extend(
                                    self._check_blob(item, commit, file_patterns_re)
                                )
                    else:
                        # 比较父子提交
                        try:
                            diff = parent.diff(child)
                            for d in diff:
                                path = d.b_path or d.a_path
                                if not path:
                                    continue
                                
                                # 检查新文件或修改的文件
                                if d.new_file or d.renamed:
                                    try:
                                        blob = child.tree[path]
                                        secrets.extend(
                                            self._check_blob_content(
                                                blob.data_stream.read().decode("utf-8", errors="replace"),
                                                path,
                                                commit,
                                                file_patterns_re
                                            )
                                        )
                                    except Exception:
                                        pass
                        except Exception:
                            pass
        except Exception:
            pass
        
        return secrets
    
    def _check_commit_message(self, commit) -> list[LeakedSecret]:
        """检查提交消息中的敏感信息"""
        secrets: list[LeakedSecret] = []
        
        for pattern, (secret_type, risk) in self._secret_type_map.items():
            if re.search(pattern, commit.message):
                match = re.search(pattern, commit.message)
                if match:
                    secrets.append(LeakedSecret(
                        secret_type=secret_type,
                        value=self._mask_value(match.group()),
                        location=f"commit:{commit.hexsha[:8]}",
                        commit_hash=commit.hexsha,
                        commit_message=commit.message[:100],
                        commit_date=datetime.fromtimestamp(commit.committed_date),
                        author=commit.author.name,
                        risk_level=risk,
                        line_preview=commit.message[:200],
                    ))
        
        return secrets
    
    def _check_blob(self, blob, commit, file_patterns_re) -> list[LeakedSecret]:
        """检查 blob 对象"""
        try:
            content = blob.data_stream.read().decode("utf-8", errors="replace")
            return self._check_blob_content(content, blob.path, commit, file_patterns_re)
        except Exception:
            return []
    
    def _check_blob_content(self, content: str, path: str, commit, file_patterns_re) -> list[LeakedSecret]:
        """检查 blob 内容"""
        secrets: list[LeakedSecret] = []
        
        # 检查文件模式过滤
        if file_patterns_re:
            if not any(p.search(path) for p in file_patterns_re):
                return secrets
        
        for pattern, (secret_type, risk) in self._secret_type_map.items():
            for match in re.finditer(pattern, content):
                # 获取匹配行的预览
                line_num = content[:match.start()].count("\n") + 1
                lines = content.split("\n")
                line_preview = lines[line_num - 1] if line_num <= len(lines) else ""
                
                secrets.append(LeakedSecret(
                    secret_type=secret_type,
                    value=self._mask_value(match.group()),
                    location=path,
                    commit_hash=commit.hexsha,
                    commit_message=commit.message[:100] if commit.message else None,
                    commit_date=datetime.fromtimestamp(commit.committed_date),
                    author=commit.author.name,
                    risk_level=risk,
                    line_preview=line_preview.strip()[:200] if line_preview else None,
                ))
        
        return secrets
    
    def _scan_text_for_secrets(self, text: str, location: str, diff_content: Optional[str] = None) -> list[LeakedSecret]:
        """扫描文本中的敏感信息"""
        secrets: list[LeakedSecret] = []
        
        for pattern, (secret_type, risk) in self._secret_type_map.items():
            for match in re.finditer(pattern, text):
                secrets.append(LeakedSecret(
                    secret_type=secret_type,
                    value=self._mask_value(match.group()),
                    location=location,
                    risk_level=risk,
                    diff_content=diff_content[:500] if diff_content else None,
                ))
        
        return secrets
    
    def _mask_value(self, value: str) -> str:
        """脱敏敏感值"""
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]
    
    def check_all(self, max_history_commits: int = 100) -> tuple[GitCheckResult, GitCheckSummary]:
        """
        执行完整的 Git 检查
        
        Args:
            max_history_commits: 最大扫描的 commit 数量
            
        Returns:
            (检查结果, 汇总信息)
        """
        staged = self.check_staged_files()
        history = self.check_history(max_commits=max_history_commits)
        
        result = GitCheckResult(
            staged_files=staged,
            history_secrets=history,
            repo_path=self.repo_path,
        )
        
        summary = GitCheckSummary(
            total_staged=len(staged),
            total_history=len(history),
            risk_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        )
        
        for secret in staged + history:
            summary.risk_counts[secret.risk_level.value] += 1
        
        return result, summary


# 便捷函数
def check_git_leaks(repo_path: Optional[Path] = None, max_commits: int = 100) -> tuple[GitCheckResult, GitCheckSummary]:
    """检查 Git 仓库敏感信息的便捷函数"""
    checker = GitChecker(repo_path)
    return checker.check_all(max_commits)
