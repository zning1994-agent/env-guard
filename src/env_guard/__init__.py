"""env-guard - Git 敏感信息泄露检测与修复工具"""

__version__ = "0.1.0"

from .git_checker import GitChecker, LeakedSecret, NotAGitRepositoryError

__all__ = [
    "GitChecker",
    "LeakedSecret",
    "NotAGitRepositoryError",
]
