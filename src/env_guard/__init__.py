"""env-guard - Git sensitive information leak detection and remediation."""

__version__ = "0.1.0"
__author__ = "env-guard contributors"

from env_guard.scanner import EnvScanner, SensitiveEntry
from env_guard.git_checker import GitChecker, LeakedSecret
from env_guard.gitignore_validator import GitignoreValidator, ValidationResult
from env_guard.reporter import Reporter

__all__ = [
    "__version__",
    "EnvScanner",
    "SensitiveEntry",
    "GitChecker",
    "LeakedSecret",
    "GitignoreValidator",
    "ValidationResult",
    "Reporter",
]
