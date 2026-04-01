"""Data models for env-guard."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from env_guard.constants import SensitivityLevel


@dataclass
class SensitiveEntry:
    """Represents a detected sensitive entry in a file."""
    key: str
    value: str  # Masked value
    line_number: int
    sensitivity_level: SensitivityLevel
    matched_pattern: str
    file_path: str
    raw_value_length: int = 0
    
    def __post_init__(self):
        if self.raw_value_length == 0:
            self.raw_value_length = len(self.value)
    
    def mask_value(self, show_chars: int = 4) -> str:
        """Return a masked version of the value."""
        if len(self.value) <= show_chars:
            return "*" * len(self.value)
        return self.value[:show_chars] + "*" * (len(self.value) - show_chars)


@dataclass
class LeakedSecret:
    """Represents a leaked secret found in git history or staged files."""
    secret_type: str
    matched_pattern: str
    file_path: str
    commit_hash: Optional[str] = None
    commit_message: Optional[str] = None
    commit_date: Optional[datetime] = None
    author: Optional[str] = None
    line_number: Optional[int] = None
    content_preview: str = ""
    severity: SensitivityLevel = SensitivityLevel.HIGH
    
    def __post_init__(self):
        if self.severity == SensitivityLevel.HIGH:
            if self.secret_type in ("openai_api_key", "github_pat", "aws_access_key"):
                self.severity = SensitivityLevel.CRITICAL


@dataclass
class GitignoreIssue:
    """Represents an issue found in .gitignore configuration."""
    issue_type: str  # "missing", "incorrect", "redundant"
    pattern: str
    file_path: str
    line_number: int
    message: str
    suggestion: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of .gitignore validation."""
    is_valid: bool
    issues: list[GitignoreIssue] = field(default_factory=list)
    existing_env_patterns: list[str] = field(default_factory=list)
    has_basic_protection: bool = False
    has_local_protection: bool = False
    
    @property
    def total_issues(self) -> int:
        return len(self.issues)
    
    @property
    def has_critical_issues(self) -> bool:
        return any(issue.issue_type == "missing" for issue in self.issues)


@dataclass
class ScanResult:
    """Result of a scan operation."""
    scanned_files: int = 0
    sensitive_entries: list[SensitiveEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_time: float = 0.0
    
    @property
    def total_findings(self) -> int:
        return len(self.sensitive_entries)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for e in self.sensitive_entries 
                   if e.sensitivity_level == SensitivityLevel.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for e in self.sensitive_entries 
                   if e.sensitivity_level == SensitivityLevel.HIGH)


@dataclass
class CheckResult:
    """Result of git check operation."""
    staged_leaks: list[LeakedSecret] = field(default_factory=list)
    history_leaks: list[LeakedSecret] = field(default_factory=list)
    scanned_commits: int = 0
    scan_time: float = 0.0
    
    @property
    def total_leaks(self) -> int:
        return len(self.staged_leaks) + len(self.history_leaks)
    
    @property
    def has_staged_leaks(self) -> bool:
        return len(self.staged_leaks) > 0
    
    @property
    def has_history_leaks(self) -> bool:
        return len(self.history_leaks) > 0


@dataclass
class IntegrationConfig:
    """Configuration for CI/hook integration."""
    config_type: str  # "pre-commit", "github-actions", "gitlab-ci"
    file_path: str
    content: str
    file_created: bool = False
