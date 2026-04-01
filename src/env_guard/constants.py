"""Sensitive information patterns and constants."""

import re
from enum import Enum
from typing import Final

# Sensitivity levels
class SensitivityLevel(str, Enum):
    """Sensitivity level for detected secrets."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Sensitive key patterns (regex)
SENSITIVE_KEY_PATTERNS: Final[list[str]] = [
    r"^(api[_\-]?key|apikey)$",
    r"^(secret|password|passwd|pwd)$",
    r"^(token|auth|bearer|jwt)$",
    r"^(private[_\-]?key|privkey)$",
    r"^(access[_\-]?key|aws[_\-]?key)$",
    r"^.*(credential|secret|token|key|password|passwd).*$",
    r"^(db[_\-]?host|db[_\-]?name|db[_\-]?user|db[_\-]?pass)$",
    r"^(mysql|postgres|mongodb|redis)[_\-]?(user|pass|host)?$",
    r"^(smtp|email|mail)[_\-]?(user|pass|host)?$",
    r"^slack[_\-]?(webhook|token|secret)$",
    r"^stripe[_\-]?(api[_\-]?key|secret|publishable[_\-]?key)$",
    r"^sendgrid[_\-]?(api[_\-]?key|key)$",
    r"^twilio[_\-]?(account[_\-]?sid|auth[_\-]?token|api[_\-]?key)$",
]

# Compiled key patterns for performance
COMPILED_KEY_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_KEY_PATTERNS]

# Common secret leak patterns (regex)
LEAK_PATTERNS: Final[dict[str, str]] = {
    "openai_api_key": r"sk-[a-zA-Z0-9]{20,}",
    "github_pat": r"ghp_[a-zA-Z0-9]{36,}",
    "github_oauth": r"gho_[a-zA-Z0-9]{36,}",
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"[A-Za-z0-9/+=]{40}",
    "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "stripe_key": r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_publishable": r"pk_live_[0-9a-zA-Z]{24,}",
    "sendgrid_key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "twilio_api_key": r"SK[a-zA-Z0-9]{32}",
    "private_key_header": r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    "generic_secret": r"(?i)(secret|password|token|key)[=:]\s*['\"]?[a-zA-Z0-9_/-]{8,}['\"]?",
}

# Compiled leak patterns
COMPILED_LEAK_PATTERNS = {
    name: re.compile(pattern, re.IGNORECASE)
    for name, pattern in LEAK_PATTERNS.items()
}

# High-risk keywords that indicate sensitive content
HIGH_RISK_KEYWORDS: Final[list[str]] = [
    "password",
    "secret",
    "api_key",
    "apikey",
    "auth_token",
    "private_key",
    "access_token",
    "bearer_token",
    "credentials",
    "encryption_key",
    "jwt_secret",
]

# ENV filename patterns to scan
ENV_FILENAME_PATTERNS: Final[list[str]] = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.test",
    ".env.staging",
    ".env.example",
    ".env.sample",
    "*.env*",
    ".flaskenv",
    ".pythonenv",
]

# Directories to exclude from scanning
EXCLUDE_DIRS: Final[set[str]] = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".tox",
    ".eggs",
    "*.egg-info",
}

# Files to exclude from scanning
EXCLUDE_FILES: Final[set[str]] = {
    ".gitignore",
    ".gitattributes",
    "README.md",
    "LICENSE",
    "*.md",
    "*.txt",
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
}

# Gitignore patterns that indicate .env protection
ENV_GITIGNORE_PATTERNS: Final[list[str]] = [
    ".env",
    "*.env",
    "*.env.local",
    "*.env.*",
    ".env.local",
    ".env.*",
]

# Default max commits to scan in history
DEFAULT_MAX_COMMITS: int = 100

# Max file size to scan (10MB)
MAX_FILE_SIZE: int = 10 * 1024 * 1024
