"""敏感信息检测常量定义"""

# 敏感键名正则模式
SENSITIVE_KEY_PATTERNS: list[str] = [
    r"^(api[_\-]?key|apikey)$",
    r"^(secret|password|passwd|pwd)$",
    r"^(token|auth|bearer|jwt)$",
    r"^(private[_\-]?key|privkey)$",
    r"^(access[_\-]?key|aws[_\-]?key)$",
    r"^.*(credential|secret|token|key|passwd).*$",
    r"^(xox[cbaprs]|github|bearer|aws).*$",
]

# 常见泄露模式（用于匹配值中的敏感信息）
LEAK_PATTERNS: list[str] = [
    r"sk\-[a-zA-Z0-9]{20,}",  # OpenAI API key
    r"sk\-[a-zA-Z0-9\-]{48}",  # OpenAI Project API key
    r"ghp_[a-zA-Z0-9]{36,}",  # GitHub Personal Access Token
    r"ghs_[a-zA-Z0-9]{36,}",  # GitHub Server Access Token
    r"ghu_[a-zA-Z0-9]{36,}",  # GitHub User Access Token
    r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
    r"(?i)amzn\.[a-zA-Z0-9]{20,}",  # AWS Secret Access Key
    r"xox[baprs]\-[a-zA-Z0-9]{10,}",  # Slack tokens
    r"msteams_[a-zA-Z0-9]{20,}",  # Microsoft Teams tokens
    r"sq0[a-z]{3}\-[a-zA-Z0-9]{22}",  # Square OAuth
]

# 高风险关键词（不区分大小写匹配键名）
HIGH_RISK_KEYWORDS: list[str] = [
    "password",
    "secret",
    "api_key",
    "apikey",
    "token",
    "private_key",
    "access_key",
    "auth_token",
    "bearer",
    "credential",
]

# 环境变量文件名称模式
ENV_FILENAME_PATTERNS: list[str] = [
    r"^\.env$",
    r"^\.env\.",
    r"^\.envrc$",
    r"^\.flaskenv$",
    r"^\.Renviron$",
    r"^config\.env$",
    r"^application\.env$",
]

# 风险等级定义
RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# .gitignore 中应包含的 .env 相关规则
REQUIRED_GITIGNORE_RULES: list[str] = [
    ".env",
    ".env.local",
    ".env.*.local",
]
