"""敏感信息常量定义"""

# 敏感键名模式（正则表达式）
SENSITIVE_KEY_PATTERNS: list[str] = [
    r"^(api[_\-]?key|apikey)$",
    r"^(secret|password|passwd|pwd)$",
    r"^(token|auth|bearer|jwt)$",
    r"^(private[_\-]?key|privkey)$",
    r"^(access[_\-]?key|aws[_\-]?key)$",
    r"^.*(credential|secret|token|key).*$",
    r"^(db[_\-]?pass|database[_\-]?pass)$",
    r"^.*(password|passwd|pwd).*$",
]

# 常见泄露模式（正则表达式）
LEAK_PATTERNS: list[str] = [
    r"sk-[a-zA-Z0-9]{20,}",          # OpenAI API key
    r"ghp_[a-zA-Z0-9]{36,}",         # GitHub Personal Access Token
    r"ghs_[a-zA-Z0-9]{36,}",         # GitHub Server Access Token
    r"ghu_[a-zA-Z0-9]{36,}",         # GitHub User Access Token
    r"AKIA[0-9A-Z]{16}",            # AWS Access Key ID
    r"[a-zA-Z0-9/+=]{40,}",         # Generic Base64 encoded secret (40+ chars)
    r"xox[baprs]-[a-zA-Z0-9]{10,}", # Slack Token
    r"sq0[a-z]{3}-[a-zA-Z0-9]{22}", # Square OAuth Secret
    r"sq0csp-[a-zA-Z0-9]{43}",      # Square OAuth Secret
    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",  # Private Key
]

# 高风险关键词（用于快速扫描）
HIGH_RISK_KEYWORDS: list[str] = [
    "api_key",
    "apikey",
    "secret_key",
    "access_token",
    "auth_token",
    "private_key",
    "password",
    "passwd",
    "pwd",
    "credentials",
]

# .env 文件名模式
ENV_FILENAME_PATTERNS: list[str] = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.test",
    ".env.example",
    ".env.sample",
    "env.local",
    "env.development",
    "env.production",
]

# 安全的默认值（用于测试）
SAFE_TEST_VALUES: list[str] = [
    "true",
    "false",
    "null",
    "none",
    "0",
    "1",
    "local",
    "development",
    "production",
    "test",
]
