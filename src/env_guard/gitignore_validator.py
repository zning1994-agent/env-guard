"""Gitignore 配置验证器"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from env_guard.constants import REQUIRED_GITIGNORE_RULES


class ValidationStatus(Enum):
    """验证状态"""
    VALID = "valid"
    MISSING = "missing"
    INCORRECT = "incorrect"
    PARTIAL = "partial"


@dataclass
class RuleValidation:
    """单条规则验证结果"""
    pattern: str
    status: ValidationStatus
    exists: bool = False
    is_correct: bool = False
    actual_pattern: Optional[str] = None
    suggestion: Optional[str] = None


@dataclass
class ValidationResult:
    """验证结果"""
    file_path: Path
    rules: list[RuleValidation] = field(default_factory=list)
    is_complete: bool = False
    missing_rules: list[str] = field(default_factory=list)
    incorrect_rules: list[str] = field(default_factory=list)
    extra_rules: list[str] = field(default_factory=list)  # 额外添加的 .env 相关规则
    overall_status: ValidationStatus = ValidationStatus.MISSING
    
    @property
    def score(self) -> int:
        """计算配置完整度分数 (0-100)"""
        if not self.rules:
            return 0
        correct = sum(1 for r in self.rules if r.is_correct)
        return int(correct / len(self.rules) * 100)
    
    @property
    def has_issues(self) -> bool:
        return bool(self.missing_rules or self.incorrect_rules)


@dataclass
class ValidationSummary:
    """验证汇总"""
    total_repos_checked: int = 0
    fully_configured: int = 0
    partially_configured: int = 0
    not_configured: int = 0
    total_missing_rules: int = 0


class GitignoreValidator:
    """Gitignore 配置验证器"""
    
    def __init__(self, required_rules: Optional[list[str]] = None):
        """
        初始化验证器
        
        Args:
            required_rules: 必须包含的规则列表
        """
        self._required_rules = required_rules or REQUIRED_GITIGNORE_RULES
        # 标准化规则（去除特殊字符）
        self._normalized_rules = [self._normalize_pattern(r) for r in self._required_rules]
    
    def _normalize_pattern(self, pattern: str) -> str:
        """标准化规则模式"""
        # 移除常见的通配符差异
        pattern = pattern.replace(".", r"\.")
        return pattern
    
    def validate(self, root: Path) -> ValidationResult:
        """
        验证 .gitignore 配置
        
        Args:
            root: 项目根目录
            
        Returns:
            ValidationResult: 验证结果
        """
        gitignore_path = root / ".gitignore"
        result = ValidationResult(file_path=gitignore_path)
        
        if not gitignore_path.exists():
            # .gitignore 不存在
            result.overall_status = ValidationStatus.MISSING
            for rule in self._required_rules:
                result.rules.append(RuleValidation(
                    pattern=rule,
                    status=ValidationStatus.MISSING,
                    suggestion=f"Add '{rule}' to .gitignore"
                ))
                result.missing_rules.append(rule)
            return result
        
        # 读取 .gitignore 内容
        try:
            with open(gitignore_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f.readlines()]
        except Exception as e:
            result.overall_status = ValidationStatus.INCORRECT
            return result
        
        # 分析每条必需规则
        found_rules: dict[str, bool] = {}
        
        for rule in self._required_rules:
            normalized_rule = self._normalize_pattern(rule)
            found = False
            actual_pattern = None
            
            for line in lines:
                # 跳过注释和空行
                if not line or line.startswith("#"):
                    continue
                
                # 精确匹配或通配符匹配
                if line == rule or line == normalized_rule:
                    found = True
                    actual_pattern = line
                    break
                elif self._pattern_matches(line, rule):
                    found = True
                    actual_pattern = line
                    break
            
            status = ValidationStatus.VALID if found else ValidationStatus.MISSING
            result.rules.append(RuleValidation(
                pattern=rule,
                status=status,
                exists=found,
                is_correct=found,
                actual_pattern=actual_pattern,
            ))
            
            if not found:
                result.missing_rules.append(rule)
            
            found_rules[rule] = found
        
        # 查找其他 .env 相关规则（用户可能添加了额外的）
        env_pattern = re.compile(r"\.env|env\.|\.envelope")
        for line in lines:
            if not line or line.startswith("#"):
                continue
            if env_pattern.search(line):
                # 检查是否在必需规则中
                if not any(self._pattern_matches(line, r) for r in self._required_rules):
                    result.extra_rules.append(line)
        
        # 确定整体状态
        if result.missing_rules:
            if result.extra_rules or any(r.exists for r in result.rules):
                result.overall_status = ValidationStatus.PARTIAL
            else:
                result.overall_status = ValidationStatus.MISSING
        else:
            result.overall_status = ValidationStatus.VALID
        
        result.is_complete = not result.missing_rules
        
        return result
    
    def _pattern_matches(self, line: str, rule: str) -> bool:
        """检查 .gitignore 行是否匹配规则"""
        # 精确匹配
        if line == rule:
            return True
        
        # 通配符匹配
        # .env 匹配 .env, .env.local, .env.production 等
        if rule == ".env":
            if line == ".env" or line.startswith(".env."):
                return True
        elif rule == ".env.local":
            if line == ".env.local":
                return True
        elif rule.startswith(".env.") and rule.endswith(".local"):
            if line == rule:
                return True
        
        return False
    
    def generate_recommendation(self, result: ValidationResult) -> str:
        """
        生成配置建议
        
        Args:
            result: 验证结果
            
        Returns:
            str: 建议内容
        """
        lines = ["# Recommended .gitignore rules for .env files:", ""]
        
        for rule in self._required_rules:
            if rule not in result.missing_rules:
                lines.append(f"# {rule} - OK")
            else:
                lines.append(f"{rule}  # MISSING - Recommended")
        
        if result.extra_rules:
            lines.append("")
            lines.append("# Extra .env rules found:")
            for rule in result.extra_rules:
                lines.append(f"# {rule} - Already configured")
        
        return "\n".join(lines)


# 便捷函数
def validate_gitignore(path: Path) -> ValidationResult:
    """验证 .gitignore 配置的便捷函数"""
    validator = GitignoreValidator()
    return validator.validate(path)
