"""GitignoreValidator 单元测试."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from env_guard.gitignore_validator import (
    GitignoreValidator,
    GitignoreValidationResult,
    ValidationStatus,
)
from env_guard.constants import SensitivityLevel


class TestGitignoreValidator:
    """GitignoreValidator 测试类."""

    @pytest.fixture
    def temp_project(self) -> Path:
        """创建临时项目目录."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_validate_missing_gitignore(self, temp_project: Path) -> None:
        """测试缺少 .gitignore 文件的情况."""
        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        assert result.gitignore_path is None
        assert result.status == ValidationStatus.FAIL
        assert result.is_valid is False
        assert result.fail_count >= 1
        assert any(
            issue.status == ValidationStatus.MISSING
            for issue in result.issues
        )

    def test_validate_empty_gitignore(self, temp_project: Path) -> None:
        """测试空的 .gitignore 文件."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text("# Empty gitignore\n", encoding="utf-8")

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        assert result.gitignore_path == gitignore
        assert result.status == ValidationStatus.FAIL
        assert result.is_valid is False
        assert result.fail_count >= 1

    def test_validate_correct_basic_rules(self, temp_project: Path) -> None:
        """测试正确的 .env 忽略规则."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            ".env\n.env.*\n.env.local\n.envrc\n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        assert result.status == ValidationStatus.PASS
        assert result.is_valid is True
        assert result.pass_count >= 3

    def test_validate_correct_wildcard_rule(self, temp_project: Path) -> None:
        """测试使用通配符的正确规则."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            "# Environment files\n.env\n.env.*\n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        assert result.is_valid is True
        assert result.warning_count == 0

    def test_validate_with_negation(self, temp_project: Path) -> None:
        """测试带有否定规则的情况."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            ".env\n.env.*\n!.env.example\n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        # 否定规则应该触发警告
        assert result.warning_count >= 1
        assert any(
            "否定规则" in issue.message or "取消忽略" in issue.message
            for issue in result.issues
        )

    def test_validate_partial_rules(self, temp_project: Path) -> None:
        """测试部分规则配置（应警告缺少某些规则）."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            ".env\n",  # 只忽略基础文件，不忽略 .env.*
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        assert result.status == ValidationStatus.WARNING
        assert result.is_valid is True
        assert result.warning_count >= 1

    def test_validate_envrc_rule(self, temp_project: Path) -> None:
        """测试 .envrc 规则."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            ".envrc\n.env\n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        assert result.pass_count >= 1

    def test_validate_duplicate_rules(self, temp_project: Path) -> None:
        """测试重复规则."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            ".env\n.env\n.env.*\n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        # 不应因此失败
        assert result.is_valid is True

    def test_validate_pattern_matching(self, temp_project: Path) -> None:
        """测试各种模式的匹配."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            ".env\n.env.local\n.env.production\n.env.development\n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        assert result.is_valid is True
        assert result.pass_count >= 3

    def test_generate_correct_config(self, temp_project: Path) -> None:
        """测试生成正确配置."""
        validator = GitignoreValidator(temp_project)
        config = validator.generate_correct_config()

        assert ".env" in config
        assert ".env.*" in config
        assert "!.env.example" in config

    def test_existing_rules_collection(self, temp_project: Path) -> None:
        """测试收集现有规则."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            "# Comments\n.env\nnode_modules/\n*.pyc\n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        assert ".env" in result.existing_rules
        assert "node_modules/" in result.existing_rules
        assert "*.pyc" in result.existing_rules

    def test_parse_gitignore_with_comments(self, temp_project: Path) -> None:
        """测试解析带有注释的 .gitignore."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            "# Environment files\n.env\n# Local files\n.env.local\n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        # 应该正确解析，忽略注释行
        assert len(result.existing_rules) == 2

    def test_parse_gitignore_with_inline_comments(self, temp_project: Path) -> None:
        """测试解析带有行内注释的规则."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            ".env  # ignore env files\n.env.local  # local override\n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        # 应该正确解析，移除行内注释
        assert ".env" in result.existing_rules
        assert ".env.local" in result.existing_rules

    def test_validate_with_whitespace_rules(self, temp_project: Path) -> None:
        """测试解析带有空白的规则."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            "  .env  \n  \n  .env.*  \n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        # 应该正确处理空白
        assert ".env" in result.existing_rules
        assert ".env.*" in result.existing_rules

    def test_validate_nested_directory_pattern(self, temp_project: Path) -> None:
        """测试嵌套目录模式."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            "config/.env\nconfig/.env.*\n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        # 应该识别为 .env 相关规则
        assert result.pass_count >= 1

    def test_validate_star_wildcard(self, temp_project: Path) -> None:
        """测试 * 通配符."""
        gitignore = temp_project / ".gitignore"
        gitignore.write_text(
            ".env*\n",
            encoding="utf-8",
        )

        validator = GitignoreValidator(temp_project)
        result = validator.validate()

        # 应该匹配 .env* 模式
        assert result.pass_count >= 1


class TestValidationResult:
    """ValidationResult 测试类."""

    def test_result_counts(self) -> None:
        """测试计数属性."""
        from env_guard.gitignore_validator import ValidationIssue

        result = GitignoreValidationResult(
            gitignore_path=Path(".gitignore"),
            status=ValidationStatus.WARNING,
            is_valid=True,
            issues=[
                ValidationIssue(".env", ValidationStatus.PASS, "OK"),
                ValidationIssue(".env.*", ValidationStatus.WARNING, "Warning"),
                ValidationIssue(".env.local", ValidationStatus.FAIL, "Fail"),
            ],
        )

        assert result.pass_count == 1
        assert result.warning_count == 1
        assert result.fail_count == 1

    def test_result_empty_issues(self) -> None:
        """测试空问题列表."""
        result = GitignoreValidationResult(
            gitignore_path=Path(".gitignore"),
            status=ValidationStatus.PASS,
            is_valid=True,
        )

        assert result.pass_count == 0
        assert result.warning_count == 0
        assert result.fail_count == 0


class TestIsCorrectRule:
    """测试 _is_correct_rule 方法."""

    def test_exact_matches(self) -> None:
        """测试精确匹配."""
        validator = GitignoreValidator()

        assert validator._is_correct_rule(".env") is True
        assert validator._is_correct_rule(".envrc") is True

    def test_env_ext_variants(self) -> None:
        """测试 .env 扩展变体."""
        validator = GitignoreValidator()

        assert validator._is_correct_rule(".env.local") is True
        assert validator._is_correct_rule(".env.production") is True
        assert validator._is_correct_rule(".env.development") is True
        assert validator._is_correct_rule(".env.staging") is True

    def test_invalid_patterns(self) -> None:
        """测试无效模式."""
        validator = GitignoreValidator()

        # 这些模式虽然会被 _matches_env_pattern 匹配，但 _is_correct_rule 应该返回 False
        assert validator._is_correct_rule(".env.localoverride") is False
        assert validator._is_correct_rule("env") is False
        assert validator._is_correct_rule("my.env") is False
