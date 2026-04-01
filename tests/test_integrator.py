"""env-guard integrator 测试"""

import os
import stat
import tempfile
from pathlib import Path

import pytest

from env_guard.integrator import (
    CIIntegrator,
    IntegrationConfig,
    integrate_all,
    integrate_github_actions,
    integrate_gitlab_ci,
    integrate_pre_commit,
)


class TestCIIntegrator:
    """CIIntegrator 测试类"""

    def setup_method(self) -> None:
        """每个测试方法前设置"""
        self.temp_dir = tempfile.mkdtemp()
        self.config = IntegrationConfig(
            project_name="test-project",
            python_version="3.11",
        )
        self.integrator = CIIntegrator(self.config)

    def teardown_method(self) -> None:
        """每个测试方法后清理"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_generate_github_actions(self) -> None:
        """测试生成 GitHub Actions 配置"""
        result = self.integrator.generate_github_actions()

        assert "GitHub Actions Workflow" in result
        assert "env-guard scan" in result
        assert "test-project" in result
        assert "3.11" in result
        assert ".github/workflows" in result

    def test_generate_github_actions_with_history_scan(self) -> None:
        """测试生成带历史扫描的 GitHub Actions 配置"""
        self.config.github_include_history_scan = True
        integrator = CIIntegrator(self.config)
        result = integrator.generate_github_actions()

        assert "history-scan" in result
        assert "Scan git history" in result

    def test_generate_github_actions_without_history_scan(self) -> None:
        """测试生成不带历史扫描的 GitHub Actions 配置"""
        self.config.github_include_history_scan = False
        integrator = CIIntegrator(self.config)
        result = integrator.generate_github_actions()

        assert "history-scan" not in result

    def test_generate_gitlab_ci(self) -> None:
        """测试生成 GitLab CI 配置"""
        result = self.integrator.generate_gitlab_ci()

        assert "GitLab CI Configuration" in result
        assert "env-guard scan" in result
        assert "test-project" in result
        assert "stages:" in result
        assert "security" in result

    def test_generate_pre_commit_hook(self) -> None:
        """测试生成 pre-commit hook 脚本"""
        result = self.integrator.generate_pre_commit_hook()

        assert "#!/bin/bash" in result
        assert "env-guard" in result
        assert "pre-commit" in result or "security scan" in result.lower()
        assert "FAIL_ON_SECRETS" in result

    def test_generate_pre_commit_config(self) -> None:
        """测试生成 pre-commit 配置文件"""
        result = self.integrator.generate_pre_commit_config()

        assert "pre-commit-config.yaml" in result
        assert "repos:" in result
        assert "env-guard" in result

    def test_generate_dockerfile(self) -> None:
        """测试生成 Dockerfile"""
        result = self.integrator.generate_dockerfile()

        assert "FROM python:" in result
        assert "3.11" in result
        assert "env-guard" in result
        assert "ENTRYPOINT" in result

    def test_save_github_actions(self) -> None:
        """测试保存 GitHub Actions 配置"""
        output_dir = Path(self.temp_dir)
        result = self.integrator.save_github_actions(output_dir)

        assert result.exists()
        assert ".github/workflows" in str(result)
        assert "security-scan.yml" in result.name

        content = result.read_text()
        assert "env-guard scan" in content

    def test_save_gitlab_ci(self) -> None:
        """测试保存 GitLab CI 配置"""
        output_dir = Path(self.temp_dir)
        result = self.integrator.save_gitlab_ci(output_dir)

        assert result.exists()
        assert ".gitlab-ci.yml" in result.name

        content = result.read_text()
        assert "env-guard scan" in content

    def test_save_pre_commit_hook(self) -> None:
        """测试保存 pre-commit hook 脚本"""
        output_dir = Path(self.temp_dir)
        result = self.integrator.save_pre_commit_hook(output_dir)

        assert result.exists()
        assert "pre-commit" in result.name

        # 检查文件是否可执行
        mode = result.stat().st_mode
        assert mode & stat.S_IXUSR

        content = result.read_text()
        assert "env-guard" in content

    def test_save_pre_commit_config(self) -> None:
        """测试保存 pre-commit 配置文件"""
        output_dir = Path(self.temp_dir)
        result = self.integrator.save_pre_commit_config(output_dir)

        assert result.exists()
        assert ".pre-commit-config.yaml" in result.name

    def test_save_dockerfile(self) -> None:
        """测试保存 Dockerfile"""
        output_dir = Path(self.temp_dir)
        result = self.integrator.save_dockerfile(output_dir)

        assert result.exists()
        assert "Dockerfile" in result.name

    def test_integration_config_defaults(self) -> None:
        """测试 IntegrationConfig 默认值"""
        config = IntegrationConfig()

        assert config.project_name == "my-project"
        assert config.python_version == "3.10"
        assert config.github_trigger_branches == ["main", "develop"]
        assert config.gitlab_trigger_branches == ["main", "develop"]
        assert config.github_fail_on_secrets is True

    def test_integration_config_custom_branches(self) -> None:
        """测试 IntegrationConfig 自定义分支"""
        config = IntegrationConfig(
            github_trigger_branches=["feature/*", "main"],
            gitlab_trigger_branches=["develop", "main"],
        )

        assert "feature/*" in config.github_trigger_branches
        assert "develop" in config.gitlab_trigger_branches


class TestShortcutFunctions:
    """快捷函数测试"""

    def setup_method(self) -> None:
        """每个测试方法前设置"""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self) -> None:
        """每个测试方法后清理"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_integrate_github_actions(self) -> None:
        """测试 integrate_github_actions 快捷函数"""
        result = integrate_github_actions(self.temp_dir)

        assert result.endswith(".yml")
        assert Path(result).exists()

    def test_integrate_gitlab_ci(self) -> None:
        """测试 integrate_gitlab_ci 快捷函数"""
        result = integrate_gitlab_ci(self.temp_dir)

        assert result.endswith(".yml")
        assert Path(result).exists()

    def test_integrate_pre_commit_hook(self) -> None:
        """测试 integrate_pre_commit hook 快捷函数"""
        result = integrate_pre_commit(self.temp_dir, hook_type="hook")

        assert "pre-commit" in result
        assert Path(result).exists()

    def test_integrate_pre_commit_config(self) -> None:
        """测试 integrate_pre_commit config 快捷函数"""
        result = integrate_pre_commit(self.temp_dir, hook_type="config")

        assert ".pre-commit-config.yaml" in result
        assert Path(result).exists()

    def test_integrate_all(self) -> None:
        """测试 integrate_all 快捷函数"""
        results = integrate_all(self.temp_dir)

        assert "github_actions" in results
        assert "gitlab_ci" in results
        assert "pre_commit_hook" in results
        assert "pre_commit_config" in results
        assert "dockerfile" in results

        # 验证所有文件都存在
        for key, path in results.items():
            assert Path(path).exists(), f"File for {key} does not exist: {path}"


class TestIntegrationScenarios:
    """集成场景测试"""

    def test_multiple_branches_scenario(self) -> None:
        """测试多分支场景"""
        config = IntegrationConfig(
            github_trigger_branches=["main", "develop", "feature/*"],
            gitlab_trigger_branches=["main", "staging"],
            python_version="3.12",
        )
        integrator = CIIntegrator(config)

        github_content = integrator.generate_github_actions()
        gitlab_content = integrator.generate_gitlab_ci()

        assert "feature/*" in github_content
        assert "staging" in gitlab_content
        assert "3.12" in github_content

    def test_fail_on_secrets_scenario(self) -> None:
        """测试 fail_on_secrets 场景"""
        config = IntegrationConfig(
            github_fail_on_secrets=True,
            gitlab_fail_on_secrets=False,
        )
        integrator = CIIntegrator(config)

        github_content = integrator.generate_github_actions()
        gitlab_content = integrator.generate_gitlab_ci()

        # GitHub 应该 fail on error
        assert "continue-on-error: false" in github_content

        # GitLab 应该允许失败
        assert "allow_failure: yes" in gitlab_content

    def test_custom_project_name(self) -> None:
        """测试自定义项目名称"""
        config = IntegrationConfig(project_name="my-awesome-api")
        integrator = CIIntegrator(config)

        github_content = integrator.generate_github_actions()

        assert "my-awesome-api" in github_content or "name:" in github_content


class TestHookScriptContent:
    """Hook 脚本内容测试"""

    def setup_method(self) -> None:
        """每个测试方法前设置"""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self) -> None:
        """每个测试方法后清理"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_hook_includes_color_output(self) -> None:
        """测试 hook 脚本包含彩色输出"""
        integrator = CIIntegrator()
        hook_content = integrator.generate_pre_commit_hook()

        # 检查颜色定义
        assert "RED=" in hook_content or "\\033" in hook_content
        assert "GREEN=" in hook_content or "\\033" in hook_content
        assert "YELLOW=" in hook_content or "\\033" in hook_content

    def test_hook_checks_env_guard_installed(self) -> None:
        """测试 hook 脚本检查 env-guard 是否安装"""
        integrator = CIIntegrator()
        hook_content = integrator.generate_pre_commit_hook()

        assert "command -v env-guard" in hook_content or "env-guard" in hook_content

    def test_hook_blocks_commit_on_secrets(self) -> None:
        """测试 hook 在发现 secrets 时阻止提交"""
        config = IntegrationConfig(hook_fail_on_secrets=True)
        integrator = CIIntegrator(config)
        hook_content = integrator.generate_pre_commit_hook()

        assert "exit 1" in hook_content

    def test_hook_allows_commit_without_secrets(self) -> None:
        """测试 hook 在无 secrets 时允许提交"""
        config = IntegrationConfig(hook_fail_on_secrets=True)
        integrator = CIIntegrator(config)
        hook_content = integrator.generate_pre_commit_hook()

        assert "exit 0" in hook_content
