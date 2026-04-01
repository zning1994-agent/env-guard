"""env-guard CLI 命令行界面"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from env_guard import __version__
from env_guard.git_checker import GitChecker
from env_guard.gitignore_validator import GitignoreValidator
from env_guard.integrator import (
    CIIntegrator,
    IntegrationConfig,
    integrate_all,
    integrate_github_actions,
    integrate_gitlab_ci,
    integrate_pre_commit,
)
from env_guard.models import (
    SensitivityLevel,
    ValidationStatus,
)
from env_guard.scanner import EnvScanner

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="env-guard")
def main() -> None:
    """env-guard - Git 敏感信息泄露检测与修复工具"""
    pass


@main.command()
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=Path("."),
    help="扫描的目录路径",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="输出报告文件路径 (JSON 格式)",
)
@click.option("--verbose", "-v", is_flag=True, help="显示详细信息")
def scan(path: Path, output: Optional[Path], verbose: bool) -> None:
    """扫描 .env 文件中的敏感信息"""
    scanner = EnvScanner()
    result = scanner.scan_directory(path)

    if result.has_secrets:
        console.print(f"[bold red]⚠️  发现 {len(result.sensitive_entries)} 个敏感条目[/bold red]")
        _display_sensitive_entries(result)

        if output:
            _save_json_report(result, output)
            console.print(f"\n报告已保存到: {output}")

        sys.exit(1)
    else:
        console.print("[bold green]✅ 未发现敏感信息[/bold green]")

        if verbose:
            console.print(f"\n扫描了 {len(result.scanned_files)} 个文件")
            console.print(f"共扫描 {result.total_lines_scanned} 行代码")


@main.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="输出报告文件路径 (JSON 格式)",
)
@click.option("--verbose", "-v", is_flag=True, help="显示详细信息")
def scan_staged(output: Optional[Path], verbose: bool) -> None:
    """扫描 staged files 中的敏感信息"""
    checker = GitChecker()
    leaks = checker.check_staged_files()

    if leaks:
        console.print(f"[bold red]⚠️  在 staged files 中发现 {len(leaks)} 处泄露[/bold red]")
        _display_leak_results(leaks)

        if output:
            _save_leak_json_report(leaks, output)
            console.print(f"\n报告已保存到: {output}")

        sys.exit(1)
    else:
        console.print("[bold green]✅ staged files 中未发现敏感信息[/bold green]")


@main.command()
@click.option(
    "--max-commits",
    "-n",
    type=int,
    default=100,
    help="最多扫描的提交数量",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="输出报告文件路径 (JSON 格式)",
)
@click.option("--verbose", "-v", is_flag=True, help="显示详细信息")
def scan_history(max_commits: int, output: Optional[Path], verbose: bool) -> None:
    """扫描 git history 中的敏感信息"""
    checker = GitChecker()
    leaks = checker.check_history(max_commits=max_commits)

    if leaks:
        console.print(
            f"[bold red]⚠️  在 git history 中发现 {len(leaks)} 处历史泄露[/bold red]"
        )
        console.print("[yellow]建议: 使用 git filter-branch 或 BFG Repo-Cleaner 清理历史[/yellow]")
        _display_leak_results(leaks)

        if output:
            _save_leak_json_report(leaks, output)
            console.print(f"\n报告已保存到: {output}")

        sys.exit(1)
    else:
        console.print("[bold green]✅ git history 中未发现敏感信息[/bold green]")


@main.command(name="check-gitignore")
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=Path("."),
    help="检查的目录路径",
)
@click.option("--fix", is_flag=True, help="自动修复问题")
def check_gitignore(path: Path, fix: bool) -> None:
    """验证 .gitignore 配置是否正确排除敏感文件"""
    validator = GitignoreValidator()
    result = validator.validate(path)

    if result.critical_count > 0:
        console.print(f"[bold red]❌ 发现 {result.critical_count} 个配置问题[/bold red]")
    elif result.warning_count > 0:
        console.print(f"[bold yellow]⚠️  发现 {result.warning_count} 个警告[/bold yellow]")
    else:
        console.print("[bold green]✅ .gitignore 配置正确[/bold green]")

    if result.issues:
        _display_validation_issues(result)

    if fix and result.issues:
        _fix_gitignore(path, result)


@main.command(name="integrate")
@click.option(
    "--github",
    "-g",
    is_flag=True,
    help="生成 GitHub Actions 配置",
)
@click.option(
    "--gitlab",
    "-l",
    is_flag=True,
    help="生成 GitLab CI 配置",
)
@click.option(
    "--pre-commit",
    "-p",
    is_flag=True,
    help="生成 pre-commit hook 脚本",
)
@click.option(
    "--all",
    "-a",
    "all_configs",
    is_flag=True,
    help="生成所有配置",
)
@click.option(
    "--project-name",
    type=str,
    default="my-project",
    help="项目名称",
)
@click.option(
    "--python-version",
    type=str,
    default="3.10",
    help="Python 版本",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("."),
    help="输出目录",
)
@click.option("--verbose", "-v", is_flag=True, help="显示详细信息")
def integrate(
    github: bool,
    gitlab: bool,
    pre_commit: bool,
    all_configs: bool,
    project_name: str,
    python_version: str,
    output_dir: Path,
    verbose: bool,
) -> None:
    """生成 CI/CD 集成配置和预提交钩子"""
    config = IntegrationConfig(
        project_name=project_name,
        python_version=python_version,
    )
    integrator = CIIntegrator(config)

    # 如果没有指定任何选项，显示帮助
    if not any([github, gitlab, pre_commit, all_configs]):
        console.print("[yellow]请使用 --github, --gitlab, --pre-commit 或 --all 指定要生成的配置[/yellow]")
        console.print("\n使用 --help 查看更多选项")
        return

    results: dict[str, str] = {}

    if all_configs or github:
        path = integrator.save_github_actions(output_dir)
        results["GitHub Actions"] = path
        console.print(f"[green]✅ GitHub Actions 配置已保存: {path}[/green]")

    if all_configs or gitlab:
        path = integrator.save_gitlab_ci(output_dir)
        results["GitLab CI"] = path
        console.print(f"[green]✅ GitLab CI 配置已保存: {path}[/green]")

    if all_configs or pre_commit:
        hook_path = integrator.save_pre_commit_hook(output_dir)
        config_path = integrator.save_pre_commit_config(output_dir)
        results["pre-commit hook"] = hook_path
        results["pre-commit config"] = config_path
        console.print(f"[green]✅ pre-commit hook 已保存: {hook_path}[/green]")
        console.print(f"[green]✅ pre-commit config 已保存: {config_path}[/green]")

    if all_configs:
        dockerfile_path = integrator.save_dockerfile(output_dir)
        results["Dockerfile"] = dockerfile_path
        console.print(f"[green]✅ Dockerfile 已保存: {dockerfile_path}[/green]")

    if verbose and results:
        console.print("\n[bold]生成的文件列表:[/bold]")
        for name, path in results.items():
            console.print(f"  - {name}: {path}")


def _display_sensitive_entries(result: "ScanResult") -> None:  # noqa: F821
    """显示敏感条目表格"""
    table = Table(title="敏感信息条目")
    table.add_column("文件", style="cyan")
    table.add_column("行号", style="magenta")
    table.add_column("键名", style="yellow")
    table.add_column("值", style="red")
    table.add_column("风险等级", style="bold")

    for entry in result.sensitive_entries:
        level_color = {
            SensitivityLevel.CRITICAL: "red",
            SensitivityLevel.HIGH: "orange1",
            SensitivityLevel.MEDIUM: "yellow",
            SensitivityLevel.LOW: "green",
        }.get(entry.sensitivity_level, "white")

        table.add_row(
            entry.file_path,
            str(entry.line_number),
            entry.key,
            entry.value,
            f"[{level_color}]{entry.sensitivity_level.value}[/{level_color}]",
        )

    console.print(table)


def _display_leak_results(leaks: list["LeakResult"]) -> None:  # noqa: F821
    """显示泄露结果表格"""
    table = Table(title="敏感信息泄露")
    table.add_column("提交", style="cyan")
    table.add_column("文件", style="yellow")
    table.add_column("行号", style="magenta")
    table.add_column("内容预览", style="red")
    table.add_column("类型", style="bold")

    for leak in leaks:
        commit = leak.commit_hash[:7] if leak.commit_hash else "STAGED"
        table.add_row(
            commit,
            leak.file_path,
            str(leak.line_number),
            leak.content_preview[:50] + "..." if len(leak.content_preview) > 50 else leak.content_preview,
            leak.matched_pattern,
        )

    console.print(table)


def _display_validation_issues(result: "ValidationResult") -> None:  # noqa: F821
    """显示验证问题"""
    table = Table(title=".gitignore 验证问题")
    table.add_column("状态", style="bold")
    table.add_column("规则", style="cyan")
    table.add_column("描述", style="yellow")
    table.add_column("建议", style="green")

    for issue in result.issues:
        status_icon = {
            ValidationStatus.VALID: "✅",
            ValidationStatus.INVALID: "❌",
            ValidationStatus.MISSING: "❗",
            ValidationStatus.WARNING: "⚠️",
        }.get(issue.status, "?")

        table.add_row(
            status_icon,
            issue.rule,
            issue.message,
            issue.suggestion or "-",
        )

    console.print(table)


def _save_json_report(result: "ScanResult", output: Path) -> None:  # noqa: F821
    """保存 JSON 格式的报告"""
    report = {
        "scanned_files": result.scanned_files,
        "total_lines_scanned": result.total_lines_scanned,
        "sensitive_entries": [
            {
                "key": e.key,
                "value": e.value,
                "line_number": e.line_number,
                "sensitivity_level": e.sensitivity_level.value,
                "matched_pattern": e.matched_pattern,
                "file_path": e.file_path,
            }
            for e in result.sensitive_entries
        ],
        "summary": {
            "total_entries": len(result.sensitive_entries),
            "critical_count": result.critical_count,
            "high_count": result.high_count,
        },
    }
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def _save_leak_json_report(leaks: list["LeakResult"], output: Path) -> None:  # noqa: F821
    """保存泄露报告为 JSON 格式"""
    report = {
        "total_leaks": len(leaks),
        "leaks": [
            {
                "commit_hash": l.commit_hash,
                "commit_message": l.commit_message,
                "file_path": l.file_path,
                "line_number": l.line_number,
                "content_preview": l.content_preview,
                "matched_pattern": l.matched_pattern,
                "sensitivity_level": l.sensitivity_level.value,
            }
            for l in leaks
        ],
    }
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def _fix_gitignore(path: Path, result: "ValidationResult") -> None:  # noqa: F821
    """修复 .gitignore 配置"""
    gitignore_path = path / ".gitignore"
    new_rules = []

    for issue in result.issues:
        if issue.suggestion:
            new_rules.append(f"# Added by env-guard\n{issue.suggestion}")

    if new_rules:
        with open(gitignore_path, "a", encoding="utf-8") as f:
            f.write("\n\n# === env-guard additions ===\n")
            f.write("\n".join(new_rules))
        console.print("[green]✅ .gitignore 已更新[/green]")


if __name__ == "__main__":
    main()
