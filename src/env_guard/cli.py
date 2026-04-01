"""命令行界面 - env-guard CLI."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from .constants import SensitivityLevel
from .gitignore_validator import GitignoreValidator, ValidationStatus
from .reporter import Reporter
from .scanner import EnvScanner


console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """env-guard - Git 敏感信息泄露检测与修复工具."""
    pass


@main.command()
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
    default=".",
    help="要扫描的路径（文件或目录）",
)
@click.option(
    "--show-values",
    "-v",
    is_flag=True,
    help="显示敏感值（默认不显示）",
)
def scan(path: Path, show_values: bool) -> None:
    """扫描 .env 文件中的敏感信息."""
    reporter = Reporter(console)

    scanner = EnvScanner()

    if path.is_file():
        entries = scanner.scan_file(path)
    else:
        entries = scanner.scan_directory(path)

    reporter.report_scanner_results(entries, show_values=show_values)


@main.command()
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=".",
    help="项目根目录",
)
@click.option(
    "--fix",
    "-f",
    is_flag=True,
    help="自动修复（生成正确的 .gitignore 配置）",
)
def check_gitignore(path: Path, fix: bool) -> None:
    """验证 .gitignore 配置是否正确保护 .env 文件."""
    reporter = Reporter(console)

    validator = GitignoreValidator(path)
    result = validator.validate()

    reporter.report_gitignore_validation(result)

    # 如果验证失败且用户请求修复
    if not result.is_valid and fix:
        console.print()
        console.print("[yellow]正在生成修复配置...[/yellow]")

        config = validator.generate_correct_config()
        gitignore_path = path / ".gitignore"

        if gitignore_path.exists():
            # 备份原文件
            backup_path = gitignore_path.with_suffix(".gitignore.backup")
            gitignore_path.rename(backup_path)
            console.print(f"[yellow]已备份原文件到 {backup_path}[/yellow]")

        gitignore_path.write_text(config, encoding="utf-8")
        console.print(f"[green]✓ 已生成 .gitignore 配置到 {gitignore_path}[/green]")

    sys.exit(0 if result.is_valid else 1)


@main.command()
@click.option(
    "--max-commits",
    "-n",
    type=int,
    default=100,
    help="检查的最多 commit 数量",
)
def check_git(max_commits: int) -> None:
    """检查 git 中的敏感信息泄露（staged files 和 history）."""
    reporter = Reporter(console)

    # TODO: 实现 git_checker.py 的调用
    # 目前仅验证 .gitignore
    console.print("[yellow]Git history 检查功能正在开发中...[/yellow]")

    validator = GitignoreValidator()
    result = validator.validate()
    reporter.report_gitignore_validation(result)


@main.command()
@click.option(
    "--path",
    "-p",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=".",
    help="项目根目录",
)
def all(path: Path) -> None:
    """运行所有检查（.gitignore + .env 扫描 + git 检查）."""
    reporter = Reporter(console)

    console.print("[bold blue]🚀 env-guard 全量检查[/bold blue]\n")

    # 1. 检查 .gitignore
    console.print("[bold]1. 验证 .gitignore 配置[/bold]")
    validator = GitignoreValidator(path)
    gitignore_result = validator.validate()
    reporter.report_gitignore_validation(gitignore_result)

    # 2. 扫描 .env 文件
    console.print("[bold]2. 扫描 .env 文件[/bold]")
    scanner = EnvScanner()
    entries = scanner.scan_directory(path)
    reporter.report_scanner_results(entries, show_values=False)

    # 3. 打印摘要
    reporter.print_summary(
        gitignore_ok=gitignore_result.is_valid,
        env_scanned=len(set(e.file_path for e in entries)),
        secrets_found=len(entries),
        git_leaks=0,  # TODO: git_checker 实现后更新
    )


if __name__ == "__main__":
    main()
