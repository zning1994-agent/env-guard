"""报告生成器 - 使用 Rich 库生成友好的终端输出."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

if TYPE_CHECKING:
    from .constants import LeakedSecret, SensitiveEntry
    from .gitignore_validator import GitignoreValidationResult


class Reporter:
    """使用 Rich 生成美观的终端报告."""

    def __init__(self, console: Console | None = None) -> None:
        """初始化报告器.

        Args:
            console: Rich Console 实例，默认创建新的
        """
        self.console = console or Console()

    def report_gitignore_validation(self, result: "GitignoreValidationResult") -> None:
        """报告 .gitignore 验证结果."""
        self.console.print()

        # 标题
        title = "🔍 Gitignore 验证结果"
        if result.status.value == "PASS":
            title += " [green]✓[/green]"
        elif result.status.value == "WARNING":
            title += " [yellow]⚠[/yellow]"
        else:
            title += " [red]✗[/red]"

        # 状态面板
        status_text = f"**状态**: {result.status.value}\n"
        status_text += f"**通过**: {result.pass_count} | **失败**: {result.fail_count} | **警告**: {result.warning_count}"

        if result.gitignore_path:
            status_text += f"\n**文件**: `{result.gitignore_path}`"
        else:
            status_text += "\n**文件**: 未找到"

        self.console.print(Panel(status_text, title=title, border_style="blue"))

        # 问题详情表格
        if result.issues:
            table = Table(title="验证详情", show_header=True, header_style="bold magenta")
            table.add_column("状态", width=10)
            table.add_column("规则", width=25)
            table.add_column("说明", min_width=50)

            for issue in result.issues:
                status_display = {
                    "PASS": "[green]✓ PASS[/green]",
                    "FAIL": "[red]✗ FAIL[/red]",
                    "WARNING": "[yellow]⚠ WARN[/yellow]",
                    "MISSING": "[red]✗ MISS[/red]",
                }.get(issue.status.value, issue.status.value)

                line_info = f"L{issue.line_number}" if issue.line_number else ""
                rule_display = f"{issue.rule} {line_info}"

                table.add_row(status_display, rule_display, issue.message)

            self.console.print(table)

        # 建议
        if result.recommendations:
            self.console.print()
            self.console.print(Rule("[bold]💡 建议[/bold]", style="yellow"))

            tree = Tree("改进建议:")
            for rec in result.recommendations:
                tree.add(f"[cyan]{rec}[/cyan]")

            self.console.print(tree)

        # 正确的配置示例
        if not result.is_valid or result.status.value == "WARNING":
            self.console.print()
            self.console.print(Panel(
                self._get_example_config(),
                title="📝 建议的 .gitignore 配置",
                border_style="green",
            ))

        self.console.print()

    def _get_example_config(self) -> str:
        """获取示例 .gitignore 配置."""
        return """# Environment files
.env
.env.*
!.env.example
!.env.sample
"""

    def report_scanner_results(
        self,
        entries: list["SensitiveEntry"],
        show_values: bool = False,
    ) -> None:
        """报告扫描结果.

        Args:
            entries: 扫描到的敏感条目列表
            show_values: 是否显示敏感值（默认不显示）
        """
        self.console.print()

        if not entries:
            self.console.print(Panel(
                "[green]✓ 未检测到敏感信息泄露[/green]",
                title="🔍 扫描结果",
                border_style="green",
            ))
            return

        # 统计
        by_level = {}
        for entry in entries:
            level = entry.sensitivity_level.value
            by_level[level] = by_level.get(level, 0) + 1

        stats_text = "\n".join(
            f"- {level}: {count} 个" for level, count in sorted(by_level.items())
        )

        self.console.print(Panel(
            f"[bold]共发现 {len(entries)} 个敏感字段[/bold]\n\n{stats_text}",
            title="🔍 扫描结果",
            border_style="red",
        ))

        # 详情表格
        table = Table(title="敏感信息详情", show_header=True, header_style="bold magenta")
        table.add_column("文件", width=30)
        table.add_column("行号", width=8, justify="center")
        table.add_column("键名", width=25)
        table.add_column("等级", width=10)
        table.add_column("值", width=25)

        for entry in entries:
            level_color = {
                "CRITICAL": "[red]CRITICAL[/red]",
                "HIGH": "[red]HIGH[/red]",
                "MEDIUM": "[yellow]MEDIUM[/yellow]",
                "LOW": "[green]LOW[/green]",
            }.get(entry.sensitivity_level.value, entry.sensitivity_level.value)

            value_display = entry.value if show_values else "[red]***[/red]"

            table.add_row(
                entry.file_path,
                str(entry.line_number),
                entry.key,
                level_color,
                value_display,
            )

        self.console.print(table)
        self.console.print()

    def report_git_check_results(
        self,
        staged_leaks: list["LeakedSecret"],
        history_leaks: list["LeakedSecret"],
    ) -> None:
        """报告 Git 检查结果.

        Args:
            staged_leaks: Staged files 中的泄露
            history_leaks: Git history 中的泄露
        """
        self.console.print()

        total = len(staged_leaks) + len(history_leaks)

        if total == 0:
            self.console.print(Panel(
                "[green]✓ Git 中未检测到敏感信息泄露[/green]",
                title="🔍 Git 安全检查",
                border_style="green",
            ))
            return

        self.console.print(Panel(
            f"[bold red]⚠ 共发现 {total} 处敏感信息泄露[/bold red]\n"
            f"- Staged files: {len(staged_leaks)} 处\n"
            f"- Git history: {len(history_leaks)} 处",
            title="🔍 Git 安全检查",
            border_style="red",
        ))

        # Staged files 详情
        if staged_leaks:
            self.console.print()
            self.console.print(Rule("[bold red]⚠ Staged Files 泄露[/bold red]"))
            self._print_leak_table(staged_leaks)

        # History 详情
        if history_leaks:
            self.console.print()
            self.console.print(Rule("[bold red]⚠ Git History 泄露[/bold red]"))
            self._print_leak_table(history_leaks)

        self.console.print()

    def _print_leak_table(self, leaks: list["LeakedSecret"]) -> None:
        """打印泄露详情表格."""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("位置", width=30)
        table.add_column("行号", width=8, justify="center")
        table.add_column("Commit", width=12)
        table.add_column("预览", min_width=40)
        table.add_column("等级", width=10)

        for leak in leaks:
            level_color = {
                "CRITICAL": "[red]CRITICAL[/red]",
                "HIGH": "[red]HIGH[/red]",
                "MEDIUM": "[yellow]MEDIUM[/yellow]",
                "LOW": "[green]LOW[/green]",
            }.get(leak.sensitivity_level.value, leak.sensitivity_level.value)

            commit = leak.commit_hash[:8] if leak.commit_hash else "staged"

            table.add_row(
                leak.file_path,
                str(leak.line_number),
                commit,
                leak.content_preview,
                level_color,
            )

        self.console.print(table)

    def print_summary(
        self,
        gitignore_ok: bool,
        env_scanned: int,
        secrets_found: int,
        git_leaks: int,
    ) -> None:
        """打印整体摘要.

        Args:
            gitignore_ok: .gitignore 配置是否正确
            env_scanned: 扫描的 .env 文件数
            secrets_found: 发现的敏感字段数
            git_leaks: Git 中的泄露数
        """
        self.console.print()

        overall_status = "✅ 安全" if (gitignore_ok and secrets_found == 0 and git_leaks == 0) else "⚠️ 存在风险"

        self.console.print(Panel(
            f"[bold]{overall_status}[/bold]\n\n"
            f"- .gitignore 配置: {'✓ 正确' if gitignore_ok else '✗ 需要修复'}\n"
            f"- .env 文件扫描: {env_scanned} 个\n"
            f"- 敏感字段: {secrets_found} 个\n"
            f"- Git 泄露: {git_leaks} 处",
            title="📊 安全检查摘要",
            border_style="blue",
        ))
