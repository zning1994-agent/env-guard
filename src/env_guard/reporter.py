"""env-guard 报告输出模块

使用 Rich 库格式化终端输出
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from env_guard.models import (
    LeakResult,
    ScanResult,
    SensitivityLevel,
    ValidationResult,
    ValidationStatus,
)


class Reporter:
    """报告输出器"""

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()

    def report_scan_result(self, result: ScanResult) -> None:
        """报告扫描结果"""
        if result.has_secrets:
            self._report_secrets_found(result)
        else:
            self._report_no_secrets(result)

    def _report_secrets_found(self, result: ScanResult) -> None:
        """报告发现敏感信息"""
        self.console.print()
        self.console.print(
            Panel(
                f"[bold red]⚠️  发现 {len(result.sensitive_entries)} 个敏感条目[/bold red]",
                title="扫描结果",
                border_style="red",
            )
        )

        # 统计各等级敏感信息
        stats = self._count_by_level(result)
        if stats:
            stats_table = Table(show_header=True, header_style="bold")
            stats_table.add_column("风险等级", style="bold")
            stats_table.add_column("数量", justify="right")

            if stats.get(SensitivityLevel.CRITICAL):
                stats_table.add_row(
                    "[red]CRITICAL[/red]", str(stats[SensitivityLevel.CRITICAL])
                )
            if stats.get(SensitivityLevel.HIGH):
                stats_table.add_row(
                    "[orange1]HIGH[/orange1]", str(stats[SensitivityLevel.HIGH])
                )
            if stats.get(SensitivityLevel.MEDIUM):
                stats_table.add_row(
                    "[yellow]MEDIUM[/yellow]", str(stats[SensitivityLevel.MEDIUM])
                )
            if stats.get(SensitivityLevel.LOW):
                stats_table.add_row(
                    "[green]LOW[/green]", str(stats[SensitivityLevel.LOW])
                )

            self.console.print(stats_table)
            self.console.print()

        # 详细表格
        self._print_sensitive_table(result)

    def _report_no_secrets(self, result: ScanResult) -> None:
        """报告未发现敏感信息"""
        self.console.print()
        self.console.print(
            Panel(
                "[bold green]✅ 未发现敏感信息[/bold green]\n\n"
                f"扫描了 {len(result.scanned_files)} 个文件\n"
                f"共 {result.total_lines_scanned} 行代码",
                title="扫描结果",
                border_style="green",
            )
        )

    def _print_sensitive_table(self, result: ScanResult) -> None:
        """打印敏感信息表格"""
        table = Table(
            title="敏感信息详情",
            show_header=True,
            header_style="bold magenta",
            box=None,
        )

        table.add_column("文件", style="cyan", no_wrap=True)
        table.add_column("行", style="magenta", justify="right")
        table.add_column("键名", style="yellow")
        table.add_column("值", style="red")
        table.add_column("风险", style="bold")

        for entry in result.sensitive_entries:
            level_color = {
                SensitivityLevel.CRITICAL: "red",
                SensitivityLevel.HIGH: "orange1",
                SensitivityLevel.MEDIUM: "yellow",
                SensitivityLevel.LOW: "green",
            }.get(entry.sensitivity_level, "white")

            level_text = Text(entry.sensitivity_level.value, style=level_color)

            # 截断过长的值
            value_display = entry.value
            if len(value_display) > 30:
                value_display = value_display[:27] + "..."

            table.add_row(
                entry.file_path,
                str(entry.line_number),
                entry.key,
                value_display,
                level_text,
            )

        self.console.print(table)

    def report_leak_results(self, leaks: list[LeakResult], source: str = "leaks") -> None:
        """报告泄露检测结果"""
        if leaks:
            self.console.print()
            self.console.print(
                Panel(
                    f"[bold red]⚠️  发现 {len(leaks)} 处泄露[/bold red]",
                    title=f"{source} 检测结果",
                    border_style="red",
                )
            )

            if source == "history":
                self.console.print(
                    "[yellow]建议: 使用 git filter-branch 或 BFG Repo-Cleaner 清理历史[/yellow]"
                )
                self.console.print()

            self._print_leak_table(leaks)
        else:
            self.console.print()
            self.console.print(
                Panel(
                    f"[bold green]✅ {source} 中未发现敏感信息[/bold green]",
                    title="检测结果",
                    border_style="green",
                )
            )

    def _print_leak_table(self, leaks: list[LeakResult]) -> None:
        """打印泄露信息表格"""
        table = Table(
            title="泄露详情",
            show_header=True,
            header_style="bold magenta",
            box=None,
        )

        table.add_column("提交", style="cyan", no_wrap=True)
        table.add_column("文件", style="yellow")
        table.add_column("行", style="magenta", justify="right")
        table.add_column("泄露内容", style="red")
        table.add_column("类型", style="bold")

        for leak in leaks:
            commit = leak.commit_hash[:7] if leak.commit_hash else "STAGED"
            content = leak.content_preview
            if len(content) > 40:
                content = content[:37] + "..."

            table.add_row(
                commit,
                leak.file_path,
                str(leak.line_number),
                content,
                leak.matched_pattern,
            )

        self.console.print(table)

    def report_validation_result(self, result: ValidationResult) -> None:
        """报告 .gitignore 验证结果"""
        self.console.print()

        if result.critical_count > 0:
            style = "red"
            title = f"[bold red]❌ 发现 {result.critical_count} 个配置问题[/bold red]"
        elif result.warning_count > 0:
            style = "yellow"
            title = f"[bold yellow]⚠️  发现 {result.warning_count} 个警告[/bold yellow]"
        else:
            style = "green"
            title = "[bold green]✅ .gitignore 配置正确[/bold green]"

        self.console.print(Panel(title, border_style=style))

        if result.issues:
            self._print_validation_table(result)

    def _print_validation_table(self, result: ValidationResult) -> None:
        """打印验证问题表格"""
        table = Table(
            title="验证问题详情",
            show_header=True,
            header_style="bold magenta",
            box=None,
        )

        table.add_column("状态", style="bold", justify="center")
        table.add_column("规则", style="cyan")
        table.add_column("描述", style="yellow")
        table.add_column("建议", style="green")

        for issue in result.issues:
            status_icon = {
                ValidationStatus.VALID: "[green]✅[/green]",
                ValidationStatus.INVALID: "[red]❌[/red]",
                ValidationStatus.MISSING: "[red]❗[/red]",
                ValidationStatus.WARNING: "[yellow]⚠️[/yellow]",
            }.get(issue.status, "?")

            suggestion = issue.suggestion or "-"
            if len(suggestion) > 50:
                suggestion = suggestion[:47] + "..."

            table.add_row(
                status_icon,
                issue.rule,
                issue.message,
                suggestion,
            )

        self.console.print(table)

    def _count_by_level(self, result: ScanResult) -> dict[SensitivityLevel, int]:
        """统计各等级敏感信息数量"""
        counts: dict[SensitivityLevel, int] = {}
        for entry in result.sensitive_entries:
            level = entry.sensitivity_level
            counts[level] = counts.get(level, 0) + 1
        return counts

    def save_json_report(self, data: dict, output_path: Path) -> None:
        """保存 JSON 格式报告"""
        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.console.print(f"\n报告已保存到: [cyan]{output_path}[/cyan]")

    def show_progress(self, description: str = "处理中..."):
        """显示进度条"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        )
