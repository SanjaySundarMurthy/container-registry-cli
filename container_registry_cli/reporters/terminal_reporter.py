"""Rich terminal reporter for registry analysis."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ..models import RegistryReport, CleanupCandidate, PolicyAction, CleanupSeverity
from ..analyzers.vuln_scanner import SecurityReport, VulnerabilitySeverity

console = Console()

SEVERITY_COLORS = {
    "critical": "red",
    "high": "bright_red",
    "medium": "yellow",
    "low": "blue",
    "negligible": "dim",
}


def print_registry_report(report: RegistryReport) -> None:
    """Print registry overview."""
    console.print()
    header = Text()
    header.append("Container Registry Analysis\n", style="bold")
    header.append(f"Registry: ", style="dim")
    header.append(f"{report.registry_url or 'local'}\n", style="bold cyan")
    header.append(f"Type: ", style="dim")
    header.append(f"{report.registry_type.value}\n", style="bold")
    header.append(f"Images: ", style="dim")
    header.append(f"{report.image_count}  ", style="bold")
    header.append(f"Tags: ", style="dim")
    header.append(f"{report.total_tags}  ", style="bold")
    header.append(f"Vulns: ", style="dim")
    vuln_color = "red" if report.total_vulns > 0 else "green"
    header.append(f"{report.total_vulns}", style=f"bold {vuln_color}")

    console.print(Panel(header, title="[bold]container-registry-cli[/bold]", border_style="blue"))

    if not report.images:
        return

    table = Table(title="Images", show_lines=True)
    table.add_column("Repository", style="cyan")
    table.add_column("Tags", justify="right")
    table.add_column("Size (MB)", justify="right")
    table.add_column("Vulns", justify="right")
    table.add_column("Critical", justify="right")

    for img in report.images:
        crit = img.critical_vulns
        crit_color = "red" if crit > 0 else "green"
        table.add_row(
            img.repository,
            str(img.tag_count),
            f"{img.total_size_mb:.1f}",
            str(len(img.vulnerabilities)),
            f"[{crit_color}]{crit}[/{crit_color}]",
        )

    console.print(table)


def print_cleanup_report(candidates: list[CleanupCandidate], reclaimable_mb: float) -> None:
    """Print cleanup candidates."""
    console.print()
    console.print(Panel(
        f"Cleanup Candidates: {len(candidates)}\n"
        f"Reclaimable Space: [bold]{reclaimable_mb:.1f} MB[/bold]",
        title="[bold]Cleanup Analysis[/bold]",
        border_style="yellow",
    ))

    if not candidates:
        console.print("[green]No cleanup candidates found.[/green]")
        return

    table = Table(title="Candidates", show_lines=True)
    table.add_column("Image", style="cyan")
    table.add_column("Tag", style="bold")
    table.add_column("Age (days)", justify="right")
    table.add_column("Size (MB)", justify="right")
    table.add_column("Action")
    table.add_column("Reason")

    action_colors = {
        PolicyAction.DELETE: "red",
        PolicyAction.ARCHIVE: "yellow",
        PolicyAction.WARN: "blue",
        PolicyAction.SKIP: "dim",
    }

    for c in candidates:
        color = action_colors.get(c.action, "white")
        table.add_row(
            c.image,
            c.tag,
            str(c.age_days),
            f"{c.size_mb:.1f}",
            f"[{color}]{c.action.value.upper()}[/{color}]",
            c.reason[:50],
        )

    console.print(table)


def print_security_report(report: SecurityReport) -> None:
    """Print security scan results."""
    console.print()
    status = "[green]✓ PASSED[/green]" if report.passed else "[red]✗ FAILED[/red]"
    console.print(Panel(
        f"Status: {status}\n"
        f"Images Scanned: {report.images_scanned}\n"
        f"Total Vulnerabilities: {report.total_vulns}\n"
        f"Fixable: {report.fixable_vulns}",
        title="[bold]Security Report[/bold]",
        border_style="red" if not report.passed else "green",
    ))

    if not report.issues:
        return

    table = Table(title="Security Issues", show_lines=True)
    table.add_column("Rule", style="bold", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Image", style="cyan")
    table.add_column("Message")

    for issue in report.issues:
        color = SEVERITY_COLORS.get(issue.severity.value, "white")
        table.add_row(
            issue.rule_id,
            f"[{color}]{issue.severity.value.upper()}[/{color}]",
            issue.image,
            issue.message,
        )

    console.print(table)
