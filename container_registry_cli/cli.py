"""CLI entry point for container-registry-cli."""

import json
import click
from rich.console import Console

from .parser import parse_registry_manifest, parse_policy_config, detect_registry_type
from .analyzers.cleanup_engine import evaluate_cleanup, calculate_reclaimable_space
from .analyzers.vuln_scanner import scan_images, VULN_RULES
from .reporters.terminal_reporter import print_registry_report, print_cleanup_report, print_security_report
from .reporters.export_reporter import export_json, export_html
from .demo import create_demo_project
from .models import RegistryReport, PolicyConfig

console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="container-registry-cli")
def main():
    """Container image registry analyzer with cleanup policies and vulnerability scanning."""
    pass


@main.command()
@click.argument("manifest")
@click.option("--registry-url", default="", help="Registry URL")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]), default="terminal")
@click.option("--output", "-o", default=None, help="Output file for JSON/HTML")
def scan(manifest, registry_url, fmt, output):
    """Scan registry manifest and display image inventory."""
    images = parse_registry_manifest(manifest)
    reg_type = detect_registry_type(registry_url)
    security = scan_images(images)

    report = RegistryReport(
        registry_url=registry_url,
        registry_type=reg_type,
        images=images,
        total_size_mb=sum(i.total_size_mb for i in images),
    )

    if fmt == "json" and output:
        path = export_json(report, security, output)
        console.print(f"[green]✓[/green] Exported report: {path}")
    else:
        print_registry_report(report)
        print_security_report(security)


@main.command()
@click.argument("manifest")
@click.option("--policy", "-p", default=None, help="Cleanup policy YAML file")
@click.option("--max-age", default=90, help="Max tag age in days")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]), default="terminal")
def cleanup(manifest, policy, max_age, fmt):
    """Analyze images for cleanup candidates based on policy."""
    images = parse_registry_manifest(manifest)

    if policy:
        config = parse_policy_config(policy)
    else:
        config = PolicyConfig(global_max_age_days=max_age)

    candidates = evaluate_cleanup(images, config)
    reclaimable = calculate_reclaimable_space(candidates)

    if fmt == "json":
        data = {
            "candidates": len(candidates),
            "reclaimable_mb": reclaimable,
            "items": [
                {
                    "image": c.image, "tag": c.tag, "action": c.action.value,
                    "reason": c.reason, "size_mb": c.size_mb, "age_days": c.age_days,
                }
                for c in candidates
            ],
        }
        click.echo(json.dumps(data, indent=2))
    else:
        print_cleanup_report(candidates, reclaimable)


@main.command()
@click.argument("manifest")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium"]), default=None)
@click.option("--size-threshold", default=500.0, help="Image size warning threshold (MB)")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]), default="terminal")
def audit(manifest, fail_on, size_threshold, fmt):
    """Run security audit on registry images."""
    images = parse_registry_manifest(manifest)
    report = scan_images(images, size_threshold_mb=size_threshold)

    if fmt == "json":
        data = {
            "passed": report.passed,
            "images_scanned": report.images_scanned,
            "total_vulns": report.total_vulns,
            "fixable_vulns": report.fixable_vulns,
            "issues": [
                {"rule_id": i.rule_id, "severity": i.severity.value, "image": i.image, "message": i.message}
                for i in report.issues
            ],
        }
        click.echo(json.dumps(data, indent=2))
    else:
        print_security_report(report)

    if fail_on:
        from .models import VulnerabilitySeverity
        severity_order = ["critical", "high", "medium"]
        check_levels = severity_order[:severity_order.index(fail_on) + 1]
        has_issues = any(i.severity.value in check_levels for i in report.issues)
        if has_issues:
            raise SystemExit(1)


@main.command()
@click.option("--output-dir", "-o", default="demo-registry", help="Output directory")
def demo(output_dir):
    """Generate demo registry manifest and policy."""
    path = create_demo_project(output_dir)
    console.print(f"[green]✓[/green] Created demo project: [bold]{path}[/bold]")
    console.print("\nTry these commands:")
    console.print(f"  container-registry-cli scan {path}/registry-manifest.yaml")
    console.print(f"  container-registry-cli cleanup {path}/registry-manifest.yaml -p {path}/cleanup-policy.yaml")
    console.print(f"  container-registry-cli audit {path}/registry-manifest.yaml")


@main.command()
def rules():
    """List all security audit rules."""
    from rich.table import Table
    table = Table(title="Security Audit Rules", show_lines=True)
    table.add_column("Rule ID", style="bold")
    table.add_column("Description")

    for rule_id, desc in VULN_RULES.items():
        table.add_row(rule_id, desc)

    console.print(table)
