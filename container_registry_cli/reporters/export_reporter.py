"""Export reporter for JSON and HTML output."""

import json
from pathlib import Path

from ..analyzers.vuln_scanner import SecurityReport
from ..models import RegistryReport


def export_json(report: RegistryReport, security: SecurityReport, output_path: str) -> str:
    """Export full report as JSON."""
    data = {
        "registry": {
            "url": report.registry_url,
            "type": report.registry_type.value,
            "image_count": report.image_count,
            "total_tags": report.total_tags,
            "total_size_mb": report.total_size_mb,
            "total_vulns": report.total_vulns,
        },
        "images": [
            {
                "repository": img.repository,
                "tag_count": img.tag_count,
                "total_size_mb": img.total_size_mb,
                "vulnerabilities": img.vuln_count_by_severity,
                "critical_vulns": img.critical_vulns,
                "tags": [
                    {
                        "name": t.name,
                        "size_mb": t.size_mb,
                        "age_days": t.age_days,
                        "status": t.status.value,
                    }
                    for t in img.tags
                ],
            }
            for img in report.images
        ],
        "security": {
            "passed": security.passed,
            "images_scanned": security.images_scanned,
            "total_vulns": security.total_vulns,
            "fixable_vulns": security.fixable_vulns,
            "issues": [
                {
                    "rule_id": i.rule_id,
                    "severity": i.severity.value,
                    "image": i.image,
                    "message": i.message,
                }
                for i in security.issues
            ],
        },
        "cleanup": {
            "candidates": len(report.cleanup_candidates),
            "reclaimable_mb": report.reclaimable_size_mb,
            "items": [
                {
                    "image": c.image,
                    "tag": c.tag,
                    "action": c.action.value,
                    "reason": c.reason,
                    "size_mb": c.size_mb,
                    "age_days": c.age_days,
                }
                for c in report.cleanup_candidates
            ],
        },
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return str(path)


def export_html(report: RegistryReport, security: SecurityReport, output_path: str) -> str:
    """Export HTML report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    images_html = ""
    for img in report.images:
        crit = img.critical_vulns
        crit_color = "#dc3545" if crit > 0 else "#28a745"
        images_html += (
            "<tr>"
            f"<td>{img.repository}</td>"
            f"<td>{img.tag_count}</td>"
            f"<td>{img.total_size_mb:.1f}</td>"
            f"<td>{len(img.vulnerabilities)}</td>"
            f'<td style="color:{crit_color};font-weight:bold">{crit}</td>'
            "</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Container Registry Report</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; max-width: 960px;
               margin: 0 auto; padding: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
        th, td {{ border: 1px solid #dee2e6; padding: 8px; text-align: left; }}
        th {{ background: #f8f9fa; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr);
                  gap: 12px; margin: 16px 0; }}
        .stat {{ background: #f8f9fa; padding: 16px; border-radius: 4px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Container Registry Report</h1>
    <div class="stats">
        <div class="stat"><div class="stat-value">{report.image_count}</div>Images</div>
        <div class="stat"><div class="stat-value">{report.total_tags}</div>Tags</div>
        <div class="stat"><div class="stat-value">{report.total_size_mb:.0f} MB</div>
        Total Size</div>
        <div class="stat"><div class="stat-value">{report.total_vulns}</div>Vulnerabilities</div>
    </div>
    <h2>Images</h2>
    <table>
        <tr><th>Repository</th><th>Tags</th><th>Size (MB)</th><th>Vulns</th><th>Critical</th></tr>
        {images_html}
    </table>
</body>
</html>"""

    path.write_text(html, encoding="utf-8")
    return str(path)
