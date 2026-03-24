"""Tests for export_reporter module."""

import json
from pathlib import Path

from container_registry_cli.analyzers.vuln_scanner import SecurityIssue, SecurityReport
from container_registry_cli.models import (
    CleanupCandidate,
    CleanupSeverity,
    Image,
    ImageTag,
    PolicyAction,
    RegistryReport,
    RegistryType,
    Vulnerability,
    VulnerabilitySeverity,
)
from container_registry_cli.reporters.export_reporter import export_html, export_json


class TestExportJson:
    def test_export_creates_file(self, tmp_path):
        report = RegistryReport(registry_url="test.azurecr.io", registry_type=RegistryType.ACR)
        security = SecurityReport()
        output = tmp_path / "report.json"

        result = export_json(report, security, str(output))

        assert Path(result).exists()
        data = json.loads(output.read_text())
        assert data["registry"]["url"] == "test.azurecr.io"

    def test_export_with_images(self, tmp_path, sample_image):
        report = RegistryReport(
            images=[sample_image],
            total_size_mb=sample_image.total_size_mb,
        )
        security = SecurityReport(
            images_scanned=1,
            total_vulns=1,
            issues=[
                SecurityIssue(
                    rule_id="REG-001",
                    message="Critical vuln",
                    severity=VulnerabilitySeverity.CRITICAL,
                    image="myapp/backend",
                )
            ],
        )
        output = tmp_path / "report.json"

        export_json(report, security, str(output))

        data = json.loads(output.read_text())
        assert len(data["images"]) == 1
        assert data["images"][0]["repository"] == "myapp/backend"
        assert len(data["security"]["issues"]) == 1

    def test_export_with_cleanup_candidates(self, tmp_path):
        report = RegistryReport(
            cleanup_candidates=[
                CleanupCandidate(
                    image="test/app",
                    tag="old",
                    reason="Too old",
                    action=PolicyAction.DELETE,
                    size_mb=100.0,
                    age_days=200,
                    severity=CleanupSeverity.HIGH,
                )
            ],
            reclaimable_size_mb=100.0,
        )
        security = SecurityReport()
        output = tmp_path / "report.json"

        export_json(report, security, str(output))

        data = json.loads(output.read_text())
        assert data["cleanup"]["candidates"] == 1
        assert data["cleanup"]["reclaimable_mb"] == 100.0

    def test_export_creates_parent_dirs(self, tmp_path):
        report = RegistryReport()
        security = SecurityReport()
        output = tmp_path / "nested" / "deep" / "report.json"

        result = export_json(report, security, str(output))

        assert Path(result).exists()


class TestExportHtml:
    def test_export_creates_file(self, tmp_path):
        report = RegistryReport()
        security = SecurityReport()
        output = tmp_path / "report.html"

        result = export_html(report, security, str(output))

        assert Path(result).exists()
        content = output.read_text()
        assert "<!DOCTYPE html>" in content
        assert "Container Registry Report" in content

    def test_export_with_images(self, tmp_path, sample_image):
        report = RegistryReport(
            images=[sample_image],
            total_size_mb=sample_image.total_size_mb,
        )
        security = SecurityReport()
        output = tmp_path / "report.html"

        export_html(report, security, str(output))

        content = output.read_text()
        assert "myapp/backend" in content

    def test_export_critical_vulns_highlighted(self, tmp_path):
        from datetime import datetime

        img = Image(
            repository="vuln/app",
            tags=[ImageTag(name="v1", digest="sha", created_at=datetime.now(), size_bytes=100)],
            vulnerabilities=[
                Vulnerability(cve_id="CVE-001", severity=VulnerabilitySeverity.CRITICAL)
            ],
        )
        report = RegistryReport(images=[img])
        security = SecurityReport()
        output = tmp_path / "report.html"

        export_html(report, security, str(output))

        content = output.read_text()
        assert "#dc3545" in content  # Red color for critical

    def test_export_creates_parent_dirs(self, tmp_path):
        report = RegistryReport()
        security = SecurityReport()
        output = tmp_path / "nested" / "report.html"

        result = export_html(report, security, str(output))

        assert Path(result).exists()
