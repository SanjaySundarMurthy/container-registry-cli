"""Tests for CLI commands."""

from click.testing import CliRunner

from container_registry_cli.cli import main

runner = CliRunner()


class TestScanCommand:
    def test_scan(self, demo_dir):
        result = runner.invoke(main, ["scan", f"{demo_dir}/registry-manifest.yaml"])
        assert result.exit_code == 0

    def test_scan_json_stdout(self, demo_dir):
        result = runner.invoke(
            main, ["scan", f"{demo_dir}/registry-manifest.yaml", "--format", "json"]
        )
        assert result.exit_code == 0
        assert "registry" in result.output

    def test_scan_json_file(self, demo_dir, tmp_path):
        out = str(tmp_path / "report.json")
        result = runner.invoke(
            main,
            ["scan", f"{demo_dir}/registry-manifest.yaml", "--format", "json", "-o", out],
        )
        assert result.exit_code == 0

    def test_scan_html_file(self, demo_dir, tmp_path):
        out = str(tmp_path / "report.html")
        result = runner.invoke(
            main,
            ["scan", f"{demo_dir}/registry-manifest.yaml", "--format", "html", "-o", out],
        )
        assert result.exit_code == 0
        assert "HTML" in result.output

    def test_scan_html_no_output(self, demo_dir):
        result = runner.invoke(
            main, ["scan", f"{demo_dir}/registry-manifest.yaml", "--format", "html"]
        )
        assert result.exit_code == 0
        assert "requires" in result.output


class TestCleanupCommand:
    def test_cleanup_default(self, demo_dir):
        result = runner.invoke(main, ["cleanup", f"{demo_dir}/registry-manifest.yaml"])
        assert result.exit_code == 0

    def test_cleanup_with_policy(self, demo_dir):
        result = runner.invoke(
            main,
            [
                "cleanup", f"{demo_dir}/registry-manifest.yaml",
                "-p", f"{demo_dir}/cleanup-policy.yaml",
            ],
        )
        assert result.exit_code == 0

    def test_cleanup_json(self, demo_dir):
        result = runner.invoke(
            main, ["cleanup", f"{demo_dir}/registry-manifest.yaml", "--format", "json"]
        )
        assert result.exit_code == 0
        assert "candidates" in result.output


class TestAuditCommand:
    def test_audit(self, demo_dir):
        result = runner.invoke(main, ["audit", f"{demo_dir}/registry-manifest.yaml"])
        assert result.exit_code == 0

    def test_audit_json(self, demo_dir):
        result = runner.invoke(
            main, ["audit", f"{demo_dir}/registry-manifest.yaml", "--format", "json"]
        )
        assert result.exit_code == 0
        assert "passed" in result.output

    def test_audit_fail_on(self, demo_dir):
        result = runner.invoke(
            main, ["audit", f"{demo_dir}/registry-manifest.yaml", "--fail-on", "critical"]
        )
        assert result.exit_code in (0, 1)


class TestDemoCommand:
    def test_demo(self, tmp_path):
        out = str(tmp_path / "test-demo")
        result = runner.invoke(main, ["demo", "-o", out])
        assert result.exit_code == 0
        assert "Created" in result.output


class TestRulesCommand:
    def test_rules(self):
        result = runner.invoke(main, ["rules"])
        assert result.exit_code == 0
        assert "REG-001" in result.output


class TestVersion:
    def test_version(self):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output
