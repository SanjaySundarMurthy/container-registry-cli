"""Tests for demo module."""

from pathlib import Path

import yaml

from container_registry_cli.demo import create_demo_project


class TestCreateDemoProject:
    def test_creates_directory(self, tmp_path):
        output = tmp_path / "test-demo"
        result = create_demo_project(str(output))

        assert Path(result).exists()
        assert Path(result).is_dir()

    def test_creates_manifest(self, tmp_path):
        output = tmp_path / "demo"
        create_demo_project(str(output))

        manifest_path = output / "registry-manifest.yaml"
        assert manifest_path.exists()

        data = yaml.safe_load(manifest_path.read_text())
        assert "images" in data
        assert len(data["images"]) >= 3

    def test_creates_policy(self, tmp_path):
        output = tmp_path / "demo"
        create_demo_project(str(output))

        policy_path = output / "cleanup-policy.yaml"
        assert policy_path.exists()

        data = yaml.safe_load(policy_path.read_text())
        assert "rules" in data
        assert "global_max_age_days" in data
        assert "protected_tags" in data

    def test_manifest_has_backend_image(self, tmp_path):
        output = tmp_path / "demo"
        create_demo_project(str(output))

        manifest_path = output / "registry-manifest.yaml"
        data = yaml.safe_load(manifest_path.read_text())

        repos = [img["repository"] for img in data["images"]]
        assert "myapp/backend" in repos

    def test_manifest_has_vulnerabilities(self, tmp_path):
        output = tmp_path / "demo"
        create_demo_project(str(output))

        manifest_path = output / "registry-manifest.yaml"
        data = yaml.safe_load(manifest_path.read_text())

        backend = next(img for img in data["images"] if "backend" in img["repository"])
        assert len(backend["vulnerabilities"]) >= 2

    def test_policy_has_rules(self, tmp_path):
        output = tmp_path / "demo"
        create_demo_project(str(output))

        policy_path = output / "cleanup-policy.yaml"
        data = yaml.safe_load(policy_path.read_text())

        assert len(data["rules"]) >= 2
        rule_names = [r["name"] for r in data["rules"]]
        assert "stale-dev-branches" in rule_names

    def test_returns_path_string(self, tmp_path):
        output = tmp_path / "demo"
        result = create_demo_project(str(output))

        assert isinstance(result, str)
        assert str(output) in result

    def test_default_output_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = create_demo_project()

        assert Path(result).exists()
        assert "demo-registry" in result

    def test_nested_output_dir(self, tmp_path):
        output = tmp_path / "nested" / "deep" / "demo"
        result = create_demo_project(str(output))

        assert Path(result).exists()
