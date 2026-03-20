"""Tests for parser module."""

from pathlib import Path
from container_registry_cli.parser import (
    parse_registry_manifest, parse_policy_config, detect_registry_type,
)
from container_registry_cli.models import RegistryType, PolicyAction


class TestParseRegistryManifest:
    def test_parse_demo(self, demo_dir):
        images = parse_registry_manifest(f"{demo_dir}/registry-manifest.yaml")
        assert len(images) >= 3
        repos = [i.repository for i in images]
        assert "myapp/backend" in repos

    def test_parse_nonexistent(self):
        assert parse_registry_manifest("/nonexistent.yaml") == []

    def test_images_have_tags(self, demo_dir):
        images = parse_registry_manifest(f"{demo_dir}/registry-manifest.yaml")
        for img in images:
            assert img.tag_count > 0

    def test_images_have_vulns(self, demo_dir):
        images = parse_registry_manifest(f"{demo_dir}/registry-manifest.yaml")
        backend = next(i for i in images if "backend" in i.repository)
        assert len(backend.vulnerabilities) >= 2


class TestParsePolicyConfig:
    def test_parse_demo(self, demo_dir):
        policy = parse_policy_config(f"{demo_dir}/cleanup-policy.yaml")
        assert len(policy.rules) >= 2
        assert policy.global_max_age_days > 0

    def test_parse_nonexistent(self):
        policy = parse_policy_config("/nonexistent.yaml")
        assert len(policy.rules) == 0

    def test_rule_actions(self, demo_dir):
        policy = parse_policy_config(f"{demo_dir}/cleanup-policy.yaml")
        actions = {r.action for r in policy.rules}
        assert PolicyAction.DELETE in actions


class TestDetectRegistryType:
    def test_acr(self):
        assert detect_registry_type("myregistry.azurecr.io") == RegistryType.ACR

    def test_ecr(self):
        assert detect_registry_type("123456.dkr.ecr.us-east-1.amazonaws.com") == RegistryType.ECR

    def test_gcr(self):
        assert detect_registry_type("gcr.io/my-project") == RegistryType.GCR

    def test_docker_hub(self):
        assert detect_registry_type("docker.io/library") == RegistryType.DOCKER_HUB

    def test_ghcr(self):
        assert detect_registry_type("ghcr.io/user/repo") == RegistryType.GHCR

    def test_generic(self):
        assert detect_registry_type("registry.example.com") == RegistryType.GENERIC
