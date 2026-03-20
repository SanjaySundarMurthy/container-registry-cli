"""Tests for analyzers."""

from datetime import datetime, timedelta
from container_registry_cli.analyzers.cleanup_engine import evaluate_cleanup, calculate_reclaimable_space
from container_registry_cli.analyzers.vuln_scanner import scan_images, VULN_RULES, SecurityReport
from container_registry_cli.models import (
    Image, ImageTag, Vulnerability, PolicyConfig, CleanupRule,
    VulnerabilitySeverity, TagStatus, PolicyAction,
)


class TestCleanupEngine:
    def test_stale_tag_detected(self, sample_image, sample_policy):
        candidates = evaluate_cleanup([sample_image], sample_policy)
        assert len(candidates) > 0

    def test_protected_tags_skipped(self):
        img = Image(
            repository="test/app",
            tags=[ImageTag(name="latest", digest="sha256:x", created_at=datetime.now() - timedelta(days=200), size_bytes=100)],
        )
        policy = PolicyConfig(protected_tags=["latest"], global_max_age_days=90)
        candidates = evaluate_cleanup([img], policy)
        assert all(c.tag != "latest" for c in candidates)

    def test_dev_branch_cleanup(self, dev_tag):
        img = Image(repository="test/app", tags=[dev_tag])
        policy = PolicyConfig(
            rules=[CleanupRule(name="dev", description="dev cleanup", delete_patterns=["dev-.*"], action=PolicyAction.DELETE)],
            protected_tags=["latest"],
        )
        candidates = evaluate_cleanup([img], policy)
        assert any(c.tag == "dev-feature-x" for c in candidates)

    def test_empty_images(self, sample_policy):
        assert evaluate_cleanup([], sample_policy) == []

    def test_reclaimable_space(self, sample_image, sample_policy):
        candidates = evaluate_cleanup([sample_image], sample_policy)
        space = calculate_reclaimable_space(candidates)
        assert space >= 0


class TestVulnScanner:
    def test_critical_vuln_detected(self, sample_image):
        report = scan_images([sample_image])
        rule_ids = {i.rule_id for i in report.issues}
        assert "REG-001" in rule_ids

    def test_clean_image_passes(self, clean_image):
        report = scan_images([clean_image])
        assert report.passed is True

    def test_no_scan_data_flagged(self):
        img = Image(repository="test/noscan", tags=[
            ImageTag(name="v1", digest="sha256:x", created_at=datetime.now(), size_bytes=100),
        ])
        report = scan_images([img])
        rule_ids = {i.rule_id for i in report.issues}
        assert "REG-004" in rule_ids

    def test_stale_tags_flagged(self):
        img = Image(repository="test/stale", tags=[
            ImageTag(name="old", digest="sha256:x", created_at=datetime.now() - timedelta(days=200), size_bytes=100),
        ], labels={"scanned": "true"})
        report = scan_images([img])
        rule_ids = {i.rule_id for i in report.issues}
        assert "REG-010" in rule_ids

    def test_large_image_flagged(self):
        img = Image(
            repository="test/big",
            tags=[ImageTag(name="v1", digest="sha256:x", created_at=datetime.now(), size_bytes=629145600)],
            labels={"scanned": "true"},
        )
        report = scan_images([img], size_threshold_mb=500.0)
        rule_ids = {i.rule_id for i in report.issues}
        assert "REG-007" in rule_ids

    def test_counts(self, sample_image):
        report = scan_images([sample_image])
        assert report.images_scanned == 1
        assert report.total_vulns == 1


class TestVulnRules:
    def test_all_rules_defined(self):
        assert len(VULN_RULES) == 10
        for i in range(1, 11):
            assert f"REG-{i:03d}" in VULN_RULES
