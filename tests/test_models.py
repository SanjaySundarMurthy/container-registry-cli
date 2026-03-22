"""Tests for domain models."""

from container_registry_cli.models import (
    CleanupCandidate,
    CleanupRule,
    CleanupSeverity,
    Image,
    ImageLayer,
    PolicyAction,
    RegistryReport,
    RegistryType,
    Vulnerability,
    VulnerabilitySeverity,
)


class TestVulnerability:
    def test_fixable(self, sample_vuln):
        assert sample_vuln.is_fixable is True

    def test_not_fixable(self):
        v = Vulnerability(
            cve_id="CVE-2024-0001",
            severity=VulnerabilitySeverity.MEDIUM,
            package="zlib",
        )
        assert v.is_fixable is False


class TestImageTag:
    def test_size_mb(self, sample_tag):
        assert sample_tag.size_mb == 100.0

    def test_age_days(self, sample_tag):
        assert 29 <= sample_tag.age_days <= 31

    def test_stale_tag_age(self, stale_tag):
        assert stale_tag.age_days >= 199


class TestImageLayer:
    def test_size_mb(self):
        layer = ImageLayer(digest="sha256:test", size_bytes=1048576)
        assert layer.size_mb == 1.0


class TestImage:
    def test_tag_count(self, sample_image):
        assert sample_image.tag_count == 2

    def test_total_size_mb(self, sample_image):
        assert sample_image.total_size_mb > 0

    def test_latest_tag(self, sample_image):
        latest = sample_image.latest_tag
        assert latest is not None
        assert latest.name == "v1.0.0"  # more recent

    def test_vuln_count(self, sample_image):
        counts = sample_image.vuln_count_by_severity
        assert counts.get("critical", 0) == 1

    def test_critical_vulns(self, sample_image):
        assert sample_image.critical_vulns == 1

    def test_empty_image(self):
        img = Image(repository="test/empty")
        assert img.tag_count == 0
        assert img.total_size_mb == 0.0
        assert img.latest_tag is None


class TestCleanupRule:
    def test_matches_old_tag(self, stale_tag):
        rule = CleanupRule(name="test", description="test", max_age_days=90)
        assert rule.matches_tag(stale_tag) is True

    def test_no_match_recent(self, sample_tag):
        rule = CleanupRule(name="test", description="test", max_age_days=90)
        assert rule.matches_tag(sample_tag) is False

    def test_pattern_match(self, dev_tag):
        rule = CleanupRule(name="test", description="test", delete_patterns=["dev-.*"])
        assert rule.matches_tag(dev_tag) is True

    def test_protected(self, sample_tag):
        rule = CleanupRule(name="test", description="test", keep_patterns=["v\\d+\\.\\d+\\.\\d+"])
        assert rule.is_protected(sample_tag) is True


class TestRegistryReport:
    def test_counts(self, sample_image, clean_image):
        report = RegistryReport(images=[sample_image, clean_image])
        assert report.image_count == 2
        assert report.total_tags == 3
        assert report.total_vulns == 1

    def test_empty_report(self):
        report = RegistryReport()
        assert report.image_count == 0
        assert report.total_tags == 0
        assert report.cleanup_count == 0

    def test_cleanup_count(self):
        report = RegistryReport(
            cleanup_candidates=[
                CleanupCandidate(
                    image="test/img",
                    tag="old",
                    reason="stale",
                    action=PolicyAction.DELETE,
                    size_mb=100.0,
                    age_days=200,
                    severity=CleanupSeverity.HIGH,
                )
            ]
        )
        assert report.cleanup_count == 1

    def test_registry_type_enum(self):
        from container_registry_cli.parser import detect_registry_type
        assert detect_registry_type("myregistry.azurecr.io") == RegistryType.ACR
