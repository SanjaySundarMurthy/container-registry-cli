"""Shared fixtures for container-registry-cli tests."""

from datetime import datetime, timedelta

import pytest

from container_registry_cli.models import (
    CleanupRule,
    Image,
    ImageLayer,
    ImageTag,
    PolicyAction,
    PolicyConfig,
    TagStatus,
    Vulnerability,
    VulnerabilitySeverity,
)


@pytest.fixture
def sample_tag():
    return ImageTag(
        name="v1.0.0",
        digest="sha256:abc123",
        created_at=datetime.now() - timedelta(days=30),
        size_bytes=104857600,  # 100MB
    )


@pytest.fixture
def stale_tag():
    return ImageTag(
        name="v0.5.0",
        digest="sha256:old456",
        created_at=datetime.now() - timedelta(days=200),
        size_bytes=157286400,
        status=TagStatus.STALE,
    )


@pytest.fixture
def dev_tag():
    return ImageTag(
        name="dev-feature-x",
        digest="sha256:dev789",
        created_at=datetime.now() - timedelta(days=45),
        size_bytes=167772160,
    )


@pytest.fixture
def sample_vuln():
    return Vulnerability(
        cve_id="CVE-2024-1234",
        severity=VulnerabilitySeverity.CRITICAL,
        package="openssl",
        installed_version="1.1.1k",
        fixed_version="1.1.1w",
    )


@pytest.fixture
def sample_image(sample_tag, stale_tag, sample_vuln):
    return Image(
        repository="myapp/backend",
        tags=[sample_tag, stale_tag],
        vulnerabilities=[sample_vuln],
        layers=[
            ImageLayer(digest="sha256:l1", size_bytes=52428800, command="FROM ubuntu"),
            ImageLayer(digest="sha256:l2", size_bytes=52428800, command="COPY . /app"),
        ],
        labels={"team": "backend"},
    )


@pytest.fixture
def clean_image():
    return Image(
        repository="myapp/frontend",
        tags=[
            ImageTag(
                name="v2.0.0",
                digest="sha256:clean01",
                created_at=datetime.now() - timedelta(days=5),
                size_bytes=52428800,
            )
        ],
        vulnerabilities=[],
        labels={"team": "frontend", "scanned": "true", "user": "appuser"},
    )


@pytest.fixture
def sample_policy():
    return PolicyConfig(
        rules=[
            CleanupRule(
                name="old-dev-branches",
                description="Remove old dev branch tags",
                max_age_days=30,
                delete_patterns=["dev-.*", "feature-.*"],
                action=PolicyAction.DELETE,
            ),
            CleanupRule(
                name="archive-old",
                description="Archive releases over 180 days",
                max_age_days=180,
                action=PolicyAction.ARCHIVE,
            ),
        ],
        global_max_age_days=90,
        global_max_tags_per_repo=50,
        protected_tags=["latest", "stable"],
    )


@pytest.fixture
def demo_dir(tmp_path):
    from container_registry_cli.demo import create_demo_project

    return create_demo_project(str(tmp_path / "demo"))
