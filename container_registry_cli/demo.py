"""Demo project generator for container-registry-cli."""

from pathlib import Path

import yaml


def create_demo_project(output_dir: str = "demo-registry") -> str:
    """Create a demo registry manifest and policy for testing."""
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)

    # Registry manifest with varied images
    manifest = {
        "images": [
            {
                "repository": "myapp/backend",
                "tags": [
                    {"name": "latest", "digest": "sha256:abc123", "created_at": 2, "size_bytes": 157286400},
                    {"name": "v2.1.0", "digest": "sha256:abc124", "created_at": 10, "size_bytes": 157286400},
                    {"name": "v2.0.0", "digest": "sha256:abc125", "created_at": 45, "size_bytes": 152043520},
                    {"name": "v1.9.0", "digest": "sha256:abc126", "created_at": 120, "size_bytes": 148897792},
                    {"name": "v1.8.0", "digest": "sha256:abc127", "created_at": 200, "size_bytes": 145752064, "status": "stale"},
                    {"name": "dev-feature-x", "digest": "sha256:abc128", "created_at": 95, "size_bytes": 162529280},
                ],
                "vulnerabilities": [
                    {"cve_id": "CVE-2024-1234", "severity": "critical", "package": "openssl", "installed_version": "1.1.1k", "fixed_version": "1.1.1w"},
                    {"cve_id": "CVE-2024-5678", "severity": "high", "package": "curl", "installed_version": "7.68.0", "fixed_version": "7.88.1"},
                    {"cve_id": "CVE-2024-9012", "severity": "medium", "package": "zlib", "installed_version": "1.2.11", "fixed_version": ""},
                ],
                "layers": [
                    {"digest": "sha256:l1", "size_bytes": 52428800, "command": "FROM ubuntu:22.04"},
                    {"digest": "sha256:l2", "size_bytes": 31457280, "command": "RUN apt-get update"},
                    {"digest": "sha256:l3", "size_bytes": 73400320, "command": "COPY . /app"},
                ],
                "labels": {"environment": "production", "team": "backend"},
            },
            {
                "repository": "myapp/frontend",
                "tags": [
                    {"name": "latest", "digest": "sha256:def001", "created_at": 1, "size_bytes": 52428800},
                    {"name": "v3.0.0", "digest": "sha256:def002", "created_at": 5, "size_bytes": 52428800},
                    {"name": "v2.9.0", "digest": "sha256:def003", "created_at": 30, "size_bytes": 48234496},
                ],
                "vulnerabilities": [
                    {"cve_id": "CVE-2024-3456", "severity": "low", "package": "busybox", "installed_version": "1.33", "fixed_version": "1.36"},
                ],
                "labels": {"team": "frontend"},
            },
            {
                "repository": "myapp/worker",
                "tags": [
                    {"name": "v1.0.0", "digest": "sha256:wkr001", "created_at": 250, "size_bytes": 209715200, "status": "stale"},
                    {"name": "v0.9.0", "digest": "sha256:wkr002", "created_at": 300, "size_bytes": 204472320, "status": "stale"},
                ],
                "vulnerabilities": [
                    {"cve_id": "CVE-2023-4567", "severity": "critical", "package": "log4j", "installed_version": "2.14.0", "fixed_version": "2.17.1"},
                    {"cve_id": "CVE-2023-7890", "severity": "critical", "package": "openssl", "installed_version": "1.0.2", "fixed_version": "3.0.8"},
                    {"cve_id": "CVE-2024-1111", "severity": "high", "package": "glibc", "installed_version": "2.28", "fixed_version": "2.35"},
                ],
                "labels": {"status": "deprecated", "environment": "production"},
            },
            {
                "repository": "myapp/cache",
                "tags": [
                    {"name": "7.2", "digest": "sha256:redis01", "created_at": 15, "size_bytes": 31457280},
                ],
                "vulnerabilities": [],
                "labels": {"team": "infra"},
            },
        ],
    }

    (root / "registry-manifest.yaml").write_text(
        yaml.dump(manifest, default_flow_style=False, sort_keys=False), encoding='utf-8'
    )

    # Cleanup policy
    policy = {
        "global_max_age_days": 90,
        "global_max_tags_per_repo": 5,
        "protected_tags": ["latest", "stable", "production", "v\\d+\\.\\d+\\.\\d+"],
        "rules": [
            {
                "name": "stale-dev-branches",
                "description": "Clean up old development branch tags",
                "max_age_days": 30,
                "delete_patterns": ["dev-.*", "feature-.*", "hotfix-.*"],
                "action": "delete",
            },
            {
                "name": "old-releases",
                "description": "Archive releases older than 180 days",
                "max_age_days": 180,
                "action": "archive",
            },
            {
                "name": "untagged-cleanup",
                "description": "Remove untagged manifests",
                "delete_patterns": ["sha256:.*"],
                "action": "delete",
            },
        ],
    }

    (root / "cleanup-policy.yaml").write_text(
        yaml.dump(policy, default_flow_style=False, sort_keys=False), encoding='utf-8'
    )

    return str(root)
