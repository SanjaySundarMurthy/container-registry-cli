"""Demo project generator for container-registry-cli."""

from pathlib import Path

import yaml


def _tag(name: str, digest: str, days: int, size_bytes: int, **kwargs) -> dict:
    return {"name": name, "digest": digest, "created_at": days, "size_bytes": size_bytes, **kwargs}


def _vuln(cve_id: str, severity: str, package: str, installed: str, fixed: str = "") -> dict:
    return {
        "cve_id": cve_id,
        "severity": severity,
        "package": package,
        "installed_version": installed,
        "fixed_version": fixed,
    }


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
                    _tag("latest", "sha256:abc123", 2, 157_286_400),
                    _tag("v2.1.0", "sha256:abc124", 10, 157_286_400),
                    _tag("v2.0.0", "sha256:abc125", 45, 152_043_520),
                    _tag("v1.9.0", "sha256:abc126", 120, 148_897_792),
                    _tag("v1.8.0", "sha256:abc127", 200, 145_752_064, status="stale"),
                    _tag("dev-feature-x", "sha256:abc128", 95, 162_529_280),
                ],
                "vulnerabilities": [
                    _vuln("CVE-2024-1234", "critical", "openssl", "1.1.1k", "1.1.1w"),
                    _vuln("CVE-2024-5678", "high", "curl", "7.68.0", "7.88.1"),
                    _vuln("CVE-2024-9012", "medium", "zlib", "1.2.11"),
                ],
                "layers": [
                    {"digest": "sha256:l1", "size_bytes": 52_428_800,
                     "command": "FROM ubuntu:22.04"},
                    {"digest": "sha256:l2", "size_bytes": 31_457_280,
                     "command": "RUN apt-get update"},
                    {"digest": "sha256:l3", "size_bytes": 73_400_320,
                     "command": "COPY . /app"},
                ],
                "labels": {"environment": "production", "team": "backend"},
            },
            {
                "repository": "myapp/frontend",
                "tags": [
                    _tag("latest", "sha256:def001", 1, 52_428_800),
                    _tag("v3.0.0", "sha256:def002", 5, 52_428_800),
                    _tag("v2.9.0", "sha256:def003", 30, 48_234_496),
                ],
                "vulnerabilities": [
                    _vuln("CVE-2024-3456", "low", "busybox", "1.33", "1.36"),
                ],
                "labels": {"team": "frontend", "user": "appuser"},
            },
            {
                "repository": "myapp/worker",
                "tags": [
                    _tag("v1.0.0", "sha256:wkr001", 250, 209_715_200, status="stale"),
                    _tag("v0.9.0", "sha256:wkr002", 300, 204_472_320, status="stale"),
                ],
                "vulnerabilities": [
                    _vuln("CVE-2023-4567", "critical", "log4j", "2.14.0", "2.17.1"),
                    _vuln("CVE-2023-7890", "critical", "openssl", "1.0.2", "3.0.8"),
                    _vuln("CVE-2024-1111", "high", "glibc", "2.28", "2.35"),
                ],
                "labels": {"status": "deprecated", "environment": "production"},
            },
            {
                "repository": "myapp/cache",
                "tags": [
                    _tag("7.2", "sha256:redis01", 15, 31_457_280),
                ],
                "vulnerabilities": [],
                "labels": {"team": "infra", "user": "redis"},
            },
        ],
    }

    (root / "registry-manifest.yaml").write_text(
        yaml.dump(manifest, default_flow_style=False, sort_keys=False), encoding="utf-8"
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
        yaml.dump(policy, default_flow_style=False, sort_keys=False), encoding="utf-8"
    )

    return str(root)
