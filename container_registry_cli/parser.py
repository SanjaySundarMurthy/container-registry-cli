"""Registry manifest parser for YAML-based registry definitions."""

from pathlib import Path
from datetime import datetime, timedelta

import yaml

from .models import (
    Image, ImageTag, ImageLayer, Vulnerability, CleanupRule,
    PolicyConfig, RegistryType, VulnerabilitySeverity, TagStatus,
    PolicyAction, RegistryReport,
)


def parse_registry_manifest(filepath: str) -> list[Image]:
    """Parse a YAML registry manifest file into Image objects."""
    path = Path(filepath)
    if not path.exists():
        return []

    data = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not data or 'images' not in data:
        return []

    images = []
    for img_data in data['images']:
        tags = []
        for tag_data in img_data.get('tags', []):
            created = tag_data.get('created_at')
            if isinstance(created, str):
                created = datetime.fromisoformat(created)
            elif isinstance(created, int):
                created = datetime.now() - timedelta(days=created)
            else:
                created = datetime.now()

            tags.append(ImageTag(
                name=tag_data['name'],
                digest=tag_data.get('digest', f"sha256:{tag_data['name']}"),
                created_at=created,
                size_bytes=tag_data.get('size_bytes', 0),
                status=TagStatus(tag_data.get('status', 'active')),
                architecture=tag_data.get('architecture', 'amd64'),
                os=tag_data.get('os', 'linux'),
            ))

        vulns = []
        for vuln_data in img_data.get('vulnerabilities', []):
            vulns.append(Vulnerability(
                cve_id=vuln_data['cve_id'],
                severity=VulnerabilitySeverity(vuln_data.get('severity', 'low')),
                package=vuln_data.get('package', ''),
                installed_version=vuln_data.get('installed_version', ''),
                fixed_version=vuln_data.get('fixed_version', ''),
                description=vuln_data.get('description', ''),
            ))

        layers = []
        for layer_data in img_data.get('layers', []):
            layers.append(ImageLayer(
                digest=layer_data.get('digest', ''),
                size_bytes=layer_data.get('size_bytes', 0),
                command=layer_data.get('command', ''),
            ))

        images.append(Image(
            repository=img_data['repository'],
            tags=tags,
            vulnerabilities=vulns,
            layers=layers,
            labels=img_data.get('labels', {}),
        ))

    return images


def parse_policy_config(filepath: str) -> PolicyConfig:
    """Parse a YAML cleanup policy configuration."""
    path = Path(filepath)
    if not path.exists():
        return PolicyConfig()

    data = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not data:
        return PolicyConfig()

    rules = []
    for rule_data in data.get('rules', []):
        rules.append(CleanupRule(
            name=rule_data.get('name', 'unnamed'),
            description=rule_data.get('description', ''),
            max_age_days=rule_data.get('max_age_days', 0),
            max_tags=rule_data.get('max_tags', 0),
            keep_patterns=rule_data.get('keep_patterns', []),
            delete_patterns=rule_data.get('delete_patterns', []),
            action=PolicyAction(rule_data.get('action', 'warn')),
        ))

    return PolicyConfig(
        rules=rules,
        global_max_age_days=data.get('global_max_age_days', 90),
        global_max_tags_per_repo=data.get('global_max_tags_per_repo', 50),
        protected_tags=data.get('protected_tags', ['latest', 'stable', 'production']),
    )


def detect_registry_type(url: str) -> RegistryType:
    """Detect registry type from URL."""
    url_lower = url.lower()
    if 'azurecr.io' in url_lower:
        return RegistryType.ACR
    elif 'amazonaws.com' in url_lower or 'ecr' in url_lower:
        return RegistryType.ECR
    elif 'gcr.io' in url_lower:
        return RegistryType.GCR
    elif 'docker.io' in url_lower or 'hub.docker' in url_lower:
        return RegistryType.DOCKER_HUB
    elif 'ghcr.io' in url_lower:
        return RegistryType.GHCR
    return RegistryType.GENERIC
