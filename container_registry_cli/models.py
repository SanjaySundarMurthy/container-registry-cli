"""Domain models for container registry analysis."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class RegistryType(Enum):
    ACR = "acr"
    ECR = "ecr"
    GCR = "gcr"
    DOCKER_HUB = "docker_hub"
    GHCR = "ghcr"
    GENERIC = "generic"


class VulnerabilitySeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class TagStatus(Enum):
    ACTIVE = "active"
    STALE = "stale"
    UNTAGGED = "untagged"
    DEPRECATED = "deprecated"


class PolicyAction(Enum):
    DELETE = "delete"
    ARCHIVE = "archive"
    WARN = "warn"
    SKIP = "skip"


class CleanupSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Vulnerability:
    cve_id: str
    severity: VulnerabilitySeverity
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    description: str = ""

    @property
    def is_fixable(self) -> bool:
        return bool(self.fixed_version)


@dataclass
class ImageLayer:
    digest: str
    size_bytes: int
    command: str = ""

    @property
    def size_mb(self) -> float:
        return self.size_bytes / (1024 * 1024)


@dataclass
class ImageTag:
    name: str
    digest: str
    created_at: datetime
    size_bytes: int
    status: TagStatus = TagStatus.ACTIVE
    architecture: str = "amd64"
    os: str = "linux"

    @property
    def size_mb(self) -> float:
        return self.size_bytes / (1024 * 1024)

    @property
    def age_days(self) -> int:
        return (datetime.now() - self.created_at).days


@dataclass
class Image:
    repository: str
    tags: list[ImageTag] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    layers: list[ImageLayer] = field(default_factory=list)
    labels: dict = field(default_factory=dict)

    @property
    def tag_count(self) -> int:
        return len(self.tags)

    @property
    def total_size_mb(self) -> float:
        if not self.tags:
            return 0.0
        return max(t.size_mb for t in self.tags)

    @property
    def latest_tag(self) -> Optional[ImageTag]:
        if not self.tags:
            return None
        return max(self.tags, key=lambda t: t.created_at)

    @property
    def vuln_count_by_severity(self) -> dict:
        counts: dict[str, int] = {}
        for v in self.vulnerabilities:
            key = v.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def critical_vulns(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL)


@dataclass
class CleanupRule:
    name: str
    description: str
    max_age_days: int = 0
    max_tags: int = 0
    keep_patterns: list[str] = field(default_factory=list)
    delete_patterns: list[str] = field(default_factory=list)
    action: PolicyAction = PolicyAction.WARN

    def matches_tag(self, tag: ImageTag) -> bool:
        import re

        if self.max_age_days > 0 and tag.age_days > self.max_age_days:
            return True
        return any(re.match(pattern, tag.name) for pattern in self.delete_patterns)

    def is_protected(self, tag: ImageTag) -> bool:
        import re

        return any(re.match(pattern, tag.name) for pattern in self.keep_patterns)


@dataclass
class CleanupCandidate:
    image: str
    tag: str
    reason: str
    action: PolicyAction
    size_mb: float
    age_days: int
    severity: CleanupSeverity = CleanupSeverity.LOW


@dataclass
class RegistryReport:
    registry_url: str = ""
    registry_type: RegistryType = RegistryType.GENERIC
    images: list[Image] = field(default_factory=list)
    cleanup_candidates: list[CleanupCandidate] = field(default_factory=list)
    total_size_mb: float = 0.0
    reclaimable_size_mb: float = 0.0

    @property
    def image_count(self) -> int:
        return len(self.images)

    @property
    def total_tags(self) -> int:
        return sum(i.tag_count for i in self.images)

    @property
    def total_vulns(self) -> int:
        return sum(len(i.vulnerabilities) for i in self.images)

    @property
    def cleanup_count(self) -> int:
        return len(self.cleanup_candidates)


@dataclass
class PolicyConfig:
    rules: list[CleanupRule] = field(default_factory=list)
    global_max_age_days: int = 90
    global_max_tags_per_repo: int = 50
    protected_tags: list[str] = field(default_factory=lambda: ["latest", "stable", "production"])
