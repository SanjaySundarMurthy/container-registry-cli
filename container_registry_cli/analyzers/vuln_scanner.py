"""Vulnerability scanner — analyzes image vulnerabilities."""

from dataclasses import dataclass, field

from ..models import Image, VulnerabilitySeverity

VULN_RULES = {
    "REG-001": "Image has critical vulnerabilities",
    "REG-002": "Image has high vulnerabilities with available fixes",
    "REG-003": "Image uses deprecated base image tag",
    "REG-004": "Image has no vulnerability scan data",
    "REG-005": "Image running as root (no USER instruction)",
    "REG-006": "Image has excessive layers (>15)",
    "REG-007": "Image size exceeds threshold",
    "REG-008": "Untagged image manifests found",
    "REG-009": "Image uses latest tag in production",
    "REG-010": "Image has stale tags (>180 days)",
}


@dataclass
class SecurityIssue:
    rule_id: str
    message: str
    severity: VulnerabilitySeverity
    image: str = ""
    details: str = ""


@dataclass
class SecurityReport:
    issues: list[SecurityIssue] = field(default_factory=list)
    images_scanned: int = 0
    total_vulns: int = 0
    fixable_vulns: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == VulnerabilitySeverity.CRITICAL)

    @property
    def passed(self) -> bool:
        return self.critical_count == 0


def scan_images(images: list[Image], size_threshold_mb: float = 500.0) -> SecurityReport:
    """Scan images for security issues."""
    issues = []
    total_vulns = 0
    fixable_vulns = 0

    for image in images:
        total_vulns += len(image.vulnerabilities)
        fixable_vulns += sum(1 for v in image.vulnerabilities if v.is_fixable)

        # REG-001: Critical vulns
        crit = image.critical_vulns
        if crit > 0:
            issues.append(
                SecurityIssue(
                    rule_id="REG-001",
                    message=f"{crit} critical vulnerabilities found",
                    severity=VulnerabilitySeverity.CRITICAL,
                    image=image.repository,
                )
            )

        # REG-002: High vulns with fixes
        high_fixable = sum(
            1
            for v in image.vulnerabilities
            if v.severity == VulnerabilitySeverity.HIGH and v.is_fixable
        )
        if high_fixable > 0:
            issues.append(
                SecurityIssue(
                    rule_id="REG-002",
                    message=f"{high_fixable} high vulnerabilities with available fixes",
                    severity=VulnerabilitySeverity.HIGH,
                    image=image.repository,
                )
            )

        # REG-003: Deprecated base tags
        deprecated_labels = ["deprecated", "eol", "end-of-life"]
        for label_key, label_val in image.labels.items():
            if any(d in str(label_val).lower() for d in deprecated_labels):
                issues.append(
                    SecurityIssue(
                        rule_id="REG-003",
                        message="Image uses deprecated base",
                        severity=VulnerabilitySeverity.MEDIUM,
                        image=image.repository,
                        details=f"{label_key}={label_val}",
                    )
                )
                break

        # REG-004: No scan data
        if not image.vulnerabilities and not image.labels.get("scanned"):
            issues.append(
                SecurityIssue(
                    rule_id="REG-004",
                    message="No vulnerability scan data available",
                    severity=VulnerabilitySeverity.MEDIUM,
                    image=image.repository,
                )
            )

        # REG-006: Excessive layers
        if len(image.layers) > 15:
            issues.append(
                SecurityIssue(
                    rule_id="REG-006",
                    message=f"Image has {len(image.layers)} layers (>15)",
                    severity=VulnerabilitySeverity.LOW,
                    image=image.repository,
                )
            )

        # REG-007: Size threshold
        if image.total_size_mb > size_threshold_mb:
            issues.append(
                SecurityIssue(
                    rule_id="REG-007",
                    message=f"Image size {image.total_size_mb:.1f}MB exceeds {size_threshold_mb}MB",
                    severity=VulnerabilitySeverity.LOW,
                    image=image.repository,
                )
            )

        # REG-008: Untagged manifests
        untagged = sum(1 for t in image.tags if t.name == "" or t.name.startswith("sha256:"))
        if untagged > 0:
            issues.append(
                SecurityIssue(
                    rule_id="REG-008",
                    message=f"{untagged} untagged manifests found",
                    severity=VulnerabilitySeverity.LOW,
                    image=image.repository,
                )
            )

        # REG-009: Latest tag
        has_latest = any(t.name == "latest" for t in image.tags)
        if has_latest and image.labels.get("environment") == "production":
            issues.append(
                SecurityIssue(
                    rule_id="REG-009",
                    message="'latest' tag used in production",
                    severity=VulnerabilitySeverity.HIGH,
                    image=image.repository,
                )
            )

        # REG-005: Running as root
        user_label = image.labels.get("user", "").lower()
        if user_label in ("", "root", "0"):
            issues.append(
                SecurityIssue(
                    rule_id="REG-005",
                    message="Image may run as root (no non-root USER configured)",
                    severity=VulnerabilitySeverity.MEDIUM,
                    image=image.repository,
                )
            )

        # REG-010: Stale tags
        stale = sum(1 for t in image.tags if t.age_days > 180)
        if stale > 0:
            issues.append(
                SecurityIssue(
                    rule_id="REG-010",
                    message=f"{stale} tags older than 180 days",
                    severity=VulnerabilitySeverity.LOW,
                    image=image.repository,
                )
            )

    return SecurityReport(
        issues=issues,
        images_scanned=len(images),
        total_vulns=total_vulns,
        fixable_vulns=fixable_vulns,
    )
