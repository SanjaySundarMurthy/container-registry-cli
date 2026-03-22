"""Cleanup policy engine — evaluates images against cleanup rules."""

import re

from ..models import (
    CleanupCandidate,
    CleanupSeverity,
    Image,
    ImageTag,
    PolicyAction,
    PolicyConfig,
    TagStatus,
)


def evaluate_cleanup(images: list[Image], policy: PolicyConfig) -> list[CleanupCandidate]:
    """Evaluate all images against cleanup policy and return candidates."""
    candidates = []

    for image in images:
        # Apply each rule
        for rule in policy.rules:
            for tag in image.tags:
                if _is_protected(tag, policy.protected_tags):
                    continue
                if rule.is_protected(tag):
                    continue
                if rule.matches_tag(tag):
                    severity = _calculate_severity(tag, image)
                    candidates.append(CleanupCandidate(
                        image=image.repository,
                        tag=tag.name,
                        reason=f"Rule '{rule.name}': {rule.description}",
                        action=rule.action,
                        size_mb=tag.size_mb,
                        age_days=tag.age_days,
                        severity=severity,
                    ))

        # Global age check
        for tag in image.tags:
            if _is_protected(tag, policy.protected_tags):
                continue
            if tag.age_days > policy.global_max_age_days:
                already = any(c.image == image.repository and c.tag == tag.name for c in candidates)
                if not already:
                    candidates.append(CleanupCandidate(
                        image=image.repository,
                        tag=tag.name,
                        reason=f"Exceeds global max age ({policy.global_max_age_days} days)",
                        action=PolicyAction.WARN,
                        size_mb=tag.size_mb,
                        age_days=tag.age_days,
                        severity=CleanupSeverity.MEDIUM,
                    ))

        # Global max tags check
        if len(image.tags) > policy.global_max_tags_per_repo:
            sorted_tags = sorted(image.tags, key=lambda t: t.created_at)
            excess = len(image.tags) - policy.global_max_tags_per_repo
            for tag in sorted_tags[:excess]:
                if _is_protected(tag, policy.protected_tags):
                    continue
                already = any(c.image == image.repository and c.tag == tag.name for c in candidates)
                if not already:
                    candidates.append(CleanupCandidate(
                        image=image.repository,
                        tag=tag.name,
                        reason=f"Exceeds max tags per repo ({policy.global_max_tags_per_repo})",
                        action=PolicyAction.WARN,
                        size_mb=tag.size_mb,
                        age_days=tag.age_days,
                        severity=CleanupSeverity.LOW,
                    ))

    return candidates


def _is_protected(tag: ImageTag, protected_patterns: list[str]) -> bool:
    """Check if a tag matches any protected pattern."""
    for pattern in protected_patterns:
        if re.match(pattern, tag.name):
            return True
    return False


def _calculate_severity(tag: ImageTag, image: Image) -> CleanupSeverity:
    """Calculate cleanup severity based on tag and image properties."""
    if image.critical_vulns > 0 and tag.status == TagStatus.STALE:
        return CleanupSeverity.CRITICAL
    if tag.age_days > 180:
        return CleanupSeverity.HIGH
    if tag.age_days > 90:
        return CleanupSeverity.MEDIUM
    return CleanupSeverity.LOW


def calculate_reclaimable_space(candidates: list[CleanupCandidate]) -> float:
    """Calculate total reclaimable space in MB."""
    return sum(c.size_mb for c in candidates)
