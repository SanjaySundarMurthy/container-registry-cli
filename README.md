# container-registry-cli

**Container image registry analyzer with cleanup policies and vulnerability scanning.**

Scan container registries, identify cleanup candidates based on tag policies, and audit images for security vulnerabilities — all from YAML manifests.

## Features

- **Registry Scanning** — Parse image manifests with tags, layers, and vulnerability data
- **Cleanup Policy Engine** — Evaluate images against configurable retention rules
- **Security Auditing** — 10 rules (REG-001 to REG-010) for image security
- **Multi-Registry Support** — ACR, ECR, GCR, Docker Hub, GHCR detection
- **Rich Terminal Output** — Color-coded tables with severity indicators
- **CI/CD Integration** — `--fail-on` flag for pipeline security gates

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
container-registry-cli demo
container-registry-cli scan demo-registry/registry-manifest.yaml
container-registry-cli cleanup demo-registry/registry-manifest.yaml -p demo-registry/cleanup-policy.yaml
container-registry-cli audit demo-registry/registry-manifest.yaml --fail-on critical
container-registry-cli rules
```

## Security Rules

| Rule | Description |
|------|-------------|
| REG-001 | Critical vulnerabilities found |
| REG-002 | High vulns with available fixes |
| REG-003 | Deprecated base image |
| REG-004 | No vulnerability scan data |
| REG-005 | Running as root |
| REG-006 | Excessive layers (>15) |
| REG-007 | Image size exceeds threshold |
| REG-008 | Untagged manifests |
| REG-009 | Latest tag in production |
| REG-010 | Stale tags (>180 days) |

## Testing

```bash
python -m pytest tests/ -v
```

## License

MIT

---

## Author

**Sanjay S** — [GitHub](https://github.com/SanjaySundarMurthy)
