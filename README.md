# container-registry-cli

[![CI](https://github.com/SanjaySundarMurthy/container-registry-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/SanjaySundarMurthy/container-registry-cli/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/container-registry-cli)](https://pypi.org/project/container-registry-cli/)
[![Python](https://img.shields.io/pypi/pyversions/container-registry-cli)](https://pypi.org/project/container-registry-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**Container image registry analyzer with cleanup policies, vulnerability scanning, and multi-format reporting — all from YAML manifests.**

Scan container registries, identify cleanup candidates based on tag retention policies, audit images against 10 security rules, and export rich terminal, JSON, or HTML reports. No registry credentials needed — works from declarative YAML.

---

## Features

| Feature | Description |
|---------|-------------|
| **Registry Scanning** | Parse image manifests with tags, layers, and vulnerability data |
| **Cleanup Policy Engine** | Evaluate images against configurable age, tag-count, and pattern rules |
| **Security Auditing** | 10 rules (REG-001 to REG-010) covering vulns, root user, image size, stale tags |
| **Multi-Registry Support** | Automatic detection — ACR, ECR, GCR, Docker Hub, GHCR |
| **Rich Terminal Output** | Color-coded tables with severity indicators via Rich |
| **JSON Export** | Full structured report to stdout or file |
| **HTML Export** | Standalone HTML report with summary stats and image table |
| **CI/CD Integration** | `--fail-on` flag for pipeline security gates (critical / high / medium) |
| **Demo Generator** | `demo` command scaffolds a complete sample registry + policy |

---

## Installation

```bash
pip install container-registry-cli
```

---

## Quick Start

```bash
# Generate a demo project with sample registry manifest and policy
container-registry-cli demo

# Scan and display image inventory
container-registry-cli scan demo-registry/registry-manifest.yaml

# Analyze cleanup candidates (terminal or JSON)
container-registry-cli cleanup demo-registry/registry-manifest.yaml -p demo-registry/cleanup-policy.yaml
container-registry-cli cleanup demo-registry/registry-manifest.yaml --format json

# Run security audit
container-registry-cli audit demo-registry/registry-manifest.yaml
container-registry-cli audit demo-registry/registry-manifest.yaml --fail-on critical

# Export reports
container-registry-cli scan demo-registry/registry-manifest.yaml --format json
container-registry-cli scan demo-registry/registry-manifest.yaml --format json -o report.json
container-registry-cli scan demo-registry/registry-manifest.yaml --format html -o report.html

# List all security rules
container-registry-cli rules
```

---

## Security Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| REG-001 | 🔴 Critical | Image has critical vulnerabilities |
| REG-002 | 🟠 High | Image has high vulnerabilities with available fixes |
| REG-003 | 🟡 Medium | Image uses deprecated base image tag |
| REG-004 | 🟡 Medium | No vulnerability scan data available |
| REG-005 | 🟡 Medium | Image may run as root (no non-root USER configured) |
| REG-006 | 🔵 Low | Image has excessive layers (>15) |
| REG-007 | 🔵 Low | Image size exceeds threshold (default 500 MB) |
| REG-008 | 🔵 Low | Untagged image manifests found |
| REG-009 | 🟠 High | `latest` tag used in production environment |
| REG-010 | 🔵 Low | Image has stale tags older than 180 days |

> `--fail-on critical|high|medium` exits with code 1 when issues at or above the given severity are found — perfect for CI gates.

---

## CLI Reference

### `scan` — inventory your registry

```
container-registry-cli scan <manifest> [OPTIONS]

Options:
  --registry-url TEXT           Registry URL for type detection
  --format [terminal|json|html] Output format (default: terminal)
  --output, -o FILE             Output file for json/html export
```

### `cleanup` — find cleanup candidates

```
container-registry-cli cleanup <manifest> [OPTIONS]

Options:
  --policy, -p FILE             Cleanup policy YAML file
  --max-age INT                 Global max tag age in days (default: 90)
  --format [terminal|json]      Output format (default: terminal)
```

### `audit` — run security rules

```
container-registry-cli audit <manifest> [OPTIONS]

Options:
  --fail-on [critical|high|medium]  Exit code 1 when issues at this level+
  --size-threshold FLOAT            Image size warning threshold MB (default: 500)
  --format [terminal|json]          Output format (default: terminal)
```

### `demo` — scaffold a sample project

```
container-registry-cli demo [OPTIONS]

Options:
  --output-dir, -o DIR   Output directory (default: demo-registry)
```

### `rules` — list all security rules

```
container-registry-cli rules
```

---

## Registry Manifest Format

```yaml
images:
  - repository: myapp/backend
    tags:
      - name: v2.1.0
        digest: sha256:abc123
        created_at: "2024-01-10T00:00:00"   # ISO datetime OR days-ago integer
        size_bytes: 157286400
        architecture: amd64
        os: linux
    vulnerabilities:
      - cve_id: CVE-2024-1234
        severity: critical
        package: openssl
        installed_version: 1.1.1k
        fixed_version: 1.1.1w
    layers:
      - digest: sha256:l1
        size_bytes: 52428800
        command: "FROM ubuntu:22.04"
    labels:
      environment: production
      team: backend
      user: appuser          # set to non-root to pass REG-005
```

## Cleanup Policy Format

```yaml
global_max_age_days: 90
global_max_tags_per_repo: 5
protected_tags: ["latest", "stable", "production"]

rules:
  - name: stale-dev-branches
    description: Clean up old dev branch tags
    max_age_days: 30
    delete_patterns: ["dev-.*", "feature-.*", "hotfix-.*"]
    action: delete    # delete | archive | warn | skip

  - name: old-releases
    description: Archive releases older than 180 days
    max_age_days: 180
    action: archive
```

---

## Output Formats

### Terminal (default)
Rich color-coded tables with severity colors and summary panels.

### JSON (stdout or file)
```bash
container-registry-cli scan manifest.yaml --format json          # to stdout
container-registry-cli scan manifest.yaml --format json -o r.json # to file
```

### HTML (file only)
Standalone HTML report with stats grid and full image table.
```bash
container-registry-cli scan manifest.yaml --format html -o report.html
```

---

## Project Structure

```
container-registry-cli/
├── container_registry_cli/
│   ├── cli.py                  # Click CLI entry point (scan, cleanup, audit, demo, rules)
│   ├── models.py               # Domain models (Image, ImageTag, Vulnerability, PolicyConfig …)
│   ├── parser.py               # YAML manifest & policy parser + registry type detection
│   ├── demo.py                 # Demo project generator
│   ├── analyzers/
│   │   ├── vuln_scanner.py     # 10-rule security scanner
│   │   └── cleanup_engine.py   # Policy evaluation engine
│   └── reporters/
│       ├── terminal_reporter.py # Rich terminal output
│       └── export_reporter.py   # JSON & HTML export
└── tests/
    ├── conftest.py             # Shared fixtures
    ├── test_models.py          # Domain model unit tests
    ├── test_parser.py          # Parser unit tests
    ├── test_analyzers.py       # Scanner & cleanup engine tests
    └── test_cli.py             # CLI integration tests (61 tests total)
```

---

## Testing

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run all 61 tests
python -m pytest tests/ -v

# Lint
ruff check .
```

---

## Docker

Run without installing Python:

```bash
# Build
docker build -t container-registry-cli .

# Run (help)
docker run --rm container-registry-cli --help

# Scan with volume mount
docker run --rm -v ${PWD}:/workspace container-registry-cli scan /workspace/manifest.yaml

# Audit with fail-on
docker run --rm -v ${PWD}:/workspace container-registry-cli audit /workspace/manifest.yaml --fail-on critical
```

Or pull from GHCR:

```bash
docker pull ghcr.io/SanjaySundarMurthy/container-registry-cli:latest
docker run --rm ghcr.io/SanjaySundarMurthy/container-registry-cli:latest --help
```

---

## CI/CD Integration

Add a security gate to your pipeline:

```yaml
# GitHub Actions example
- name: Audit container images
  run: |
    pip install container-registry-cli
    container-registry-cli audit registry-manifest.yaml --fail-on critical
```

The `--fail-on` flag maps severity levels inclusively:
- `--fail-on critical` → fail on critical issues only
- `--fail-on high` → fail on critical + high
- `--fail-on medium` → fail on critical + high + medium

---

## Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push: `git push origin feature/amazing-feature`
5. Open a Pull Request

Ensure tests pass and lint is clean before submitting:

```bash
pip install -e ".[dev]"
pytest -v
ruff check .
```

---

## Links

- **PyPI**: [https://pypi.org/project/container-registry-cli/](https://pypi.org/project/container-registry-cli/)
- **GitHub**: [https://github.com/SanjaySundarMurthy/container-registry-cli](https://github.com/SanjaySundarMurthy/container-registry-cli)
- **Issues**: [https://github.com/SanjaySundarMurthy/container-registry-cli/issues](https://github.com/SanjaySundarMurthy/container-registry-cli/issues)

---

## Author

**Sanjay S** — [GitHub](https://github.com/SanjaySundarMurthy)

## License

MIT
