# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-03-24

### Added
- CHANGELOG following Keep a Changelog format
- CONTRIBUTING guide with development workflow
- CODE_OF_CONDUCT (Contributor Covenant v2.1)
- SECURITY.md with vulnerability reporting policy
- GitHub issue templates (bug report, feature request)
- Pull request template
- Dependabot configuration for automated dependency updates
- CodeQL security scanning in CI pipeline
- Test coverage reporting with Codecov upload
- Docker image build and publish in CI pipeline
- `py.typed` marker for PEP 561 compliance
- Makefile with common development commands
- Pre-commit configuration with ruff and mypy hooks
- Example configurations (`examples/` directory)
- Architecture documentation in README
- Comprehensive test suite for reporters and demo modules
- Mypy strict type-checking configuration
- pip dependency caching in CI for faster builds

### Changed
- Enhanced CI/CD pipeline with multi-version matrix, coverage, Docker, and security jobs
- Updated `pyproject.toml` with full classifiers, keywords, URLs, and author metadata
- Bumped version to 1.1.0
- Improved README with architecture section, contributing guide link, and full badge set

## [1.0.0] - 2025-06-01

### Added
- Initial release
- Registry manifest parsing from YAML files
- Cleanup policy engine with age-based retention and pattern matching
- Security auditing with 10 rules (REG-001 to REG-010)
- Multi-registry detection (ACR, ECR, GCR, Docker Hub, GHCR)
- Rich terminal output with color-coded tables
- JSON and HTML export reporters
- `--fail-on` flag for CI/CD pipeline gates
- Demo project generator
- CLI commands: `scan`, `cleanup`, `audit`, `demo`, `rules`
- Docker support with multi-stage build
- Blog post for Dev.to

[1.1.0]: https://github.com/SanjaySundarMurthy/container-registry-cli/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/SanjaySundarMurthy/container-registry-cli/releases/tag/v1.0.0
