---
title: "🐳 container-registry-cli: Image Registry Analyzer with Cleanup & Security Scanning"
published: true
description: "A Python CLI tool for analyzing container registries, enforcing tag cleanup policies, and auditing image security with 10 built-in rules."
tags: docker, containers, devops, security
---

## What I Built

**container-registry-cli** — analyzes container image registries from YAML manifests:

- **Image Inventory** — Tags, sizes, layers, vulnerability data
- **Cleanup Policy Engine** — Age-based retention, pattern matching, protected tags
- **Security Auditing** — 10 rules (REG-001 to REG-010) covering CVEs, stale tags, oversized images
- **Multi-Registry Detection** — ACR, ECR, GCR, Docker Hub, GHCR

## Test Results

```
54 passed in 0.82s
├── test_models.py     — 18 tests
├── test_parser.py     — 13 tests
├── test_analyzers.py  — 12 tests
└── test_cli.py        — 11 tests
```

## Links

- **GitHub**: [container-registry-cli](https://github.com/sanjaysundarmurthy/container-registry-cli)
- **Part of**: DevOps CLI Tools Suite (Tool 8 of 14)
