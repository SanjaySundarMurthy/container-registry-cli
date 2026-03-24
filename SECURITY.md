# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **sanjaysundarmurthy@users.noreply.github.com**

Please include the following information in your report:

- Type of vulnerability (e.g., code injection, path traversal, denial of service)
- Full path to the source file(s) related to the vulnerability
- Location of the affected code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment of the vulnerability

### What to Expect

1. **Acknowledgment**: You will receive an acknowledgment within 48 hours.
2. **Assessment**: We will investigate and validate the reported vulnerability within 7 days.
3. **Resolution Timeline**: We aim to release a patch within 30 days for critical vulnerabilities.
4. **Disclosure**: We practice coordinated disclosure and will credit reporters in the release notes (unless you prefer to remain anonymous).

## Security Best Practices for Users

When using container-registry-cli:

1. **Input Validation**: Only use manifests from trusted sources. The tool parses YAML files which could potentially contain malicious content if sourced from untrusted origins.

2. **Network Security**: When scanning remote registries, ensure you're using secure connections (HTTPS).

3. **Credential Handling**: This tool does not handle registry credentials directly. If you extend the tool to connect to registries, ensure credentials are managed securely (e.g., using environment variables, secret managers).

4. **CI/CD Integration**: When using `--fail-on` in CI pipelines, ensure the manifest files are from trusted sources to prevent pipeline manipulation.

## Dependency Security

This project uses automated security scanning:

- **Dependabot**: Automated dependency updates for known vulnerabilities
- **CodeQL**: Static analysis for security issues in the codebase

## Known Security Considerations

- YAML parsing uses `yaml.safe_load()` to prevent arbitrary code execution
- File operations are limited to reading from user-specified paths
- No network operations are performed (manifest files are local)
