<!-- ================================================================
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  Open Source V:1.0
  File   : CONTRIBUTING.md
  Purpose: Guidelines for contributing to the project.
================================================================= -->

# 🤝 Contributing to Unified Open-Source SOC Platform

Thank you for your interest in contributing! This project is built by and for the cybersecurity community, and every contribution matters — whether it's fixing a typo, reporting a bug, or building a new feature.

---

## 📋 Table of Contents

- [Code of Conduct](#-code-of-conduct)
- [How Can I Contribute?](#-how-can-i-contribute)
- [Getting Started](#-getting-started)
- [Development Setup](#-development-setup)
- [Branch Naming Convention](#-branch-naming-convention)
- [Commit Message Format](#-commit-message-format)
- [Pull Request Process](#-pull-request-process)
- [Coding Standards](#-coding-standards)
- [Security Vulnerabilities](#-security-vulnerabilities)
- [Community](#-community)

---

## 📜 Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/) code of conduct. By participating, you agree to uphold a respectful, inclusive, and harassment-free environment for everyone.

**In short:**
- Be respectful and constructive
- Welcome newcomers
- Focus on what is best for the community
- Show empathy towards other community members

---

## 💡 How Can I Contribute?

### 🐛 Report Bugs

Found a bug? Please [open an issue](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform/issues/new) with:

1. **Title**: Clear, descriptive summary
2. **Environment**: OS, Docker version, RAM, disk space
3. **Steps to Reproduce**: Numbered steps to trigger the bug
4. **Expected Behavior**: What you expected to happen
5. **Actual Behavior**: What actually happened
6. **Logs**: Output from `docker compose logs <service>`
7. **Screenshots**: If applicable

### 💡 Suggest Features

Have an idea? [Open a feature request](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform/issues/new) with:

1. **Problem**: What problem does this solve?
2. **Solution**: Your proposed solution
3. **Alternatives**: Other approaches you considered
4. **Impact**: Who benefits and how?

### 📝 Improve Documentation

Documentation improvements are always welcome:
- Fix typos and grammar
- Add missing information
- Improve code examples
- Write tutorials or guides
- Translate to other languages

### 🔧 Submit Code

- Bug fixes
- New features
- Security hardening
- Performance improvements
- Integration tests

### 🌟 Other Ways to Help

- ⭐ Star the repository
- 📢 Share the project
- 💬 Answer questions in Issues
- 📖 Write blog posts about the project

---

## 🚀 Getting Started

### 1. Fork the Repository

Click the **Fork** button at the top right of the [repository page](https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform).

### 2. Clone Your Fork

```bash
git clone https://github.com/<YOUR_USERNAME>/Unified-Open-Source-SOC-Platform.git
cd Unified-Open-Source-SOC-Platform
```

### 3. Add Upstream Remote

```bash
git remote add upstream https://github.com/boniyeamincse/Unified-Open-Source-SOC-Platform.git
```

### 4. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

### 5. Make Your Changes

Edit files, test locally, and commit.

### 6. Push and Open a PR

```bash
git push origin feature/your-feature-name
```

Then open a Pull Request on GitHub.

---

## 🛠 Development Setup

### Prerequisites

| Tool | Version |
|---|---|
| Docker | 24.0+ |
| Docker Compose | v2.20+ |
| Git | 2.30+ |
| Python | 3.9+ (for scripts) |
| RAM | 16 GB minimum |

### Local Setup

```bash
# 1. Clone and enter the directory
git clone https://github.com/<YOUR_USERNAME>/Unified-Open-Source-SOC-Platform.git
cd Unified-Open-Source-SOC-Platform

# 2. Copy environment template
cp .env.example .env

# 3. Edit configuration
nano .env

# 4. Start the stack
docker compose up -d

# 5. Check service health
docker compose ps
```

### Testing Your Changes

```bash
# Check all services are running
docker compose ps

# View logs for a specific service
docker compose logs -f wazuh.manager

# Run the deployment health check
sudo bash docs/deploy.sh health
```

---

## 🌿 Branch Naming Convention

| Type | Format | Example |
|---|---|---|
| Feature | `feature/description` | `feature/add-mfa-support` |
| Bug Fix | `fix/description` | `fix/nginx-tls-config` |
| Documentation | `docs/description` | `docs/update-install-guide` |
| Security | `security/description` | `security/harden-api-auth` |
| Refactor | `refactor/description` | `refactor/split-compose` |

---

## 📝 Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[body]

[footer]
```

### Types

| Type | Description |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `security` | Security improvement |
| `refactor` | Code restructuring |
| `test` | Adding tests |
| `chore` | Maintenance tasks |

### Examples

```bash
feat(wazuh): add custom decoder for AWS CloudTrail logs
fix(nginx): correct TLS cipher suite ordering
docs(readme): update quick start instructions
security(thehive): restrict header-based authentication
```

---

## 🔀 Pull Request Process

### Before Submitting

- [ ] Your code follows the project's coding standards
- [ ] You've tested your changes locally
- [ ] All services start successfully with `docker compose up -d`
- [ ] You've updated relevant documentation
- [ ] Your commits follow the commit message format
- [ ] You've added your author header to new files

### PR Template

When opening a PR, please include:

```markdown
## Summary
Brief description of what this PR does.

## Changes
- List of specific changes made

## Testing
- How you tested these changes

## Related Issues
Closes #<issue-number>

## Checklist
- [ ] Code follows project standards
- [ ] Documentation updated
- [ ] Tested locally
- [ ] All services healthy
```

### Review Process

1. **Automated checks** — Docker build validation
2. **Maintainer review** — Code review and feedback
3. **Testing** — Verify on staging environment
4. **Merge** — Squash and merge to `main`

---

## 📏 Coding Standards

### File Headers

All files **must** include the standardized header block:

**For shell/YAML/conf files:**
```bash
####################################################################
#  Unified Open-Source SOC Platform
#  Author : Boni Yeamin
#  Open Source V:1.0
#  File   : <path/to/file>
#  Purpose: <one-line description>
####################################################################
```

**For Python files:**
```python
#!/usr/bin/env python3
"""
####################################################################
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  Open Source V:1.0
  File   : <path/to/file>
  Purpose: <one-line description>
####################################################################
"""
```

**For Markdown files:**
```html
<!-- ================================================================
  Unified Open-Source SOC Platform
  Author : Boni Yeamin
  Open Source V:1.0
  File   : <path/to/file>
  Purpose: <one-line description>
================================================================= -->
```

### General Guidelines

- **No hardcoded secrets** — Use environment variables via `.env`
- **Pin Docker image versions** — Never use `:latest`
- **Include comments** — Explain *why*, not just *what*
- **Keep it modular** — One config file per component
- **Test locally** — Verify `docker compose up -d` works before submitting

---

## 🔒 Security Vulnerabilities

> **⚠️ Do NOT open a public issue for security vulnerabilities.**

If you discover a security vulnerability, please report it responsibly:

1. **Email**: Contact the maintainer directly
2. **Include**: Description, reproduction steps, potential impact
3. **Wait**: Allow reasonable time for a fix before public disclosure

We take security seriously and will respond promptly.

---

## 🌍 Community

- **GitHub Issues** — Bug reports and feature requests
- **Pull Requests** — Code contributions
- **Discussions** — Questions and ideas

---

## 🙏 Thank You

Every contribution, no matter how small, makes this project better for the cybersecurity community. Whether you're fixing a typo or building a new integration — **thank you!**

---

<div align="center">

**Happy Contributing! 🛡**

</div>
