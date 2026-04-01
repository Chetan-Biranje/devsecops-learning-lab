# 🛡️ DevSecOps Learning Lab

> **A complete, production-grade DevSecOps pipeline with CI/CD, SAST, DAST, Container Security, IaC scanning, and Kubernetes hardening.**

[![CI/CD Pipeline](https://github.com/Chetan-Biranje/devsecops-learning-lab/actions/workflows/devsecops-pipeline.yml/badge.svg)](https://github.com/Chetan-Biranje/devsecops-learning-lab/actions)
[![CodeQL](https://github.com/Chetan-Biranje/devsecops-learning-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/Chetan-Biranje/devsecops-learning-lab/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)](https://python.org)

---

## 🗺️ What's Inside

```
devsecops-learning-lab/
├── .github/
│   └── workflows/
│       ├── devsecops-pipeline.yml   # 8-stage security pipeline
│       ├── codeql.yml               # GitHub CodeQL analysis
│       └── dependency-review.yml    # PR dependency review
├── app/
│   ├── src/app.py                   # Hardened Flask application
│   ├── tests/test_app.py            # Pytest test suite (80%+ coverage)
│   └── requirements.txt
├── docker/
│   ├── Dockerfile                   # Multi-stage, non-root, read-only FS
│   └── docker-compose.yml           # App + ZAP + Prometheus + Grafana
├── k8s/
│   └── base/
│       ├── deployment.yaml          # Pod security context, resource limits
│       └── service.yaml             # NetworkPolicy, HPA, PDB
├── terraform/
│   ├── main.tf                      # AWS EKS + VPC (flow logs, encryption)
│   └── variables.tf
├── ansible/
│   └── playbooks/
│       └── harden-server.yml        # CIS Benchmark L1 hardening
├── security/
│   ├── sast/                        # Bandit + Semgrep configs
│   ├── sca/                         # pip-audit + Safety outputs
│   ├── dast/zap-rules.conf          # OWASP ZAP rule set
│   ├── secrets/.gitleaks.toml       # Gitleaks secret scanning config
│   └── iac/                         # Checkov + tfsec outputs
└── monitoring/
    └── prometheus/prometheus.yml
```

---

## 🔄 CI/CD Security Pipeline

The pipeline runs **8 security stages** on every push/PR:

| # | Stage | Tools | Gate |
|---|-------|-------|------|
| 1 | 🔍 **SAST** | Bandit, Semgrep, CodeQL | MEDIUM+ severity fails |
| 2 | 📦 **SCA** | Safety, pip-audit | Known CVEs fail |
| 3 | 🔑 **Secrets Scan** | Gitleaks, TruffleHog | Any secret fails |
| 4 | 🧪 **Unit Tests** | Pytest + Coverage | < 80% coverage fails |
| 5 | 🐳 **Container Scan** | Trivy | CRITICAL/HIGH CVEs fail |
| 6 | 🏗️ **IaC Scan** | Checkov, tfsec | Misconfigs reported |
| 7 | 🕷️ **DAST** | OWASP ZAP | Critical findings fail |
| 8 | 📊 **Summary** | GitHub Step Summary | Full report in Actions |

---

## 🚀 Quick Start

### Local Development

```bash
git clone https://github.com/Chetan-Biranje/devsecops-learning-lab.git
cd devsecops-learning-lab

# Run the application
docker compose -f docker/docker-compose.yml up app

# Run with DAST (ZAP)
docker compose -f docker/docker-compose.yml --profile dast up

# Run with monitoring (Prometheus + Grafana)
docker compose -f docker/docker-compose.yml --profile monitoring up
```

### Run Tests

```bash
pip install -r app/requirements.txt pytest pytest-cov
cd app && pytest tests/ -v --cov=src --cov-fail-under=80
```

### Run SAST Locally

```bash
pip install bandit semgrep

# Bandit
bandit -r app/src/ -ll -ii

# Semgrep
semgrep --config=auto app/src/
```

### Run Secrets Scan Locally

```bash
# Install gitleaks
brew install gitleaks   # macOS
# or download from: https://github.com/gitleaks/gitleaks/releases

gitleaks detect --config security/secrets/.gitleaks.toml --source .
```

### Container Scan Locally

```bash
# Install trivy
brew install trivy   # macOS

# Scan image
docker build -f docker/Dockerfile -t devsecops-lab:local .
trivy image devsecops-lab:local --severity CRITICAL,HIGH

# Scan filesystem
trivy fs . --severity CRITICAL,HIGH
```

---

## 🔒 Security Features

### Application (`app/src/app.py`)
- ✅ Parameterised SQL queries (no injection risk)
- ✅ PBKDF2-HMAC-SHA256 password hashing with salt
- ✅ Rate limiting via Flask-Limiter
- ✅ All security response headers (HSTS, CSP, X-Frame-Options…)
- ✅ Server fingerprint removed
- ✅ Gunicorn (production WSGI) – not Flask dev server

### Docker (`docker/Dockerfile`)
- ✅ Multi-stage build (minimal attack surface)
- ✅ Non-root user (`appuser`)
- ✅ Read-only root filesystem
- ✅ No unnecessary packages
- ✅ Health check configured
- ✅ `PYTHONDONTWRITEBYTECODE=1`

### Kubernetes (`k8s/`)
- ✅ `runAsNonRoot: true`
- ✅ `readOnlyRootFilesystem: true`
- ✅ `allowPrivilegeEscalation: false`
- ✅ `capabilities: drop: [ALL]`
- ✅ Default-deny NetworkPolicy
- ✅ Resource requests & limits
- ✅ HorizontalPodAutoscaler + PodDisruptionBudget
- ✅ Pod Security Standards: `restricted`

### Terraform (`terraform/`)
- ✅ Remote state with S3 encryption + DynamoDB locking
- ✅ EKS secrets envelope encryption
- ✅ VPC Flow Logs enabled
- ✅ EBS volumes encrypted
- ✅ Private subnets for nodes
- ✅ EKS audit logging enabled

### Server Hardening (`ansible/`)
- ✅ CIS Benchmark Level 1 (Ubuntu 22.04)
- ✅ SSH hardened (key-auth only, no root, port changed)
- ✅ UFW firewall (deny-all default)
- ✅ Fail2Ban brute-force protection
- ✅ Kernel hardening via sysctl
- ✅ auditd enabled
- ✅ Automatic security updates

---

## 📚 Learning Resources

| Topic | What to explore |
|-------|-----------------|
| SAST | `security/sast/.semgrep.yml` – write custom rules |
| DAST | `security/dast/zap-rules.conf` – tune ZAP findings |
| IaC | `terraform/main.tf` – find & fix Checkov warnings |
| K8s  | `k8s/base/deployment.yaml` – understand security contexts |
| Hardening | `ansible/playbooks/harden-server.yml` – CIS controls |

---

## ⚠️ Disclaimer

This lab is for **educational and authorized testing purposes only**.  
Do not deploy to production without a full security review.

---

## 👤 Author

**Chetan Biranje** – [@Chetan-Biranje](https://github.com/Chetan-Biranje)
