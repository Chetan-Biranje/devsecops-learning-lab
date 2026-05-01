# 🔒 DevSecOps Learning Lab

> Production-grade secure Flask application with a complete 8-stage CI/CD security pipeline on AWS EKS.

![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub_Actions-2088FF?style=flat-square&logo=github-actions)
![AWS](https://img.shields.io/badge/Cloud-AWS_EKS-232F3E?style=flat-square&logo=amazon-aws)
![Terraform](https://img.shields.io/badge/IaC-Terraform-7B42BC?style=flat-square&logo=terraform)
![Ansible](https://img.shields.io/badge/Config-Ansible-EE0000?style=flat-square&logo=ansible)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## Pipeline Overview

```
Code Push
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Stage 1 → SAST          Semgrep + Bandit           │
│  Stage 2 → SCA           pip-audit (dependencies)   │
│  Stage 3 → Secrets       Gitleaks + detect-secrets  │
│  Stage 4 → DAST          OWASP ZAP baseline scan    │
│  Stage 5 → Container     Trivy image scan           │
│  Stage 6 → IaC           tfsec + checkov            │
│  Stage 7 → Build Gate    Block if critical findings │
│  Stage 8 → Deploy        EKS via Terraform          │
└─────────────────────────────────────────────────────┘
```

---

## Stack

| Layer | Technology |
|-------|-----------|
| Application | Flask (Python) |
| CI/CD | GitHub Actions |
| SAST | Semgrep, Bandit |
| SCA | pip-audit |
| Secrets | Gitleaks, detect-secrets |
| DAST | OWASP ZAP |
| Container Scan | Trivy |
| IaC Scan | tfsec, checkov |
| Orchestration | Kubernetes (EKS) |
| Provisioning | Terraform |
| Hardening | Ansible CIS Level 2 |
| Cloud | AWS (EKS, IAM, S3) |

---

## Security Controls

- **Least-privilege IAM** — scoped roles per service
- **CIS Level 2 hardening** — applied via Ansible across all nodes
- **Non-root containers** — enforced in Dockerfile
- **Secrets never in code** — GitHub Secrets + AWS Secrets Manager
- **Build gates** — critical SAST/container findings block merge

---

## Setup

```bash
git clone https://github.com/Chetan-Biranje/devsecops-learning-lab
cd devsecops-learning-lab

# Provision infrastructure
cd terraform/
terraform init && terraform apply

# Run Ansible hardening
ansible-playbook -i inventory playbooks/cis-hardening.yml

# Local dev
pip install -r requirements.txt
python app.py
```

---

## Project Structure

```
devsecops-learning-lab/
├── .github/
│   └── workflows/
│       └── devsecops-pipeline.yml   # 8-stage CI/CD
├── app/
│   └── app.py                       # Flask application
├── terraform/
│   ├── main.tf                      # EKS cluster
│   ├── iam.tf                       # Least-privilege roles
│   └── variables.tf
├── ansible/
│   └── playbooks/
│       └── cis-hardening.yml        # CIS Level 2
├── k8s/
│   ├── deployment.yaml
│   └── network-policy.yaml
├── Dockerfile
└── requirements.txt
```

---

## Author

**Chetan Biranje** — [github.com/Chetan-Biranje](https://github.com/Chetan-Biranje)
