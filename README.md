# Cloud security engineering assessment

[![ci](https://github.com/ipd02/cloud-security-engineer-technical-assessment/actions/workflows/ci.yml/badge.svg)](https://github.com/ipd02/cloud-security-engineer-technical-assessment/actions/workflows/ci.yml)

This repository is my answer to a cloud security engineer take-home assessment. The task has four parts: secure infrastructure as code on GCP, a security review of a CloudFormation template and a Dockerfile, a Go tool that finds firewall rules open to the internet, and an audit of vulnerable Node.js dependencies. Each part has its own folder and README with the answers, the limits and how it was checked.

## Parts

| Part | What | Where | Run (from the repository root) |
| --- | --- | --- | --- |
| 1 | Secure GCP infrastructure with Terraform | [`01-gcp-terraform/`](01-gcp-terraform/README.md) | `make tf-lint tf-test tf-scan` |
| 2 | CloudFormation and Dockerfile security review | [`02-cloud-security-check/`](02-cloud-security-check/README.md) | `make cloud-check-lint cloud-check-test cloud-check-scan` |
| 3 | Go multi-cloud firewall scanner | [`03-firewall-scanner/`](03-firewall-scanner/README.md) | `make fwscan-mock` |
| 4 | Third-party dependency audit | [`04-dependency-audit/`](04-dependency-audit/README.md) | `make dep-audit-test dep-audit-scan` |

`make help` lists every target. `make lint test scan` runs the checks of all four parts. None of them needs cloud credentials.

## Requirements

`make lint test scan` needs Terraform, tflint (with the Google ruleset), checkov, cfn-lint, hadolint, trivy, ruff, Go, golangci-lint and Python 3.12 on your `PATH`. Docker is needed only for `make cloud-check-build`. The exact versions are in `.github/workflows/ci.yml`, `ci/` and `02-cloud-security-check/scripts/ci-install-tools.sh`. The first run needs network access for the Terraform provider, the tflint plugin and the trivy database.

## Coverage matrix

| Control area | Where | How verified |
| --- | --- | --- |
| Infrastructure as code | `01-gcp-terraform/*/module/`, `02-cloud-security-check/cloudformation/hardened.yaml` | `terraform fmt`, `validate`, `tflint`, `cfn-lint` (`make lint`) |
| Network | Firewall rules in `01-gcp-terraform/*/module/firewall.tf`. Firewall scanner in `03-firewall-scanner/` | `terraform test` (34 and 48 tests). Scanner unit tests with fake clients |
| Identity and least privilege | Service accounts and two writer roles in `01-gcp-terraform/*/module/iam.tf`. Role and scoped policy in `hardened.yaml` | Tests and a custom checkov policy that fail on `roles/editor` or `roles/owner`. A check that fails on a wildcard action in the role policy |
| Encryption | KMS key and bucket encryption in `hardened.yaml`. Optional CMEK disk key and TLS policy in `01-gcp-terraform/extended/` | `checkov` and `trivy config` on `hardened.yaml`. `terraform test` |
| Logging and detection | Flow, firewall, NAT and load balancer logs in `01-gcp-terraform/extended/`. S3 access logs in `hardened.yaml`. `02-cloud-security-check/scripts/find_risky_iam_users.py` | `terraform test`, `checkov`, finder unit tests |
| Guardrails and policy as code | Custom checkov policies in `01-gcp-terraform/policy/checkov/`. Example SCP and RCP in `02-cloud-security-check/policies/` | `make tf-scan`. The SCP and RCP are examples only and are checked in a test AWS account, not in CI |
| Secrets | `.gitleaks.toml`, `.gitignore`, `Dockerfile.hardened` takes secrets at run time | gitleaks over the full history in CI |
| Supply chain and dependencies | `04-dependency-audit/`, base image pinned by digest, `.github/dependabot.yml` | `npm audit` and `trivy fs`, `make dep-audit-scan`, `trivy image` in CI |
| CI/CD pipeline permissions | `.github/workflows/ci.yml`: `permissions: {}`, `contents: read` per job, actions pinned to a commit SHA, pinned tool versions | Read the workflow. CI runs on every pull request |
| Container and host hardening | `02-cloud-security-check/docker/Dockerfile.hardened`, OS Login and Shielded VM in `01-gcp-terraform/extended/` | `hadolint`, `trivy config`, `docker build` and run with `--read-only --cap-drop=ALL` in CI |
| API and edge protection | TLS 1.2 policy and Cloud Armor in `01-gcp-terraform/extended/module/` | `terraform test`, `checkov`. Live run, see below |
| Runtime protection (described only) | `02-cloud-security-check/PREVENTION.md`, section 4 | Not implemented here |

## Verified how

- **In CI and with `make lint test scan`, with no credentials:** formatting, validation and linting, `terraform test` with a mocked provider, `checkov`, `cfn-lint`, `hadolint`, `trivy config` and `trivy image`, unit tests for the Go tool and the Python scripts, `gitleaks`, and a script that checks the original task files fail the scanners and the hardened files pass.
- **Live, by hand, on 2026-10-14:** the Terraform modules were applied in a throwaway GCP project and then destroyed. The CloudFormation template, the IAM detection commands and the example policies were tested in a test AWS account. The Go scanner was run against test environments in AWS, GCP and Azure. Everything created for these tests was deleted afterwards. CI does not repeat these runs, and the per-part READMEs list what each run showed.
- **Not run:** runtime protection (Falco, EDR, admission control) is described in `PREVENTION.md` and not built.

GitHub's own dependency alerts on `04-dependency-audit/vulnerable-input/` and `04-dependency-audit/tests/fixtures/custom-app/` are expected. Those folders hold deliberately vulnerable inputs.
