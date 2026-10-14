# Part 1: Secure GCP infrastructure with Terraform

The task asks for a Terraform module that deploys, on Google Cloud, a VPC with a public and a private subnet, a Compute Engine instance in the private subnet, a global HTTP load balancer, and firewall rules for 443 from the internet, 22 from a trusted range and 80 from the load balancer. The bonus is least-privilege IAM.

There are two versions. Each one is a standalone module with its own tests, example and README.

| | [Base version](base/README.md) | [Extended version](extended/README.md) |
| --- | --- | --- |
| What it is | The complete solution to the brief | The base plus optional security additions |
| Requirements met | All of them, including the bonus | The same, unchanged |
| Additions | None | Improve the security posture. The brief does not ask for them |
| Resources (live apply) | 23 | 35 |
| `terraform test` | 34 passed | 48 passed |
| Checkov | 43 passed, 11 documented skips | 98 passed, 1 documented skip |
| Verified live | 2026-10-14 | 2026-10-13 |

Start with the base version to check the brief is met. Read the extended version to see what I would add on top and why. `diff -ru base extended` shows exactly the difference.

## Base version

![Base version diagram](docs/base.png)

## Extended version

![Extended version diagram](docs/extended.png)

## What the extended version adds

| Addition | Why |
| --- | --- |
| Hardening of both instances: Shielded VM, OS Login, project SSH keys blocked, serial port off, optional CMEK disk key | A compromised or mis-keyed instance is harder to abuse |
| Per-instance SSH logins (`roles/compute.osLogin`, no sudo) and an optional IAP rule | Least privilege at resource level, not project-wide |
| Deny-all ingress and egress rules, narrow egress allow | The default deny becomes explicit and auditable, and a compromised instance can reach less |
| Cloud Router, Cloud NAT, Private Google Access | The private instance can fetch updates without a public address |
| TLS policy, minimum TLS 1.2 | Old TLS versions are refused |
| Cloud Armor: OWASP rules, rate limit | Common web attacks are filtered at the edge |
| Flow, firewall, NAT, load balancer and health check logs | Detection and investigation |
| Custom Checkov policies and more tests | Guard rails for what a unit test cannot see |

## Three points where the brief and Google Cloud need an explanation

1. **The load balancer is not in the public subnet.** A Google Cloud global external Application Load Balancer is a Google-managed service, not a virtual machine deployed inside your VPC. It has no subnet, so it cannot be placed in the public subnet. The public subnet exists because the brief asks for it, and it holds the SSH bastion.
2. **"HTTP" load balancer, but only 443 from the internet.** I read "HTTP load balancer" as the product type and followed the 443 rule: one forwarding rule on tcp/443 and no port-80 listener. No VPC firewall rule can express "443 from the internet to the load balancer", because the load balancer is not in the VPC. The forwarding rule is the control.
3. **SSH from a trusted range to a private instance.** The instance is in the private subnet, so it has no external IP and a public address cannot reach it. SSH goes through a bastion in the public subnet: trusted range to bastion, then bastion to instance. Both versions include it.

## How to run

The checks need no GCP credentials. From the repo root:

```sh
make lint test scan
```

That runs `terraform fmt -check`, `terraform validate`, `tflint`, `terraform test` (mocked `google` provider) and `checkov` on both modules. To deploy, copy a module's `examples/basic/main.tf`, set `project_id`, `trusted_ssh_cidrs` and either `domains` or `existing_ssl_certificate_id`, then run `terraform init`, `plan` and `apply` with your own credentials.

## Layout

| Path | Content |
| --- | --- |
| `base/` | Module, tests, example and README |
| `extended/` | Module, tests, example and README |
| `policy/checkov/` | Three custom Checkov policies used on both: no `roles/editor` or `roles/owner`, forwarding rule on tcp/443 only, no ingress allow from the whole internet |
| `docs/` | The two diagrams, PNG and SVG source |
| `part.mk` | Make targets for both modules |

## Limits

- Verified live with a self-signed certificate. The Google-managed certificate, TLS 1.1 refusal, IAP and CMEK were not exercised.
- The live runs used a project owner account, so the deployer role tables are not proven.
- The mock-provider tests cannot catch what a real API rejects or how resources behave when replaced. Two defects in the extended version were found only by applying it. Both are documented in its README.
- This is a take-home exercise, not a production design.
