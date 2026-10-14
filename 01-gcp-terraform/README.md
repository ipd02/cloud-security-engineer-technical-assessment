# Part 1: Secure GCP infrastructure with Terraform

A Terraform module for Google Cloud that deploys a VPC with a public and a private subnet, a Compute Engine instance in the private subnet, a global HTTP load balancer, and firewall rules for 443, 22 and 80. The bonus is least-privilege IAM.

I built two versions. Each is a standalone module with its own tests, example and README.

| | [Base](base/README.md) | [Extended](extended/README.md) |
| --- | --- | --- |
| What it is | The complete solution to the brief | The base plus optional security additions |
| Requirements met | All, including the bonus | The same, unchanged |
| Additions | None | Improve the security posture. The brief does not ask for them |
| Live apply and destroy | 23 resources, 2026-10-14 | 37 resources, 2026-10-14 |
| `terraform test` | 34 passed | 48 passed |
| Checkov | 43 passed, 11 documented skips | 98 passed, 1 documented skip |

Read the base to check the brief is met. Read the extended to see what I would add and why. `diff -ru base extended` shows the difference.

## Base

![Base version diagram](docs/base.png)

## Extended

![Extended version diagram](docs/extended.png)

## How the brief is met

| Requirement | Solution |
| --- | --- |
| VPC with a public and a private subnet | Custom-mode VPC and two subnets |
| Instance in the private subnet | One Compute Engine instance, no external IP |
| Global HTTP load balancer | Global external Application Load Balancer, HTTPS on 443, backend on port 80 |
| Allow only 443 from the internet to the load balancer | One forwarding rule on tcp/443, no port-80 listener |
| Allow only SSH from a trusted range (not 0.0.0.0/0) to the instance | Trusted range to a bastion, then bastion to the instance. Strict range validation |
| Allow only 80 from the load balancer to the instance | Firewall rule for Google's load balancer ranges, tcp/80 |
| Bonus: least-privilege IAM | Dedicated service accounts, two writer roles on the instance, none on the bastion |

File-by-file detail is in the [base README](base/README.md).

## Three points that need an explanation

1. **The load balancer is not in the public subnet.** A Google Cloud global external Application Load Balancer is a Google-managed service, not a virtual machine deployed inside your VPC. It has no subnet. The public subnet exists because the brief asks for it, and it holds the SSH bastion.
2. **An "HTTP" load balancer with only 443 open.** I read "HTTP load balancer" as the product type and followed the 443 rule. No firewall rule can express it, because the load balancer is not in the VPC. The forwarding rule is the control.
3. **SSH to a private instance.** It has no external IP, so a public address cannot reach it. SSH goes through a bastion in the public subnet.

## What the extended version adds

| Addition | Why |
| --- | --- |
| Hardened instances: Shielded VM, OS Login, project SSH keys blocked, optional CMEK | A compromised or mis-keyed instance is harder to abuse |
| Per-instance logins and an optional IAP rule | Least privilege at resource level |
| Deny-all ingress and egress, narrow egress allow | Explicit, auditable default deny |
| Cloud Router, Cloud NAT, Private Google Access | Updates without a public address |
| TLS policy, minimum TLS 1.2 | Old TLS versions are refused |
| Cloud Armor: OWASP rules, rate limit | Common web attacks filtered at the edge |
| Flow, firewall, NAT, load balancer and health check logs | Detection and investigation |
| Custom Checkov policies, more tests | Guard rails a unit test cannot give |

## Environments and audit logs

The module takes `project_id` and `name`. A team would call it once per environment, each call pointed at its own project, as `extended/examples/basic/main.tf` shows. No extra environments are built here.

Cloud Audit Logs and a log sink are not part of this module. A real deployment would route Admin Activity logs to a locked log bucket in a separate project. The flow, firewall, NAT and load balancer logs in the extended version cover network detection only.

## Run the checks

No GCP credentials are needed. From the repo root:

```sh
make lint test scan
```

It runs `terraform fmt -check`, `validate`, `tflint`, `terraform test` (mocked provider) and `checkov` on both modules. To deploy, copy a module's `examples/basic/main.tf`, set `project_id`, `trusted_ssh_cidrs` and either `domains` or `existing_ssl_certificate_id`, and run `terraform init`, `plan`, `apply` with your own credentials.

## Layout

```text
01-gcp-terraform/
├── README.md           this overview
├── docs/               diagrams (PNG and SVG source)
├── base/
│   ├── README.md
│   ├── examples/basic/
│   └── module/         the Terraform module, with tests/ and scripts/
├── extended/           same shape as base
├── policy/checkov/     three custom Checkov policies for both versions
└── part.mk             make targets for both versions
```

## Notes

- The live runs used a self-signed certificate passed in as `existing_ssl_certificate_id`, and an account holding only the deployer roles listed in each README.
- A take-home exercise, not a production design.
