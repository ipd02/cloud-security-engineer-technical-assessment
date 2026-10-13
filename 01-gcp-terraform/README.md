# Part 1: Secure GCP infrastructure with Terraform

## What it does

A Terraform module that builds a small web stack in one GCP project:

- A custom-mode VPC with a public and a private subnet, both with flow logs.
- One Compute Engine instance in the private subnet. It has no external IP.
- A global external Application Load Balancer that accepts HTTPS (443) only and sends traffic to the instance on port 80.
- Firewall rules for 443 from the internet (at the load balancer), 22 from trusted ranges, and 80 from the load balancer, plus explicit deny-all rules.
- Cloud Router and Cloud NAT so the private instance can fetch updates.
- Least-privilege IAM: a dedicated service account with log and metric writer roles only.
- Cloud Armor in front of the backend. This is an addition beyond the brief.

## How to run

Checks need no GCP credentials. From the repo root:

```sh
make lint test scan
```

That runs `terraform fmt -check`, `terraform validate`, `tflint`, `terraform test` (mocked `google` provider) and `checkov`. Individual targets are `tf-lint`, `tf-test` and `tf-scan`.

To use the module, see `examples/basic/main.tf`. The inputs you must set are `project_id`, `trusted_ssh_cidrs`, and either `domains` or `existing_ssl_certificate_id`. Then run `terraform init`, `terraform plan` and `terraform apply` with credentials of your own.

## Files

| File | Concern |
| --- | --- |
| `versions.tf` | Terraform and provider constraints (`~> 7.0`, lock file committed) |
| `variables.tf` | Inputs with validation |
| `validations.tf` | Cross-variable checks (precondition and a `check` block) |
| `network.tf` | VPC, subnets, Cloud Router, Cloud NAT |
| `firewall.tf` | Allow rules, deny-all rules, egress posture |
| `iam.tf` | Instance service account and role bindings |
| `compute.tf` | Instance and unmanaged instance group |
| `loadbalancer.tf` | Address, certificate, TLS policy, health check, backend, URL map, proxy, forwarding rule |
| `armor.tf` | Cloud Armor policy |
| `scripts/startup.sh` | Serves a test page on port 80 |
| `tests/*.tftest.hcl` | Offline tests |
| `examples/basic/` | Example consumer |

## What was verified

All of these ran on my machine with Terraform 1.16.5 and provider `hashicorp/google` 7.46.1 (the version in the lock file). No credentials were used.

| Check | Result |
| --- | --- |
| `terraform fmt -check -recursive` | clean |
| `terraform init -backend=false` | ok |
| `terraform validate` | valid |
| `tflint` (recommended preset, recursive) | no issues |
| `terraform test` | 17 passed, 0 failed |
| `checkov -d 01-gcp-terraform` | 61 passed, 0 failed, 0 skipped |
| `make lint test scan` | green |

The tests use `mock_provider "google"` and `command = plan`. They check the rendered configuration, not real GCP behaviour. They cover: forwarding rule on 443 only, TLS policy MODERN with minimum TLS 1.2, backend and health check logging, firewall ranges and ports, no external IP, Shielded VM, OS Login metadata, exactly two IAM roles with no `roles/editor` or `roles/owner`, the opt-in IAP rule, existing-certificate mode, CMEK pass-through, and rejection of bad input (`0.0.0.0/0`, `::/0`, empty list, prefix too short, malformed CIDR, missing or doubled certificate input, overlapping subnets, zone outside region).

Not verified:

- I did not run `terraform plan` or `terraform apply` against real GCP. No resource exists because of this work.
- Whether the load balancer serves traffic, whether the managed certificate provisions, whether the startup script works on the image, and whether the deployer roles below are enough have not been tested.
- Cloud Armor rule behaviour (false positives on the OWASP rules, the rate limit threshold) has not been observed.

**Live verification: pending.** The author will run a live apply in a throwaway project and update this line with the date and result.

## Checkov skips

None. Checkov reports 61 passed, 0 failed, 0 skipped, so there are no `checkov:skip` comments in the code. If a later change adds one, list it here with the reason.

## Design decisions

### The load balancer is not in a subnet

A global external Application Load Balancer is a Google edge service. Its proxies run in Google's network, not in your VPC subnets, so no subnet can contain it. The task text says "in the public subnet". The module cannot do that literally, and I did not fake it.

The public subnet is still created, as the brief asks. In this design it holds nothing. It exists as the place for resources that need their own internet-reachable addresses later, such as a bastion host, or for a proxy-only subnet if you switch to a regional load balancer. It has flow logs on, so any future use is observable. Do not read it as part of the request path.

The request path is: internet, forwarding rule on the global address (443), HTTPS proxy, URL map, backend service (with Cloud Armor), then the instance in the private subnet on port 80.

### HTTPS only, not "HTTP"

The task says "Global HTTP Load Balancer" but also says to allow only HTTPS (443) from the internet to it. These conflict if "HTTP" means plain port 80. I read "HTTP load balancer" as the product type (the Application Load Balancer, which handles HTTP and HTTPS traffic) and followed the explicit firewall requirement. The module has one forwarding rule on port 443 and no port-80 frontend, not even a redirect. Clients that try plain HTTP get no listener.

The TLS policy sets minimum TLS 1.2 and profile MODERN. The certificate is an input: Google-managed for `domains`, or an existing certificate id. Terraform never generates a private key, so none lands in state. A Google-managed certificate only becomes active after DNS for the domains points at `load_balancer_ip`.

Between the load balancer and the instance the hop is plain HTTP on port 80, as the brief requires. It stays inside Google's network and the firewall allows only the Google ranges. End-to-end TLS would need a certificate on the instance and is not built.

### Firewall rules

VPC firewall rules apply to instances, not to the load balancer, so "443 from the internet to the load balancer" is enforced by the forwarding rule listening on 443 only. The VPC rules are:

| Rule | Direction | Source or destination | Port | Target |
| --- | --- | --- | --- | --- |
| allow-lb-http | ingress | `130.211.0.0/22`, `35.191.0.0/16` | tcp/80 | instance service account |
| allow-ssh-trusted | ingress | `var.trusted_ssh_cidrs` | tcp/22 | instance service account |
| allow-ssh-iap (opt-in) | ingress | `35.235.240.0/20` | tcp/22 | instance service account |
| deny-all-ingress, deny-all-ingress-v6 | ingress | `0.0.0.0/0`, `::/0` | all | all |
| allow-egress-web | egress | `0.0.0.0/0` | tcp/80, tcp/443 | instance service account |
| deny-all-egress | egress | `0.0.0.0/0` | all | all |

Allow rules use priority 1000 and deny rules 65000. Every rule has logging on. Rules target the instance service account instead of a network tag, because anyone who can edit an instance can add a tag, while a service account needs `iam.serviceAccounts.actAs`.

The two Google ranges were checked against https://docs.cloud.google.com/load-balancing/docs/firewall-rules during this build. The page lists `35.191.0.0/16` for health checks and `35.191.0.0/16` plus `130.211.0.0/22` for Google Front End proxies when backends are instance groups. The IAP range `35.235.240.0/20` was checked against https://docs.cloud.google.com/iap/docs/using-tcp-forwarding. The URLs are also in the comments in `firewall.tf`. Google can change these ranges, so recheck before relying on them.

The egress posture allows only tcp/80 and tcp/443, for package repositories through Cloud NAT and Google APIs through Private Google Access. DNS to the metadata server is always allowed by GCP.

### SSH

SSH is allowed only from `trusted_ssh_cidrs`. It is a required input with no default. Validation rejects an empty list, malformed CIDRs, `0.0.0.0/0`, `::/0`, IPv4 prefixes shorter than /8 and IPv6 prefixes shorter than /32. A /8 is 16 million addresses. A looser floor would let someone paste a "mostly the internet" range, and a tighter one would block legitimate large corporate ranges. A `check` block warns on anything wider than /16.

IAP TCP forwarding is the better option because it needs no public SSH exposure and ties access to IAM. It is available with `enable_iap_ssh = true` and is off by default, so the default meets the task's literal requirement. Users of IAP need `roles/iap.tunnelResourceAccessor`. With OS Login on, SSH users also need `roles/compute.osLogin` (or `roles/compute.osAdminLogin`) on the instance or project.

### Instance hardening

Private subnet only, no external IP. Dedicated service account, never the default compute account. Shielded VM with secure boot, vTPM and integrity monitoring. OS Login on, project SSH keys blocked, serial port off, IP forwarding off. Boot disk uses Google-managed encryption, or your key if you set `kms_key_self_link` (CMEK). The image is the Debian 12 family. The startup script runs a Python static file server as `nobody` under a hardened systemd unit.

### IAM

The instance service account has `roles/logging.logWriter` and `roles/monitoring.metricWriter`, nothing else. Bindings use `google_project_iam_member`, which is non-authoritative and leaves other bindings alone. A test fails if `roles/editor` or `roles/owner` appears.

Roles the deployer identity needs (chosen from role descriptions, not proven by a live apply, so expect to adjust after the first real run):

| Role | Why |
| --- | --- |
| `roles/compute.networkAdmin` | VPC, subnets, router, NAT, global address |
| `roles/compute.securityAdmin` | Firewall rules, SSL policy, Cloud Armor policy |
| `roles/compute.loadBalancerAdmin` | Backend service, URL map, proxy, forwarding rule, certificate |
| `roles/compute.instanceAdmin.v1` | Instance and instance group |
| `roles/iam.serviceAccountAdmin` | Create the instance service account |
| `roles/iam.serviceAccountUser` | Attach that service account to the instance |
| `roles/resourcemanager.projectIamAdmin` | Grant the two writer roles on the project |

`projectIamAdmin` is powerful. If that is too broad for your pipeline, replace it with a custom role holding only `resourcemanager.projects.getIamPolicy` and `setIamPolicy`, or bind the writer roles outside this module. The APIs `compute.googleapis.com`, `iam.googleapis.com`, `logging.googleapis.com` and `monitoring.googleapis.com` must be enabled. The module does not enable them.

### Logging and detection

Implemented: subnet flow logs on both subnets, firewall rule logs on every rule, Cloud NAT logs, backend service logs (sample rate 1.0), health check logs, and Cloud Armor request logging through the backend service logs.

Not implemented, as a short extension: Cloud Audit Logs are on by default for admin activity. Data access logs and a log sink to a locked-down bucket or a SIEM would be the next step.

### Cloud Armor (addition)

The policy denies SQL injection, cross-site scripting, local file inclusion and remote code execution with the preconfigured `*-v33-stable` rule sets, adds the `cve-canary` signature rule, throttles each client IP (default 300 requests per 60 seconds, then HTTP 429), and turns on Layer 7 adaptive protection. The default rule allows. The OWASP rules can block legitimate traffic, so run them in preview mode on a real application first. This module does not do that.

### Environment separation

The module takes `project_id` and `name`. To separate environments, call it once per environment with a different project, as `examples/basic` shows for dev. A second environment is not built.

## Honest limitations

- Single instance, single zone, unmanaged instance group. No autoscaling or high availability.
- Port 80 between load balancer and instance is unencrypted.
- No organisation policy constraints, no VPC Service Controls, no log sink.
- The mock-provider tests cannot detect an argument that the real API rejects. A live apply is the only check for that, and it is pending.
- The load balancer needs DNS and certificate provisioning (often tens of minutes) before HTTPS works.
