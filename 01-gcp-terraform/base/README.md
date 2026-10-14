# Base version

The complete solution to the brief. Every requirement is met, including the IAM bonus. The [extended version](../extended/README.md) adds optional security improvements. The [overview](../README.md) compares the two.

![Base version diagram](../docs/base.png)

## The brief, requirement by requirement

| Requirement | What implements it | File |
| --- | --- | --- |
| VPC with a public and a private subnet | `google_compute_network.vpc`, `google_compute_subnetwork.public`, `google_compute_subnetwork.private` | `network.tf` |
| Instance in the private subnet | `google_compute_instance.web`: private subnet, no external IP | `compute.tf` |
| Global HTTP load balancer to the instance | Forwarding rule, HTTPS proxy, URL map, backend service, health check, instance group, global address | `loadbalancer.tf`, `compute.tf` |
| Only 443 from the internet to the load balancer | `google_compute_global_forwarding_rule.https`: tcp/443, no port-80 listener | `loadbalancer.tf` |
| Only SSH from a trusted range to the instance | `allow_ssh_trusted_bastion`, then `allow_ssh_bastion_to_web` | `firewall.tf`, `bastion.tf` |
| Only 80 from the load balancer to the instance | `allow_lb_http`: `130.211.0.0/22`, `35.191.0.0/16` | `firewall.tf` |
| Bonus: least-privilege IAM | Instance service account with `logging.logWriter` and `monitoring.metricWriter`. Bastion account with no roles | `iam.tf`, `bastion.tf` |

## Design notes

**Why the load balancer is not in the public subnet.** A Google Cloud global external Application Load Balancer is a Google-managed service, not a virtual machine deployed inside your VPC. It has no subnet, so it cannot be placed in one. The public subnet exists because the brief asks for it, and it holds the SSH bastion.

**HTTPS only on an "HTTP" load balancer.** The brief names an HTTP load balancer and allows only 443 from the internet. I read "HTTP load balancer" as the product type and followed the 443 rule. The hop to the instance is plain HTTP on port 80, as the brief says. The certificate is an input (Google-managed for `domains`, or `existing_ssl_certificate_id`), and Terraform never creates a private key.

**No firewall rule for 443.** VPC firewall rules apply to instances, and the load balancer is not in the VPC. The forwarding rule is the control. A custom Checkov policy guards it.

**How SSH reaches the instance.** The instance has no external IP, so a public address cannot reach it. The path has two rules:

1. Trusted range to the **bastion** on tcp/22. The bastion is in the public subnet and has the only external IP.
2. Bastion to the **instance** on tcp/22. The source is the bastion's service account, so no other host can use the rule.

**Strict range validation.** `trusted_ssh_cidrs` must hold "not 0.0.0.0/0" in effect, because `0.0.0.0/1` plus `128.0.0.0/1` is the same thing. It accepts only canonical IPv4 CIDRs. It rejects null, an empty list, IPv6, host bits, whitespace, `0.0.0.0/0`, prefixes shorter than /8, and lists that add up to more than one /8.

## Inputs

Set `project_id`, `trusted_ssh_cidrs`, and either `domains` or `existing_ssl_certificate_id`. See `examples/basic/main.tf`.

## Verification

| Check | Result |
| --- | --- |
| `terraform fmt -check`, `init -backend=false`, `validate` | clean |
| `tflint` (recommended preset) | no issues |
| `terraform test` (mocked provider) | 34 passed, 0 failed |
| `checkov` with the three shared custom policies | 43 passed, 0 failed, 11 documented skips |
| `examples/basic` | validates |

### Live run, 2026-10-14

Applied in a throwaway project (23 resources) with a self-signed certificate, then destroyed. A listing showed nothing left behind.

| Check | Result |
| --- | --- |
| Backend service | `HEALTHY` |
| `https://<lb ip>/` | 200 |
| TLS | 1.2 and 1.3 negotiate |
| Port 80 on the load balancer address | no answer |
| Instance | private subnet, no external IP |
| SSH: trusted range, bastion, instance | works |
| SSH straight to the instance | times out |
| Bastion to instance | tcp/22 open, tcp/80 closed |
| Bastion with another range in `trusted_ssh_cidrs` | times out |
| Project roles of the module's accounts | only the two writer roles, on the instance account |

Not verified: the Google-managed certificate and TLS 1.1 refusal.

### Checkov skips

Each is an inline `checkov:skip` with its reason.

| Check | Resource | Meaning | Reason |
| --- | --- | --- | --- |
| `CKV_GCP_40` | bastion | No public IP on an instance | The bastion is the SSH entry point. SSH reaches it only from the trusted range and it holds no roles |
| `CKV_GCP_32`, `38`, `39` | instance, bastion | Block project SSH keys, customer disk key, Shielded VM | Extended version |
| `CKV_GCP_26`, `74` | both subnets | Flow logs, Private Google Access | Extended version |

## Deployer roles

Chosen from role descriptions. The account that applied it live was a project owner, so the table is unproven.

| Role | Why |
| --- | --- |
| `roles/compute.networkAdmin` | VPC, subnets, global address |
| `roles/compute.securityAdmin` | Firewall rules |
| `roles/compute.loadBalancerAdmin` | Backend service, URL map, proxy, forwarding rule, certificate |
| `roles/compute.instanceAdmin.v1` | Instances and instance group |
| `roles/iam.serviceAccountAdmin`, `roles/iam.serviceAccountUser` | Create and attach the service accounts |
| `roles/resourcemanager.projectIamAdmin` | Grant the two writer roles |

The APIs `compute`, `iam`, `logging` and `monitoring` must be enabled. The module does not enable them.

## Scope notes

- One instance in one zone, no autoscaling.
- Port 80 from the load balancer to the instance is plain HTTP.
- The instance has no route to the internet. The extended version adds Cloud NAT.
- SSH keys use Google's default handling. The extended version switches to OS Login.
- After a real instance replacement (new image or disk), the instance group stays empty until a second `terraform apply`. Editing the startup script does not replace the instance. It runs at boot, so reset the instance to rerun it.
