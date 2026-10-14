# Base version

This module does only what the brief asks. It adds nothing for extra security. The version with security additions is in [`../extended`](../extended/README.md), and [`../README.md`](../README.md) compares the two.

![Base version: only what the brief asks](../docs/base.png)

Source of the diagram: `../docs/base.svg`.

## The brief, requirement by requirement

| Requirement | What implements it | File |
| --- | --- | --- |
| A VPC network with a public and a private subnet | `google_compute_network.vpc`, `google_compute_subnetwork.public`, `google_compute_subnetwork.private` | `network.tf` |
| A Compute Engine instance in the private subnet | `google_compute_instance.web`. It uses the private subnet and has no external IP | `compute.tf` |
| A global HTTP load balancer that routes to the instance | Forwarding rule, HTTPS proxy, URL map, backend service, health check, instance group, reserved global address | `loadbalancer.tf`, `compute.tf` |
| Allow only HTTPS (443) from the internet to the load balancer | `google_compute_global_forwarding_rule.https`: one rule, tcp/443, no port-80 listener | `loadbalancer.tf` |
| Allow only SSH (22) from a trusted range, not 0.0.0.0/0, to the instance | `google_compute_firewall.allow_ssh_trusted`, source `trusted_ssh_cidrs` | `firewall.tf`, `variables.tf` |
| Allow only HTTP (80) from the load balancer to the instance | `google_compute_firewall.allow_lb_http`, sources `130.211.0.0/22` and `35.191.0.0/16` | `firewall.tf` |
| Bonus: least-privilege IAM, not `roles/editor` or `roles/owner` | A dedicated service account with `roles/logging.logWriter` and `roles/monitoring.metricWriter` only | `iam.tf` |

### Where the brief and Google Cloud do not line up

- **The load balancer is not in the public subnet.** A global external Application Load Balancer is a Google edge service. It has no subnet. The public subnet exists because the brief asks for it, and it holds no resources. The extended version puts an SSH bastion there.
- **"HTTP" load balancer, HTTPS only.** The brief names an HTTP load balancer but also says to allow only 443 from the internet. I read "HTTP load balancer" as the product type (the Application Load Balancer) and followed the 443 rule. There is one forwarding rule on port 443 and no port-80 listener. Between the load balancer and the instance the hop is plain HTTP on port 80, as the brief says. The certificate is an input: Google-managed for `domains`, or `existing_ssl_certificate_id`. Terraform never creates a private key.
- **There is no firewall rule for 443.** VPC firewall rules apply to instances, and a global load balancer is not in the VPC. The forwarding rule is the control.
- **SSH reachability.** The instance has no external IP because it is in the private subnet. A trusted public address (an office IP, say) cannot open a connection to it, whatever the firewall says. The rule is correct and it is what the brief asks for, but it admits only ranges that reach the VPC over private connectivity (VPN, Interconnect, peering) or from inside the VPC. The extended version adds a bastion so a public trusted range works.

## Inputs

You must set `project_id`, `trusted_ssh_cidrs`, and either `domains` or `existing_ssl_certificate_id`. The other inputs have defaults. See `examples/basic/main.tf`.

`trusted_ssh_cidrs` validation is strict in both versions, because the brief says "not 0.0.0.0/0" and `0.0.0.0/1` plus `128.0.0.0/1` is the same thing. It accepts only canonical IPv4 CIDRs and rejects null, an empty list, IPv6, host bits, whitespace, `0.0.0.0/0`, any prefix shorter than /8, and a list that adds up to more than one /8 (16,777,216 addresses).

## What this version does not have

Each item is added, with its reason, in the extended version.

- No outbound internet for the instance and no Private Google Access. The instance cannot fetch updates or call Google APIs, so the two writer roles are granted but nothing can use them yet.
- No SSH path from a public range, and no bastion.
- No Cloud Armor and no pinned TLS policy. The load balancer uses Google's default TLS policy.
- No Shielded VM setting, OS Login, project SSH key block or customer-managed disk key. The image defaults apply (Debian 13 turned on vTPM and integrity monitoring, and left secure boot off).
- No deny-all rules and no egress rules. Only the implied VPC defaults apply: ingress denied, egress allowed.
- No logging: no flow logs, firewall logs, NAT logs, load balancer logs or health check logs.

## What was verified

| Check | Result |
| --- | --- |
| `terraform fmt -check`, `terraform init -backend=false`, `terraform validate` | clean |
| `tflint` (recommended preset) | no issues |
| `terraform test` (mocked `google` provider) | 34 passed, 0 failed |
| `checkov` with the three shared custom policies | 31 passed, 0 failed, 7 skipped |
| `examples/basic` | validates |

The tests have one run per bullet of the brief, plus the SSH range validation cases. They check the rendered configuration, not real GCP behaviour.

**Live, 2026-10-14.** I applied the module in a throwaway project (20 resources) and destroyed it afterwards. A listing showed nothing left behind. The certificate was a self-signed one passed in as `existing_ssl_certificate_id`.

- The backend became `HEALTHY` and `https://<lb ip>/` returned 200 with the instance's page.
- TLS 1.2 and TLS 1.3 negotiated. Port 80 on the load balancer address got no answer.
- The instance has no external IP and sits in the private subnet. Its service account holds only the two writer roles.
- The VPC has exactly two allow rules: tcp/80 from the Google ranges and tcp/22 from the trusted `/32`. There is no router, no NAT and no logging.
- A SQL injection string returned 200 (there is no WAF in this version).
- An SSH attempt from my machine to the instance's internal address timed out, as expected without a private route.

Not verified live: SSH to the instance (no route exists in this version), the Google-managed certificate, TLS 1.1 refusal.

### Checkov skips

Seven checks fail on purpose. Each is an inline `checkov:skip` with the reason "not in the brief, added by the extended module".

| Check | Where | What it asks for |
| --- | --- | --- |
| `CKV_GCP_32` | `compute.tf` | Block project-wide SSH keys |
| `CKV_GCP_38` | `compute.tf` | Customer-supplied disk encryption key |
| `CKV_GCP_39` | `compute.tf` | Shielded VM |
| `CKV_GCP_26` | `network.tf`, both subnets | VPC flow logs |
| `CKV_GCP_74` | `network.tf`, both subnets | Private Google Access |

## Roles the deployer needs

Chosen from role descriptions. The account that applied it live was a project owner, so this table is not proven.

| Role | Why |
| --- | --- |
| `roles/compute.networkAdmin` | VPC, subnets, global address |
| `roles/compute.securityAdmin` | Firewall rules |
| `roles/compute.loadBalancerAdmin` | Backend service, URL map, proxy, forwarding rule, certificate |
| `roles/compute.instanceAdmin.v1` | Instance and instance group |
| `roles/iam.serviceAccountAdmin` | Create the instance service account |
| `roles/iam.serviceAccountUser` | Attach it to the instance |
| `roles/resourcemanager.projectIamAdmin` | Grant the two writer roles on the project |

The APIs `compute.googleapis.com`, `iam.googleapis.com`, `logging.googleapis.com` and `monitoring.googleapis.com` must be enabled. The module does not enable them.

## Limits

- One instance in one zone. No autoscaling or high availability.
- Port 80 between the load balancer and the instance is unencrypted.
- After a real instance replacement (a new image or disk), the instance group is empty until you run `terraform apply` a second time. Editing the startup script does not replace the instance. It runs at boot, so reset the instance to run an edited script.
- This is a take-home exercise, not a production design.
