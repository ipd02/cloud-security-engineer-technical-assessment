# Base version

The complete solution to the brief. Every requirement is met, including the IAM bonus. The [extended version](../extended/README.md) adds optional security improvements. The [overview](../README.md) compares the two.

![Base version diagram](../docs/base.png)

## Usage

```hcl
module "web" {
  source = "./module" # path to this folder's module

  project_id        = "my-project"
  trusted_ssh_cidrs = ["203.0.113.0/24"] # your office or VPN egress range
  domains           = ["www.example.com"]
}
```

Then run `terraform init`, `plan` and `apply` with your own credentials. Point DNS for `domains` at the `load_balancer_ip` output. A full caller is in [`examples/basic`](examples/basic/main.tf). The code is in `module/`, and the folder tree is in the [overview](../README.md#layout).

## The brief, requirement by requirement

Files are in `module/`.

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

## Inputs and outputs

| Input | Default | Meaning |
| --- | --- | --- |
| `project_id` | required | Project that receives all resources |
| `trusted_ssh_cidrs` | required | IPv4 ranges allowed to SSH to the bastion. Strictly validated |
| `domains` or `existing_ssl_certificate_id` | `[]` or `null` | Set exactly one: a Google-managed certificate for the domains, or an existing certificate |
| `name` | `secure-web` | Prefix for every resource, 20 characters at most |
| `region`, `zone` | `europe-west1`, `europe-west1-b` | The zone must be inside the region |
| `public_subnet_cidr`, `private_subnet_cidr` | `10.10.0.0/24`, `10.10.1.0/24` | Must not overlap |
| `machine_type`, `bastion_machine_type` | `e2-small`, `e2-micro` | |
| `boot_image` | Debian 13 family | Image family for both instances |

| Output | Use |
| --- | --- |
| `load_balancer_ip` | Point DNS for `domains` here |
| `bastion_external_ip`, `instance_internal_ip` | The two addresses for an SSH hop through the bastion |
| `instance_name`, `instance_service_account`, `bastion_service_account` | Names and accounts |
| `vpc_id`, `public_subnet_id`, `private_subnet_id` | Network ids for other modules |

## Verification

| Check | Result |
| --- | --- |
| `terraform fmt -check`, `init -backend=false -lockfile=readonly`, `validate` | clean, modules and example |
| `tflint` (recommended preset and the Google ruleset) | no issues |
| `terraform test` (mocked provider) | 34 passed, 0 failed |
| `checkov` with the three shared custom policies | 43 passed, 0 failed, 11 documented skips |

The tests have one run per bullet of the brief, plus the SSH range validation cases.

### Live run, 2026-10-14

Applied in a throwaway project (23 resources) by an account that held only the roles in the table below, then destroyed. A listing showed nothing left behind. The certificate was a self-signed one passed in as `existing_ssl_certificate_id`.

| Check | Result |
| --- | --- |
| Backend service | `HEALTHY` |
| `https://<lb ip>/` | 200 |
| TLS | 1.2 and 1.3 negotiate |
| Port 80 on the load balancer address | no answer |
| Instance | private subnet, no external IP |
| `ssh -J <user>@<bastion_external_ip> <user>@<instance_internal_ip>` from the trusted range | works |
| SSH straight to the instance | times out |
| Bastion to instance | tcp/22 open, tcp/80 closed |
| Bastion with another range in `trusted_ssh_cidrs` | times out |
| Firewall rules in the VPC | `allow-lb-http`, `allow-ssh-bastion-in`, `allow-ssh-bastion-to-web` |
| Project roles of the module's accounts | only the two writer roles, on the instance account |

### Checkov skips

Each is an inline `checkov:skip` with its reason.

| Check | Resource | Meaning | Reason |
| --- | --- | --- | --- |
| `CKV_GCP_40` | bastion | No public IP on an instance | The bastion is the SSH entry point. SSH reaches it only from the trusted range and it holds no roles |
| `CKV_GCP_32`, `38`, `39` | instance, bastion | Block project SSH keys, customer disk key, Shielded VM | Extended version |
| `CKV_GCP_26`, `74` | both subnets | Flow logs, Private Google Access | Extended version |

## Deployer roles

The live run above applied and destroyed everything with an account holding exactly these roles.

| Role | Why |
| --- | --- |
| `roles/compute.networkAdmin` | VPC, subnets, global address |
| `roles/compute.securityAdmin` | Firewall rules |
| `roles/compute.loadBalancerAdmin` | Backend service, URL map, proxy, forwarding rule, certificate |
| `roles/compute.instanceAdmin.v1` | Instances and instance group |
| `roles/iam.serviceAccountAdmin`, `roles/iam.serviceAccountUser` | Create and attach the service accounts |
| `roles/resourcemanager.projectIamAdmin` | Grant the two writer roles |

The APIs `compute`, `iam`, `logging` and `monitoring` must be enabled first.

## Scope notes

- One instance in one zone. Port 80 from the load balancer to the instance is plain HTTP.
- The two writer roles let an agent or application on the instance write logs and metrics.
- SSH keys use Google's default handling (project or instance metadata). The extended version switches to OS Login.
- After a real instance replacement (new image or disk), run `terraform apply` a second time to put the instance back in its group. Editing the startup script does not replace the instance. It runs at boot, so reset the instance to rerun it.
