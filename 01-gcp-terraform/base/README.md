# Base version

The complete solution to the brief. Every requirement is met, including the IAM bonus. The [extended version](../extended/README.md) adds optional security improvements on top. The [overview](../README.md) compares the two.

![Base version diagram](../docs/base.png)

Diagram source: `../docs/base.svg`.

## The brief, requirement by requirement

| Requirement | What implements it | File |
| --- | --- | --- |
| A VPC network with a public and a private subnet | `google_compute_network.vpc`, `google_compute_subnetwork.public`, `google_compute_subnetwork.private` | `network.tf` |
| A Compute Engine instance in the private subnet | `google_compute_instance.web`. It uses the private subnet and has no external IP | `compute.tf` |
| A global HTTP load balancer that routes to the instance | Forwarding rule, HTTPS proxy, URL map, backend service, health check, instance group, reserved global address | `loadbalancer.tf`, `compute.tf` |
| Allow only HTTPS (443) from the internet to the load balancer | `google_compute_global_forwarding_rule.https`: one rule on tcp/443, no port-80 listener | `loadbalancer.tf` |
| Allow only SSH (22) from a trusted range, not 0.0.0.0/0, to the instance | `allow_ssh_trusted_bastion` (trusted range to the bastion) and `allow_ssh_bastion_to_web` (bastion to the instance) | `firewall.tf`, `bastion.tf` |
| Allow only HTTP (80) from the load balancer to the instance | `allow_lb_http`, sources `130.211.0.0/22` and `35.191.0.0/16` | `firewall.tf` |
| Bonus: least-privilege IAM, not `roles/editor` or `roles/owner` | A dedicated service account with `roles/logging.logWriter` and `roles/monitoring.metricWriter`. The bastion has its own account with no roles | `iam.tf`, `bastion.tf` |

## Design notes

### Why the load balancer is not in the public subnet

The brief says the load balancer is "in the public subnet". A Google Cloud global external Application Load Balancer is a Google-managed service, not a virtual machine deployed inside your VPC. It has no subnet, so it cannot be placed in one. The public subnet exists because the brief asks for it, and it holds the SSH bastion.

### HTTPS only on an "HTTP" load balancer

The brief names an HTTP load balancer and also allows only 443 from the internet. I read "HTTP load balancer" as the product type (the Application Load Balancer) and followed the 443 rule. There is one forwarding rule on tcp/443 and no port-80 listener. The hop from the load balancer to the instance is plain HTTP on port 80, as the brief says.

The certificate is an input: Google-managed for `domains`, or `existing_ssl_certificate_id`. Terraform never creates a private key, so none lands in state.

### No firewall rule for 443

VPC firewall rules apply to instances. The load balancer is not in the VPC, so a rule cannot see it. The forwarding rule listening on 443 only is the control, and a custom Checkov policy guards it.

### How SSH reaches the instance

The instance is in the private subnet, so it has no external IP and a public trusted address cannot reach it. The path is:

1. The trusted range connects to the **bastion** on tcp/22. The bastion is in the public subnet and is the only host with an external IP.
2. The bastion connects to the **instance** on tcp/22. The rule's source is the bastion's service account, so no other host can use it.

Neither rule takes `0.0.0.0/0`. The bastion has its own service account with no roles.

### Strict SSH range validation

`trusted_ssh_cidrs` validation is strict because "not 0.0.0.0/0" must hold in effect: `0.0.0.0/1` plus `128.0.0.0/1` is the same thing. It accepts only canonical IPv4 CIDRs and rejects null, an empty list, IPv6, host bits, whitespace, `0.0.0.0/0`, any prefix shorter than /8, and a list that adds up to more than one /8 (16,777,216 addresses).

## Inputs

Set `project_id`, `trusted_ssh_cidrs`, and either `domains` or `existing_ssl_certificate_id`. The rest have defaults. See `examples/basic/main.tf`.

## Verification

| Check | Result |
| --- | --- |
| `terraform fmt -check`, `terraform init -backend=false`, `terraform validate` | clean |
| `tflint` (recommended preset) | no issues |
| `terraform test` (mocked `google` provider) | 34 passed, 0 failed |
| `checkov` with the three shared custom policies | 43 passed, 0 failed, 11 documented skips |
| `examples/basic` | validates |

The tests have one run per bullet of the brief, plus the SSH range validation cases. They check the rendered configuration, not real GCP behaviour.

### Live run, 2026-10-14

I applied the module in a throwaway project (23 resources) and destroyed it afterwards. A listing showed nothing left behind. The certificate was a self-signed one passed in as `existing_ssl_certificate_id`.

| Observed | Result |
| --- | --- |
| Backend service | `HEALTHY` |
| `https://<lb ip>/` | 200, with the instance's page |
| TLS | 1.2 and 1.3 negotiate |
| Port 80 on the load balancer address | no answer |
| Compute Engine instance | in the private subnet, no external IP |
| SSH, trusted range to bastion to instance | works |
| SSH straight to the instance from outside | times out |
| Bastion to instance | tcp/22 open, tcp/80 closed |
| Bastion with `trusted_ssh_cidrs` set to another range | times out |
| Project roles of the module's service accounts | only the two writer roles, on the instance account |

Not verified: the Google-managed certificate and TLS 1.1 refusal.

### Checkov skips

Eleven checks are skipped inline, each with its reason. They belong to the extended version, except the bastion's public IP, which is its purpose.

| Check | Resource | Meaning | Reason |
| --- | --- | --- | --- |
| `CKV_GCP_40` | bastion | No public IP on an instance | The bastion is the SSH entry point. SSH reaches it only from `trusted_ssh_cidrs` and it holds no roles |
| `CKV_GCP_32` | instance, bastion | Block project-wide SSH keys | Extended version |
| `CKV_GCP_38` | instance, bastion | Customer-supplied disk key | Extended version |
| `CKV_GCP_39` | instance, bastion | Shielded VM | Extended version |
| `CKV_GCP_26` | both subnets | VPC flow logs | Extended version |
| `CKV_GCP_74` | both subnets | Private Google Access | Extended version |

## Roles the deployer needs

Chosen from role descriptions. The account that applied it live was a project owner, so the table is not proven.

| Role | Why |
| --- | --- |
| `roles/compute.networkAdmin` | VPC, subnets, global address |
| `roles/compute.securityAdmin` | Firewall rules |
| `roles/compute.loadBalancerAdmin` | Backend service, URL map, proxy, forwarding rule, certificate |
| `roles/compute.instanceAdmin.v1` | Instances and instance group |
| `roles/iam.serviceAccountAdmin` | Create the two service accounts |
| `roles/iam.serviceAccountUser` | Attach them to the instances |
| `roles/resourcemanager.projectIamAdmin` | Grant the two writer roles on the project |

The APIs `compute.googleapis.com`, `iam.googleapis.com`, `logging.googleapis.com` and `monitoring.googleapis.com` must be enabled. The module does not enable them.

## Scope notes

- One instance in one zone, with no autoscaling.
- Port 80 between the load balancer and the instance is plain HTTP.
- The instance has no route to the internet, so it cannot fetch updates. The extended version adds Cloud NAT for that.
- SSH keys are managed the Google default way (project or instance metadata). The extended version switches to OS Login.
- After a real instance replacement (a new image or disk), the instance group stays empty until you run `terraform apply` a second time. Editing the startup script does not replace the instance. It runs at boot, so reset the instance to run an edited script.
- A take-home exercise, not a production design.
