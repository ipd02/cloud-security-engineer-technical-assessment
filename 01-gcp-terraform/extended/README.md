# Extended version

The [base version](../base/README.md) already meets the whole brief. This version is the base plus optional additions that improve the security posture. The brief does not ask for any of them. Each one is tagged `+ added` in the diagram and listed below with its reason and its file. The [overview](../README.md) compares the two.

![Extended version diagram](../docs/extended.png)

Diagram source: `../docs/extended.svg`. Compare the code with `diff -ru base extended`.

## What it adds to the base

| Addition | Why | Where |
| --- | --- | --- |
| Hardening of the instance and the bastion: Shielded VM, OS Login, project SSH keys blocked, serial port off, no IP forwarding, optional CMEK disk key | A compromised or mis-keyed instance is harder to abuse | `compute.tf`, `bastion.tf` |
| Per-instance SSH logins (`ssh_login_members`, `roles/compute.osLogin`, no sudo) and an optional IAP rule | Least privilege at resource level, not project-wide | `iam.tf`, `firewall.tf` |
| Deny-all ingress (IPv4 and IPv6) and deny-all egress, with a narrow egress allow | The default deny becomes explicit and auditable, and a compromised instance can reach less | `firewall.tf` |
| Cloud Router, Cloud NAT, Private Google Access | The private instance can fetch updates without a public address | `network.tf` |
| TLS policy: MODERN profile, minimum TLS 1.2 | Old TLS versions are refused | `loadbalancer.tf` |
| Cloud Armor: OWASP rules, a CVE rule, a rate limit | Common web attacks are filtered at the edge | `armor.tf` |
| Logging: VPC flow logs, firewall logs, NAT logs, load balancer and health check logs | Detection and investigation | `network.tf`, `firewall.tf`, `loadbalancer.tf` |
| `enable_bastion` switch and a direct trusted-range rule to the instance | For ranges that reach the VPC over VPN, Interconnect or peering | `bastion.tf`, `firewall.tf` |
| Custom Checkov policies and more tests | Guard rails for what a unit test cannot see | `policy/`, `tests/` |

Identical in both versions: the SSH bastion path, strict `trusted_ssh_cidrs` validation, the dedicated service accounts with the two writer roles and none, rules that target service accounts, narrow instance scopes, the startup script in metadata, and the Debian 13 image.

## How to run

The checks need no GCP credentials. From the repo root run `make lint test scan`. It runs `terraform fmt -check`, `terraform validate`, `tflint`, `terraform test` (mocked `google` provider) and `checkov` on both modules. To use the module, see `examples/basic/main.tf`. Set `project_id`, `trusted_ssh_cidrs`, and either `domains` or `existing_ssl_certificate_id`.

## Files

| File | Concern |
| --- | --- |
| `versions.tf` | Terraform and provider constraints (`~> 7.0`, lock file committed) |
| `variables.tf` | Inputs with validation |
| `validations.tf` | Cross-variable checks (preconditions and a `check` block) |
| `network.tf` | VPC, subnets, Cloud Router, Cloud NAT |
| `firewall.tf` | Allow rules, deny-all rules, egress posture |
| `iam.tf` | Service account, project roles, per-instance login bindings |
| `compute.tf` | Compute Engine instance and unmanaged instance group |
| `bastion.tf` | SSH bastion in the public subnet and its service account |
| `loadbalancer.tf` | Address, certificate, TLS policy, health check, backend, URL map, proxy, forwarding rule |
| `armor.tf` | Cloud Armor policy |
| `scripts/startup.sh` | Serves a test page on port 80 |
| `tests/*.tftest.hcl` | Offline tests |
| `examples/basic/` | Example consumer |

## Verification

All of these ran with Terraform 1.16.5 and provider `hashicorp/google` 7.46.1 (the lock file version). No credentials were used.

| Check | Result |
| --- | --- |
| `terraform fmt -check -recursive`, `terraform init -backend=false`, `terraform validate` | clean |
| `tflint` (recommended preset, recursive) | no issues |
| `terraform test` | 48 passed, 0 failed |
| `checkov` (built-in plus three custom policies) | 98 passed, 0 failed, 1 documented skip |
| `make lint test scan` | green |

`tests/requirements.tftest.hcl` has one run per bullet of the brief (subnets, private instance, global load balancer chain, 443-only forwarding rule, SSH through the bastion, HTTP from the load balancer, allow rules ranked above the deny rules, IAM). The tests use `mock_provider "google"`, with `command = plan` or `apply` against the mock. They check the rendered configuration, not real GCP behaviour. They cover: forwarding rule on 443 only, TLS policy MODERN with minimum TLS 1.2, backend and health check logging, firewall ranges and ports, no external IP, Shielded VM, OS Login metadata, exactly two IAM roles on the dedicated service account, the opt-in IAP rule, existing-certificate mode, CMEK pass-through, and rejection of bad SSH input (`0.0.0.0/0`, IPv6 and IPv4-mapped IPv6, mixed lists, empty list, prefixes shorter than /8, 256 /8s that add up to the internet, host bits, whitespace, malformed CIDRs) and of a missing or doubled certificate input, overlapping subnets and a zone outside the region.

`terraform test` can only look at resources the module declares, so it cannot notice a new, unrelated resource. Three custom Checkov policies in `policy/checkov/` cover that gap across the whole directory: no `roles/editor` or `roles/owner` bindings, every global forwarding rule on port 443 only, and no ingress allow rule from `0.0.0.0/0` or `::/0`. Checkov's built-in `CKV_GCP_2` and `CKV_GCP_117` overlap with the first and third.

### Live verification

On 2026-10-13 I applied the module in a throwaway project (35 resources, Terraform 1.16.5, provider 7.46.1), tested it, and destroyed it. A final listing showed only the project's own default network and firewall rules left. The certificate was a self-signed one passed in as `existing_ssl_certificate_id`.

Observed:

- Backend service `HEALTHY`. `https://<lb ip>/` returned 200 with the instance's page. It took a few minutes after apply, with 502 or 503 until the backend registered.
- TLS 1.2 and TLS 1.3 negotiate. Port 80 on the load balancer address gets no answer (connection error).
- Cloud Armor returned 403 for a SQL injection string, an XSS string, a path traversal string, a shell command string and a `${jndi:...}` header.
- Boot image `debian-13-trixie`. The Compute Engine instance has no external IP, Shielded VM on, OS Login on, scopes limited to `logging.write` and `monitoring.write`. The bastion is the only instance with an external IP.
- SSH: from the trusted `/32` to the bastion works, and from there to the Compute Engine instance works (tested with `ssh -J`-style proxying through the bastion). A direct connection to the Compute Engine instance's internal address from outside times out. After changing `trusted_ssh_cidrs` to a different range, the bastion no longer answers.
- Bastion to Compute Engine instance on 22 is open, on 80 is closed. Compute Engine instance egress: 443 and 80 reach the internet through Cloud NAT (the source address was the NAT address), 8080 is refused. The bastion's egress on 8080 is refused too.
- OS Login bindings exist on the two instances only. The only project-level roles held by the module's service accounts are the two writer roles on the Compute Engine instance's account. The bastion account has none.
- Logs appeared in Cloud Logging for VPC flow, firewall (allow and deny rules), Cloud NAT, load balancer requests and health checks.
- Cloud Armor rate limit (300 requests per 60 seconds): in one run, 637 requests were allowed and 1,613 got HTTP 429 over about 70 seconds. In an earlier run on a freshly created policy, more than 8,000 requests over roughly half an hour got no 429 at all. After I changed the rule once with `gcloud`, it enforced. I do not know why the first policy did not. Google documents the enforcement as approximate. Treat the rate limit as configured and observed once, not as a guarantee.

Defects found only by the live runs, and fixed:

- Editing the startup script replaced the instance (the `metadata_startup_script` argument forces a new instance), and GCP then dropped the replacement from the unmanaged instance group, so the load balancer had no backend. The script now lives in `metadata["startup-script"]`, so edits update in place. A real replacement (new image, disk or network) still leaves the group empty until a second `terraform apply`, which adds the instance back. I confirmed that second apply works. The per-instance login bindings are replaced together with the instance.
- The group needs the instance's full URL (`self_link`), not its short id, or the second apply fails.
- On Debian 13, systemd warned that `User=nobody` is "not safe". The unit now uses `DynamicUser=yes`.

Not verified live: TLS 1.1 refusal (my client cannot speak it), the IAP option, CMEK, the Google-managed certificate, the `python3-minimal` fallback in the startup script (Debian 13 already has Python 3.13, so it never ran), and the no-sudo behaviour of `roles/compute.osLogin` (the account I tested with is a project owner and had sudo). The deployer role table below comes from role descriptions. The account that applied was a project owner, so the table is not proven.

Not verified at all: whether the OWASP rules give false positives on a real application.

## Checkov skips

One. `CKV_GCP_40` (no public IP on an instance) is skipped inline on `google_compute_instance.bastion` in `bastion.tf`. The bastion is the SSH entry point, SSH reaches it only from `trusted_ssh_cidrs`, and its service account has no roles. The Compute Engine instance passes the check.

## Design notes

### Why the load balancer is not in the public subnet

A Google Cloud global external Application Load Balancer is a Google-managed service, not a virtual machine deployed inside your VPC. It has no subnet, so it cannot be placed in the public subnet. The public subnet exists because the brief asks for it, and it holds the SSH bastion. The request path is: internet, forwarding rule on the global address (443), HTTPS proxy, URL map, backend service (with Cloud Armor), then the instance on port 80.

### HTTPS only on an "HTTP" load balancer

The brief names an HTTP load balancer and also allows only 443 from the internet. I read "HTTP load balancer" as the product type and followed the 443 rule: one forwarding rule on tcp/443 and no port-80 listener, not even a redirect. The TLS policy sets minimum TLS 1.2 and the MODERN profile. The certificate is an input (Google-managed for `domains`, or an existing one) and Terraform never creates a private key. A Google-managed certificate becomes active only after DNS for the domains points at `load_balancer_ip`. The hop from the load balancer to the instance is plain HTTP on port 80, as the brief says.

### Firewall rules

VPC firewall rules apply to instances, so "443 from the internet to the load balancer" is the forwarding rule, not a rule. The VPC rules:

| Rule | Direction | Source or destination | Port | Target | In base |
| --- | --- | --- | --- | --- | --- |
| allow-lb-http | ingress | `130.211.0.0/22`, `35.191.0.0/16` | tcp/80 | instance service account | yes |
| allow-ssh-bastion-in | ingress | `trusted_ssh_cidrs` | tcp/22 | bastion service account | yes |
| allow-ssh-bastion-to-web | ingress | bastion service account | tcp/22 | instance service account | yes |
| allow-ssh-trusted | ingress | `trusted_ssh_cidrs` | tcp/22 | instance service account | added |
| allow-ssh-iap (opt-in) | ingress | `35.235.240.0/20` | tcp/22 | instance service account | added |
| deny-all-ingress, deny-all-ingress-v6 | ingress | `0.0.0.0/0`, `::/0` | all | all | added |
| allow-egress-web | egress | `0.0.0.0/0` | tcp/80, tcp/443 | instance and bastion service accounts | added |
| allow-egress-bastion-ssh | egress | private subnet range | tcp/22 | bastion service account | added |
| deny-all-egress | egress | `0.0.0.0/0` | all | all | added |

Allow rules use priority 1000 and deny rules 65000. Every rule logs. Rules target service accounts, because anyone who can edit an instance can add a network tag, while using a service account needs `iam.serviceAccounts.actAs`.

The two Google ranges were checked against https://docs.cloud.google.com/load-balancing/docs/firewall-rules. The page lists `35.191.0.0/16` for health checks and `35.191.0.0/16` plus `130.211.0.0/22` for Google Front End proxies when backends are instance groups. The IAP range was checked against https://docs.cloud.google.com/iap/docs/using-tcp-forwarding. Google can change these ranges, so recheck them.

### SSH

The SSH path is the same as in the base: trusted range to bastion, then bastion to instance. This version adds:

- **A hardened bastion:** Shielded VM, OS Login, project SSH keys blocked, serial port off, and egress limited to tcp/22 into the private subnet plus tcp/80 and tcp/443.
- **A direct rule** from the trusted range to the instance, and the `enable_bastion` switch. Together they serve ranges that reach the VPC over VPN, Interconnect or peering.
- **Per-instance logins:** `ssh_login_members` gets `roles/compute.osLogin` (no sudo) on the two instances. A connection looks like `ssh -J <os-login-user>@<bastion_external_ip> <os-login-user>@<instance_internal_ip>`, with both addresses from the module outputs.
- **An IAP rule** (`enable_iap_ssh`, off by default). IAP TCP forwarding needs no public SSH exposure and ties access to IAM. Users need `roles/iap.tunnelResourceAccessor`.

The range validation, which is the same in both versions, accepts only canonical IPv4 CIDRs and caps the total at one /8. A `check` block here warns on anything wider than /16.

### Instance hardening

Shielded VM with secure boot, vTPM and integrity monitoring. OS Login on, project SSH keys blocked, serial port off, IP forwarding off. The boot disk uses Google-managed encryption, or your key if you set `kms_key_self_link` (CMEK). The image is the Debian 13 family. Debian 12 left regular security support in July 2026, so set `boot_image` to pin another family.

### IAM extras

The service accounts and the two writer roles are the same as in the base. This version adds per-instance `roles/compute.osLogin` bindings and, with `enable_iap_ssh`, `roles/iap.tunnelResourceAccessor` on the instance. Nobody is granted login by default. Bindings use `google_project_iam_member`, which is non-authoritative. A test and a custom Checkov policy fail if `roles/editor` or `roles/owner` appears.

Roles the deployer needs (chosen from role descriptions, not proven by a live apply):

| Role | Why |
| --- | --- |
| `roles/compute.networkAdmin` | VPC, subnets, router, NAT, global address |
| `roles/compute.securityAdmin` | Firewall rules, SSL policy, Cloud Armor policy |
| `roles/compute.loadBalancerAdmin` | Backend service, URL map, proxy, forwarding rule, certificate |
| `roles/compute.instanceAdmin.v1` | Instances, instance group, per-instance login bindings |
| `roles/iap.admin` (only with `enable_iap_ssh` and `ssh_login_members`) | IAP tunnel bindings on the instance |
| `roles/iam.serviceAccountAdmin` | Create the service accounts |
| `roles/iam.serviceAccountUser` | Attach them to the instances |
| `roles/resourcemanager.projectIamAdmin` | Grant the writer roles on the project |

`projectIamAdmin` is powerful. Replace it with a custom role holding `resourcemanager.projects.getIamPolicy` and `setIamPolicy` if that is too broad. The APIs `compute`, `iam`, `logging` and `monitoring` must be enabled. The module does not enable them.

### Logging and detection

Subnet flow logs on both subnets, firewall rule logs on every rule, Cloud NAT logs, backend service logs (sample rate 1.0), health check logs, and Cloud Armor decisions through the backend service logs. Not built: data access audit logs and a log sink to a locked-down bucket or a SIEM.

### Cloud Armor

The policy denies SQL injection, cross-site scripting, local file inclusion and remote code execution with the preconfigured `*-v33-stable` rule sets, adds the `cve-canary` rule, throttles each client IP (default 300 requests per 60 seconds, then HTTP 429), and turns on Layer 7 adaptive protection. The OWASP rules can block legitimate traffic, so run them in preview mode on a real application first. This module does not do that.

### Environment separation

The module takes `project_id` and `name`. Call it once per environment with a different project, as `examples/basic` shows. A second environment is not built.

## Limits

- One instance in one zone, with no autoscaling.
- Port 80 between the load balancer and the instance is plain HTTP.
- The writer roles are granted but nothing on the instance uses them yet, because no Ops Agent is installed.
- The bastion is one host with an external IP and an SSH daemon. The firewall and OS Login limit it, but it is more attack surface than IAP alone.
- No organisation policy constraints, no VPC Service Controls, no log sink.
- The mock tests cannot detect an argument the real API rejects or a lifecycle problem. Both defects above were found only by applying.
- After a real instance replacement the instance group stays empty until a second `terraform apply`. The startup script runs at boot only, so reset the instance after editing it.
- The load balancer needs DNS and certificate provisioning (often tens of minutes) before HTTPS works.
