# Part 1: Secure GCP infrastructure with Terraform

## What it does

A Terraform module that builds a small web stack in one GCP project:

- A custom-mode VPC with a public and a private subnet, both with flow logs.
- One Compute Engine instance in the private subnet. It has no external IP.
- A small SSH bastion in the public subnet, the only way in for a trusted public range (on by default, `enable_bastion`).
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
| `iam.tf` | Instance service account, project roles, per-instance login bindings |
| `compute.tf` | Web instance and unmanaged instance group |
| `bastion.tf` | SSH bastion in the public subnet and its service account |
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
| `terraform test` | 48 passed, 0 failed |
| `checkov -d 01-gcp-terraform` (built-in plus three custom policies) | 98 passed, 0 failed, 1 skipped |
| `make lint test scan` | green |

`tests/requirements.tftest.hcl` has one run per bullet of the brief (subnets, private instance, global load balancer chain, 443-only forwarding rule, SSH through the bastion, HTTP from the load balancer, allow rules ranked above the deny rules, IAM). The tests use `mock_provider "google"`, with `command = plan` or `apply` against the mock. They check the rendered configuration, not real GCP behaviour. They cover: forwarding rule on 443 only, TLS policy MODERN with minimum TLS 1.2, backend and health check logging, firewall ranges and ports, no external IP, Shielded VM, OS Login metadata, exactly two IAM roles on the dedicated service account, the opt-in IAP rule, existing-certificate mode, CMEK pass-through, and rejection of bad SSH input (`0.0.0.0/0`, IPv6 and IPv4-mapped IPv6, mixed lists, empty list, prefixes shorter than /8, 256 /8s that add up to the internet, host bits, whitespace, malformed CIDRs) and of a missing or doubled certificate input, overlapping subnets and a zone outside the region.

`terraform test` can only look at resources the module declares, so it cannot notice a new, unrelated resource. Three custom Checkov policies in `policy/checkov/` cover that gap across the whole directory: no `roles/editor` or `roles/owner` bindings, every global forwarding rule on port 443 only, and no ingress allow rule from `0.0.0.0/0` or `::/0`. Checkov's built-in `CKV_GCP_2` and `CKV_GCP_117` overlap with the first and third.

### Live verification

On 2026-10-13 I applied the module in a throwaway project (35 resources, Terraform 1.16.5, provider 7.46.1), tested it, and destroyed it. A final listing showed only the project's own default network and firewall rules left. The certificate was a self-signed one passed in as `existing_ssl_certificate_id`.

Observed:

- Backend service `HEALTHY`. `https://<lb ip>/` returned 200 with the instance's page. It took a few minutes after apply, with 502 or 503 until the backend registered.
- TLS 1.2 and TLS 1.3 negotiate. Port 80 on the load balancer address gets no answer (connection error).
- Cloud Armor returned 403 for a SQL injection string, an XSS string, a path traversal string, a shell command string and a `${jndi:...}` header.
- Boot image `debian-13-trixie`. The web instance has no external IP, Shielded VM on, OS Login on, scopes limited to `logging.write` and `monitoring.write`. The bastion is the only instance with an external IP.
- SSH: from the trusted `/32` to the bastion works, and from there to the web instance works (tested with `ssh -J`-style proxying through the bastion). A direct connection to the web instance's internal address from outside times out. After changing `trusted_ssh_cidrs` to a different range, the bastion no longer answers.
- Bastion to web instance on 22 is open, on 80 is closed. Web instance egress: 443 and 80 reach the internet through Cloud NAT (the source address was the NAT address), 8080 is refused. The bastion's egress on 8080 is refused too.
- OS Login bindings exist on the two instances only. The only project-level roles held by the module's service accounts are the two writer roles on the web account. The bastion account has none.
- Logs appeared in Cloud Logging for VPC flow, firewall (allow and deny rules), Cloud NAT, load balancer requests and health checks.
- Cloud Armor rate limit (300 requests per 60 seconds): in one run, 637 requests were allowed and 1,613 got HTTP 429 over about 70 seconds. In an earlier run on a freshly created policy, more than 8,000 requests over roughly half an hour got no 429 at all. After I changed the rule once with `gcloud`, it enforced. I do not know why the first policy did not. Google documents the enforcement as approximate. Treat the rate limit as configured and observed once, not as a guarantee.

Defects found only by the live runs, and fixed:

- Editing the startup script replaced the instance (the `metadata_startup_script` argument forces a new instance), and GCP then dropped the replacement from the unmanaged instance group, so the load balancer had no backend. The script now lives in `metadata["startup-script"]`, so edits update in place. A real replacement (new image, disk or network) still leaves the group empty until a second `terraform apply`, which adds the instance back. I confirmed that second apply works. The per-instance login bindings are replaced together with the instance.
- The group needs the instance's full URL (`self_link`), not its short id, or the second apply fails.
- On Debian 13, systemd warned that `User=nobody` is "not safe". The unit now uses `DynamicUser=yes`.

Not verified live: TLS 1.1 refusal (my client cannot speak it), the IAP option, CMEK, the Google-managed certificate, the `python3-minimal` fallback in the startup script (Debian 13 already has Python 3.13, so it never ran), and the no-sudo behaviour of `roles/compute.osLogin` (the account I tested with is a project owner and had sudo). The deployer role table below comes from role descriptions. The account that applied was a project owner, so the table is not proven.

Not verified at all: whether the OWASP rules give false positives on a real application.

## Checkov skips

One. `CKV_GCP_40` (no public IP on a Compute instance) is skipped inline on `google_compute_instance.bastion` in `bastion.tf`. The bastion is the one host with an external IP, SSH reaches it only from `trusted_ssh_cidrs`, and its service account has no roles. The web instance passes the check. Checkov reports 98 passed, 0 failed, 1 skipped.

## Design decisions

### The load balancer is not in a subnet

A global external Application Load Balancer is a Google edge service. Its proxies run in Google's network, not in your VPC subnets, so no subnet can contain it. The task text says "in the public subnet". The module cannot do that literally, and I did not fake it.

The public subnet is still created, as the brief asks. In this design it holds the SSH bastion and nothing else. It is not part of the request path for web traffic, and a proxy-only subnet for a regional load balancer would be a separate subnet with its own purpose, so this one cannot be reused for that. Apart from the bastion's external IP, the only difference from the private subnet is that Cloud NAT covers the private one. Flow logs are on.

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
| allow-ssh-trusted | ingress | `var.trusted_ssh_cidrs` | tcp/22 | web instance service account |
| allow-ssh-bastion-in | ingress | `var.trusted_ssh_cidrs` | tcp/22 | bastion service account |
| allow-ssh-bastion-to-web | ingress | source: bastion service account | tcp/22 | web instance service account |
| allow-egress-bastion-ssh | egress | private subnet range | tcp/22 | bastion service account |
| allow-ssh-iap (opt-in) | ingress | `35.235.240.0/20` | tcp/22 | instance service account |
| deny-all-ingress, deny-all-ingress-v6 | ingress | `0.0.0.0/0`, `::/0` | all | all |
| allow-egress-web | egress | `0.0.0.0/0` | tcp/80, tcp/443 | web instance and bastion service accounts |
| deny-all-egress | egress | `0.0.0.0/0` | all | all |

Allow rules use priority 1000 and deny rules 65000. Every rule has logging on. Rules target the instance service account instead of a network tag, because anyone who can edit an instance can add a tag, while a service account needs `iam.serviceAccounts.actAs`.

The two Google ranges were checked against https://docs.cloud.google.com/load-balancing/docs/firewall-rules during this build. The page lists `35.191.0.0/16` for health checks and `35.191.0.0/16` plus `130.211.0.0/22` for Google Front End proxies when backends are instance groups. The IAP range `35.235.240.0/20` was checked against https://docs.cloud.google.com/iap/docs/using-tcp-forwarding. The URLs are also in the comments in `firewall.tf`. Google can change these ranges, so recheck before relying on them.

The egress posture allows only tcp/80 and tcp/443, for package repositories through Cloud NAT and Google APIs through Private Google Access. DNS to the metadata server is always allowed by GCP.

### SSH

SSH is allowed only from `trusted_ssh_cidrs`. It is a required input with no default and a `null` value is an error. Validation accepts only canonical IPv4 CIDRs (no IPv6, no host bits, no whitespace) and rejects an empty list, `0.0.0.0/0`, any prefix shorter than /8, and a list whose entries add up to more than one /8 (16,777,216 addresses) in total, so a long list of /8s cannot rebuild the internet. IPv6 is rejected because the VPC is IPv4-only and a GCP firewall rule cannot mix IPv4 and IPv6 ranges. A looser floor would let someone paste a "mostly the internet" range, and a tighter one would block legitimate large corporate ranges. A `check` block warns on anything wider than /16.

**Reachability and the bastion.** The web instance has no external IP, as the brief's "private subnet" implies. A trusted public address such as an office IP can never open a TCP connection to it directly, whatever the firewall says. The load balancer does not help: it carries only HTTP(S) and is not in a subnet. To make the SSH requirement work end to end, the module adds a small bastion VM in the public subnet (`bastion.tf`, `enable_bastion`, on by default):

1. The trusted range reaches the bastion on tcp/22 (`allow-ssh-bastion-in`). The bastion has the only external IP in the module.
2. The bastion reaches the web instance on tcp/22 (`allow-ssh-bastion-to-web`). The source is the bastion's service account, so no other host in the VPC can use that path.
3. The bastion's egress is limited to tcp/22 into the private subnet, plus tcp/80 and tcp/443 for updates.

`allow-ssh-trusted` (trusted range straight to the web instance) stays. It is the literal rule from the brief and it is what makes the module work with `enable_bastion = false` when the trusted ranges reach the VPC over VPN, Interconnect or peering.

The bastion is hardened like the web instance: dedicated service account with no project roles, Shielded VM, OS Login, project SSH keys blocked, serial port off, no IP forwarding. The one Checkov skip in the module is `CKV_GCP_40` on the bastion, because the external IP is its purpose. Cost: one e2-micro and one external IP. Users need an OS Login role on both instances, for example `roles/compute.osAdminLogin`. A connection looks like `ssh -J <os-login-user>@<bastion_external_ip> <os-login-user>@<instance_internal_ip>`, with both addresses from the module outputs. This path has not been tested live.

IAP TCP forwarding is the better option because it needs no public SSH exposure and ties access to IAM. It is available with `enable_iap_ssh = true` and is off by default, so the default meets the task's literal requirement. Users of IAP need `roles/iap.tunnelResourceAccessor`. With OS Login on, SSH users also need `roles/compute.osLogin` (or `roles/compute.osAdminLogin`) on the instance or project.

### Instance hardening

Private subnet only, no external IP. Dedicated service account, never the default compute account. Shielded VM with secure boot, vTPM and integrity monitoring. OS Login on, project SSH keys blocked, serial port off, IP forwarding off. Boot disk uses Google-managed encryption, or your key if you set `kms_key_self_link` (CMEK). The image is the Debian 13 family. Debian 12 left regular security support in July 2026, so the module no longer defaults to it; set `boot_image` to pin another family. The startup script runs a Python static file server as `nobody` under a hardened systemd unit.

### IAM

The web instance's service account has `roles/logging.logWriter` and `roles/monitoring.metricWriter`, nothing else. The bastion's account has no roles. Instance OAuth scopes match the two roles (`logging.write`, `monitoring.write`), never `cloud-platform`. SSH logins are granted per instance, not per project: `ssh_login_members` gets `roles/compute.osLogin` (no sudo) on the web instance and the bastion only, and `roles/iap.tunnelResourceAccessor` on the web instance when `enable_iap_ssh` is on. Nobody is granted login by default. Bindings use `google_project_iam_member`, which is non-authoritative and leaves other bindings alone. A test fails if `roles/editor` or `roles/owner` appears.

Roles the deployer identity needs (chosen from role descriptions, not proven by a live apply, so expect to adjust after the first real run):

| Role | Why |
| --- | --- |
| `roles/compute.networkAdmin` | VPC, subnets, router, NAT, global address |
| `roles/compute.securityAdmin` | Firewall rules, SSL policy, Cloud Armor policy |
| `roles/compute.loadBalancerAdmin` | Backend service, URL map, proxy, forwarding rule, certificate |
| `roles/compute.instanceAdmin.v1` | Instances, instance group, and the per-instance login bindings |
| `roles/iap.admin` (only with `enable_iap_ssh` and `ssh_login_members`) | IAP tunnel bindings on the web instance |
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
- The log and metric writer roles are granted but nothing on the instance uses them yet: no Ops Agent is installed. They are there so an agent can be added without touching IAM.
- The bastion is a single host with an external IP and an SSH daemon. It is limited by the firewall and OS Login, but it is more attack surface than IAP alone.
- No organisation policy constraints, no VPC Service Controls, no log sink.
- The mock-provider tests cannot detect an argument that the real API rejects or a lifecycle problem. Both defects listed under live verification were found only by applying.
- After a real instance replacement the instance group stays empty until a second `terraform apply`.
- The startup script runs at boot only. After editing it, reset the instance.
- The load balancer needs DNS and certificate provisioning (often tens of minutes) before HTTPS works.
