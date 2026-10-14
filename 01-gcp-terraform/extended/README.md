# Extended version

The [base version](../base/README.md) already meets the whole brief. This version is the base plus optional additions that improve the security posture. The brief does not ask for any of them. Each one is tagged `+ added` in the diagram. The [overview](../README.md) compares the two, and `diff -ru base extended` shows the code difference.

![Extended version diagram](../docs/extended.png)

## What it adds to the base

| Addition | Why | File |
| --- | --- | --- |
| Hardened instance and bastion: Shielded VM, OS Login, project SSH keys blocked, serial port off, no IP forwarding, optional CMEK disk key | A compromised or mis-keyed instance is harder to abuse | `compute.tf`, `bastion.tf` |
| Per-instance logins (`ssh_login_members`, `roles/compute.osLogin`, no sudo) and an optional IAP rule | Least privilege at resource level | `iam.tf`, `firewall.tf` |
| Deny-all ingress and egress, narrow egress allow | Explicit, auditable default deny. A compromised instance reaches less | `firewall.tf` |
| Cloud Router, Cloud NAT, Private Google Access | Updates without a public address | `network.tf` |
| TLS policy: MODERN, minimum TLS 1.2 | Old TLS versions are refused | `loadbalancer.tf` |
| Cloud Armor: OWASP rules, CVE rule, rate limit | Common web attacks filtered at the edge | `armor.tf` |
| Logs: VPC flow, firewall, NAT, load balancer, health check | Detection and investigation | `network.tf`, `firewall.tf`, `loadbalancer.tf` |
| `enable_bastion` switch and a direct trusted-range rule | For ranges that reach the VPC over VPN, Interconnect or peering | `bastion.tf`, `firewall.tf` |
| Custom Checkov policies, more tests | Guard rails a unit test cannot give | `policy/`, `tests/` |

Identical in both versions: the bastion SSH path, strict `trusted_ssh_cidrs` validation, the service accounts and their roles, rules that target service accounts, narrow instance scopes, the startup script in metadata, and the Debian 13 image. The explanations of the load balancer and the 443 rule are in the [base README](../base/README.md#design-notes).

## Firewall rules

| Rule | Direction | Source or destination | Port | Target | In base |
| --- | --- | --- | --- | --- | --- |
| allow-lb-http | ingress | `130.211.0.0/22`, `35.191.0.0/16` | tcp/80 | instance | yes |
| allow-ssh-bastion-in | ingress | `trusted_ssh_cidrs` | tcp/22 | bastion | yes |
| allow-ssh-bastion-to-web | ingress | bastion service account | tcp/22 | instance | yes |
| allow-ssh-trusted | ingress | `trusted_ssh_cidrs` | tcp/22 | instance | added |
| allow-ssh-iap (opt-in) | ingress | `35.235.240.0/20` | tcp/22 | instance | added |
| deny-all-ingress, deny-all-ingress-v6 | ingress | `0.0.0.0/0`, `::/0` | all | all | added |
| allow-egress-web | egress | `0.0.0.0/0` | tcp/80, tcp/443 | instance and bastion | added |
| allow-egress-bastion-ssh | egress | private subnet range | tcp/22 | bastion | added |
| deny-all-egress | egress | `0.0.0.0/0` | all | all | added |

Allow rules use priority 1000, deny rules 65000, and every rule logs. Rules target service accounts, not network tags, because anyone who can edit an instance can add a tag, while using a service account needs `iam.serviceAccounts.actAs`. The Google ranges were checked against [the load balancer firewall docs](https://docs.cloud.google.com/load-balancing/docs/firewall-rules) and the IAP range against [the IAP TCP forwarding docs](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding). Google can change them, so recheck.

## Notes on the additions

- **Bastion:** Shielded VM, OS Login, project SSH keys blocked, serial port off, egress limited to tcp/22 into the private subnet plus 80 and 443. A login looks like `ssh -J <user>@<bastion_external_ip> <user>@<instance_internal_ip>`, with both addresses from the outputs.
- **Logins and IAP:** `ssh_login_members` gets `roles/compute.osLogin` on the two instances only. With `enable_iap_ssh` they also get `roles/iap.tunnelResourceAccessor` on the instance. Nobody is granted login by default.
- **Instance:** secure boot, vTPM and integrity monitoring on. Boot disk uses a Google-managed key, or yours via `kms_key_self_link`. Debian 12 left regular security support in July 2026, so pin another family with `boot_image` if needed.
- **IAM guard rails:** a test and a custom Checkov policy fail if `roles/editor` or `roles/owner` appears.
- **Cloud Armor:** `sqli`, `xss`, `lfi`, `rce` (`*-v33-stable`) and `cve-canary`, a rate limit of 300 requests per 60 seconds per IP (then 429), and Layer 7 adaptive protection. The OWASP rules can block legitimate traffic, so run them in preview mode on a real application first.
- **Deployer roles:** the same as the [base](../base/README.md#deployer-roles), plus `roles/iap.admin` when using the IAP bindings. Unproven.

## Verification

| Check | Result |
| --- | --- |
| `terraform fmt -check`, `init -backend=false`, `validate` | clean |
| `tflint` (recommended preset, recursive) | no issues |
| `terraform test` (mocked provider) | 48 passed, 0 failed |
| `checkov` with the three custom policies | 98 passed, 0 failed, 1 documented skip |
| `make lint test scan` | green |

The tests have one run per bullet of the brief, plus the SSH range validation cases, the additions, and the opt-in options. They check the rendered configuration, not real GCP behaviour. Three custom Checkov policies cover what a test cannot see: no `roles/editor` or `roles/owner` bindings, forwarding rules on tcp/443 only, and no ingress allow from the whole internet.

**Checkov skip:** `CKV_GCP_40` on the bastion (it is the SSH entry point). The instance passes the check.

### Live run, 2026-10-13

Applied in a throwaway project (35 resources) with a self-signed certificate, tested, then destroyed. A listing showed nothing left behind.

| Check | Result |
| --- | --- |
| Backend service, `https://<lb ip>/` | `HEALTHY`, 200 (a few minutes after apply) |
| TLS, port 80 | 1.2 and 1.3 negotiate, port 80 gets no answer |
| Cloud Armor | 403 for SQL injection, XSS, path traversal, shell command and `${jndi:...}` strings |
| Instance | Debian 13, no external IP, Shielded VM and OS Login on, two scopes |
| SSH | trusted `/32` to bastion to instance works. Direct to the instance times out. The bastion refuses another range |
| Bastion to instance | tcp/22 open, tcp/80 closed |
| Egress | instance reaches 80 and 443 through NAT, 8080 refused. Bastion 8080 refused |
| IAM | login bindings on the two instances only. Writer roles only on the instance account. None on the bastion |
| Logs | VPC flow, firewall (allow and deny), NAT, load balancer and health check entries appeared |
| Rate limit (300 per 60 s) | one run: 637 allowed, 1,613 got 429 |

The rate limit did not enforce on the first policy: more than 8,000 requests over about half an hour got no 429, then it enforced after I changed the rule once with `gcloud`. I do not know why. Google documents enforcement as approximate, so treat the limit as configured and observed, not guaranteed.

**Defects only the live runs found, now fixed:**

- Editing the startup script replaced the instance, and GCP dropped the replacement from the unmanaged instance group, so the load balancer had no backend. The script now lives in `metadata`, so edits update in place.
- The group update needs the instance's full `self_link`.
- systemd warned that `User=nobody` is "not safe" on Debian 13, so the unit uses `DynamicUser=yes`.

Not verified: TLS 1.1 refusal, IAP, CMEK, the Google-managed certificate, the no-sudo behaviour of `roles/compute.osLogin` (my test account is a project owner), whether the OWASP rules give false positives.

## Limits

- One instance in one zone, no autoscaling. Port 80 behind the load balancer is plain HTTP.
- The writer roles are granted but nothing uses them yet, because no Ops Agent is installed.
- The bastion is one host with an external IP. The firewall and OS Login limit it, but IAP alone would expose less.
- No organisation policy constraints, no VPC Service Controls, no log sink.
- After a real instance replacement the instance group stays empty until a second `terraform apply`. The startup script runs at boot, so reset the instance after editing it.
- The load balancer needs DNS and certificate provisioning (often tens of minutes) before HTTPS works.
