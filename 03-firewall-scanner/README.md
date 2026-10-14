# Part 3: fwscan, a multi-cloud firewall scanner

`fwscan` is a read-only Go command line tool. It checks the firewall rules of AWS, GCP and Azure and reports every inbound rule that is open to the whole internet (`0.0.0.0/0`), for any protocol and any port.

To try it without credentials: `make fwscan-mock` from the repository root.

## Overview

**What it does**

- Uses the credentials you already have, through each SDK's default credential chain.
- Finds what those credentials can see: organizations, accounts, projects, subscriptions and regions.
- Reads the firewall rules: AWS security groups, GCP firewall rules and policies, Azure network security groups (NSGs).
- Reports every inbound allow rule whose source is `0.0.0.0/0`.
- Never changes anything. It only lists and describes.

**What you get**

- A JSON report in the shape of the task's example.
- An exit code for pipelines: 0 clean, 1 findings, 2 scan incomplete.
- A mock mode that needs no credentials.

**Where the task is covered**

| Task requirement | Where |
| --- | --- |
| Authenticate with AWS, GCP and Azure | The Credentials part of [AWS](#aws), [GCP](#gcp) and [Azure](#azure) |
| Fetch all firewall rules | [What is scanned by default](#what-is-scanned-by-default) |
| Detect `0.0.0.0/0` for any protocol and port | [What counts as a finding](#what-counts-as-a-finding) |
| Output JSON | [Output](#output) |
| AWS: Go SDK, EC2 security groups | [AWS](#aws) |
| GCP: Go SDK, firewall rules, `sourceRanges` | [GCP](#gcp) |
| Azure: Go SDK, NSGs, "Any" source | [Azure](#azure) |

## How it works

1. **Log in.** Each provider builds its client from the SDK's default credential chain. The tool takes no credentials as flags.
2. **Find the scope.** With no scope flag, each cloud scans everything its credentials can see. Flags narrow it.
3. **Read the rules.** Each cloud client follows every page of results.
4. **Check each rule.** Pure functions in `internal/detect` decide whether a rule is open. They use no SDK types and no network.
5. **Write the report.** Findings are sorted and printed as JSON. If a provider fails, the error goes into `errors` and the other providers still report.

### What counts as a finding

"Any protocol and any port" means every inbound allow rule whose source is the whole internet is reported, whatever its protocol or port. The task's own example lists `tcp/8080` and `udp/123`.

A rule is reported when all of these are true:

- It is inbound.
- It allows traffic. Deny rules are ignored.
- It is enabled.
- Its source is the literal `0.0.0.0/0`. Ranges that only add up to the whole internet, such as `0.0.0.0/1` plus `128.0.0.0/1`, are not reported.

A rule with several protocol and port entries gives one finding per entry. IPv6 `::/0` is not part of the task, so it is reported only with `--include-ipv6`.

### Design

- Detection is separate from the cloud code, so it is easy to test.
- Every cloud client sits behind a small interface. Tests use fake clients, and `--mock` runs the real code against fake clients.
- If something fails halfway, what was found before the failure stays in the output, and the exit code is 2. An incomplete scan is never shown as clean.
- Providers run at the same time. Inside a provider, AWS regions, AWS accounts and Azure subscriptions run in parallel, at most 8 at once. GCP projects run one after another.
- Rule priority is not evaluated, so a deny rule that would block an open rule is not taken into account. The tool can over-report.

### Code layout

```
cmd/fwscan/            flags, concurrency, exit codes
internal/detect/       is this rule open to the world (pure functions)
internal/scan/aws/     EC2, Organizations and STS
internal/scan/gcp/     Compute, Cloud Asset and Resource Manager
internal/scan/azure/   NSG and subscription clients
internal/model/        report types (the JSON shape)
internal/report/       JSON writer
internal/mock/         fake clients for --mock
```

Go 1.26.0 is the minimum. All dependency versions are in `go.mod`.

## What is scanned by default

With no scope flag, each cloud scans everything its credentials can see:

| Cloud | Default | Flags that narrow it |
| --- | --- | --- |
| AWS | The organization if the caller can list its accounts, otherwise the caller's account. All enabled regions. | `--aws-scope`, `--aws-regions` |
| GCP | Every organization the caller can see, or if there is none, every project the caller can see. | `--gcp-org`, `--gcp-folder`, `--gcp-project` |
| Azure | Every enabled subscription the credential can read. | `--azure-subscription` |

## AWS

**Credentials.** The default AWS chain: environment variables, shared config, SSO or `aws login`, and roles. If no region is configured, `us-east-1` is used for credential handling.

**What is scanned.** Security groups, through EC2 `DescribeSecurityGroups` (SDK for Go v2, paginated).

- Regions: `all` enabled regions by default (from `DescribeRegions`), or the ones you list.
- `--aws-scope auto` (default): the organization if the caller can list its accounts, otherwise the caller's account. `org` requires an organization. `account` scans only the caller's account.
- The caller's own account is scanned with the caller's credentials. Other active accounts are reached by assuming the role `--aws-role-name` (default `fwscan-reader`). The role must exist in each account and trust the caller.
- Suspended and closing accounts are skipped. If a role cannot be assumed in one account, the error is listed and the other accounts still report.

**What is reported.** Each `IpRanges[].CidrIp` equal to `0.0.0.0/0` in a group's inbound rules. The report shows the protocol (`-1` becomes `all`; protocols 1, 6, 17 and 58 become `icmp`, `tcp`, `udp`, `icmpv6`) and the port or port range. A tcp or udp range of 0-65535 is shown as `all`. For ICMP the numbers are type and code. With `--include-ipv6`, `Ipv6Ranges` equal to `::/0` count too. Egress rules are never reported.

**Limits.**

- It does not check whether a group is attached to anything.
- Prefix lists and referenced security groups are not expanded.
- Network ACLs and AWS Network Firewall are not read.
- Only the `aws` partition is supported.
- Temporary credentials from the global STS endpoint are rejected in opt-in regions. With `--aws-regions all` that region fails, the others still report, and the exit code is 2. Use a regional STS endpoint (`AWS_STS_REGIONAL_ENDPOINTS=regional`) or long-lived role credentials.

The tool prints a warning on stderr when it runs as the AWS root user.

**Permissions needed.**

| Case | Permissions |
| --- | --- |
| One account | `ec2:DescribeSecurityGroups`, plus `ec2:DescribeRegions` for `--aws-regions all`. Both can only be granted on `*`. |
| Organization | The caller needs `organizations:ListAccounts` and `sts:AssumeRole` on the role in each other account. The role holds the two EC2 permissions and must trust the caller. The root user cannot assume roles. Without `organizations:ListAccounts`, `auto` scans the caller's account only. |

## GCP

**Credentials.** Application Default Credentials. With user credentials, organization and folder scans need a quota project: pass `--gcp-quota-project`, or run `gcloud auth application-default set-quota-project`. The Cloud Asset API must be enabled in that project.

**What is scanned.** VPC firewall rules (Compute `FirewallsClient`), and with `--gcp-policies` (on by default) network firewall policies and hierarchical policies of organizations and folders.

- No scope flag: every organization the caller can see, otherwise every project the caller can see.
- `--gcp-org` and `--gcp-folder` (not both) cover every project below, using Cloud Asset Inventory. A project you name that lies inside is reported once.
- `--gcp-project` takes a list and reads the Compute API directly, in real time.
- A project whose Compute API is off is skipped without an error.

**What is reported.**

- VPC firewall rules: ingress (an empty direction counts as ingress), not disabled, with `sourceRanges` containing `0.0.0.0/0`. An `allowed` entry without `ports` means all ports. Each port or range is one finding.
- Policy rules: ingress, not disabled, action `allow`, `srcIpRanges` containing `0.0.0.0/0`. Policy findings carry a `type` and the rule priority as `rule_id`.

**Limits.**

- Priority and the order between VPC rules and policies are not evaluated. A rule shadowed by a higher-priority deny is still reported.
- Target tags and target service accounts are ignored, and it does not check whether any instance uses a rule.
- Only `sourceRanges` and `srcIpRanges` are read. A rule with only source tags or source service accounts is not reported. A rule with `0.0.0.0/0` and source tags is reported, because GCP treats them as alternatives.
- In policies, only `allow` is reported. Rules with `goto_next`, `deny`, or an allow through a security profile group are not. Address groups, FQDNs, region codes and secure tags are not read. A policy attached to nothing is still reported.
- Hierarchical policies are read for the organization or folder and its subfolders, not for the parents of a folder you pass.
- The Cloud Asset index lags behind real changes. In a test, a rule created seconds earlier showed up about 30 seconds later. `--gcp-project` has no delay.

**Permissions needed.**

| Case | Permissions |
| --- | --- |
| Project scope, `--gcp-policies=false` | `compute.firewalls.list` on each project. A custom role with this one permission is the tightest. `roles/compute.networkViewer` also works and is broader. |
| Project scope, default | Add `compute.firewallPolicies.list` on each project. It is not in `roles/compute.networkViewer`. |
| No scope flag | `resourcemanager.organizations.get` to find organizations and `resourcemanager.projects.get` to find projects. Without them the tool asks for a scope flag. |
| Organization or folder scope | `cloudasset.assets.searchAllResources` on the scope, and `compute.firewallPolicies.list` on the organization, each folder and each project. The caller also needs `serviceusage.services.use` on the quota project. Use a custom role, because `roles/cloudasset.viewer` is broad. |

## Azure

**Credentials.** `DefaultAzureCredential`: environment variables for a service principal, workload identity, managed identity, and the Azure CLI login.

**What is scanned.** NSGs, through the `armnetwork` pager, in every region of each subscription.

- No subscription named: every enabled subscription the credential can read (the tenant).
- `--azure-subscription` takes a list. `--azure-all-subscriptions` adds all readable subscriptions to it.
- Subscriptions run in parallel, at most 8 at once. A failing subscription is listed in `errors` and the others still report.
- Management groups are not walked.

**What is reported.** Custom `securityRules` that are `Inbound` and `Allow`, with a source of `*`, `Any`, `Internet` or `0.0.0.0/0` (case-insensitive), in `sourceAddressPrefix` or in any entry of `sourceAddressPrefixes`. Ports come from `destinationPortRange` and each entry of `destinationPortRanges`. The source is shown as written, so a rule with `*` shows `"source": "*"`. Azure's built-in default rules are skipped.

**Limits.**

- `Internet` is a service tag for public address space, not literally `0.0.0.0/0`. It is treated as open on purpose, as the task intends.
- Priority and the association of an NSG with subnets or NICs are not evaluated, so a rule blocked by a higher-priority deny is still reported.
- Azure Firewall, application security groups and Virtual Network Manager security admin rules are not read.
- Azure refuses a rule whose source prefixes overlap, so `0.0.0.0/0` cannot share a list with other CIDRs.

**Permissions needed.** `Microsoft.Network/networkSecurityGroups/read` on each subscription. Built-in `Reader` covers it, and a custom role with that one action is tighter. `Network Contributor` is too broad. Listing all subscriptions needs no extra permission, because it returns the ones where the identity holds a role.

## Running it

### Try it without credentials

```sh
make fwscan-mock                         # from the repository root
# or
cd 03-firewall-scanner && go run ./cmd/fwscan --mock
```

Build, test and lint from the repository root:

```sh
make fwscan-build     # builds 03-firewall-scanner/bin/fwscan, with the version from git
make fwscan-test      # go test -race ./...
make fwscan-lint      # golangci-lint with the root .golangci.yml
```

### Scan real clouds

```sh
fwscan                                                  # everything the credentials can see, in all three clouds
fwscan --providers aws --aws-regions eu-west-1,eu-north-1 --aws-scope account
fwscan --providers gcp --gcp-org 123456789012
fwscan --providers gcp --gcp-project my-project
fwscan --providers azure --azure-subscription 00000000-0000-0000-0000-000000000000
fwscan --fail-on-findings --output report.json --gcp-project my-project --azure-subscription <id>
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--providers` | `aws,gcp,azure` | Providers to scan, comma separated. |
| `--mock` | off | Use built-in fixtures. No credentials, no network. |
| `--output` | `-` | Output file, or `-` for stdout. A new file is created with mode 0600. An existing file is overwritten and keeps its mode. |
| `--fail-on-findings` | off | Exit 1 when at least one rule is reported. |
| `--timeout` | `60s` | Overall scan timeout. |
| `--include-ipv6` | off | Also report `::/0` sources. |
| `--version` | | Print the version. |
| `--aws-regions` | `all` | Regions, comma separated, or `all` enabled regions. |
| `--aws-scope` | `auto` | `auto`, `org` or `account`. |
| `--aws-role-name` | `fwscan-reader` | Role assumed in the other accounts of an organization. |
| `--gcp-org` | none | Organization number. Scans every project under it. |
| `--gcp-folder` | none | Folder number. Scans every project under it. |
| `--gcp-project` | none | Project ids, comma separated. |
| `--gcp-quota-project` | none | Project billed for the API calls. User credentials need it for `--gcp-org` and `--gcp-folder`. |
| `--gcp-policies` | on | Also read network and hierarchical firewall policies. |
| `--azure-subscription` | none | Subscription ids, comma separated. |
| `--azure-all-subscriptions` | on when no subscription is named | Also scan every enabled subscription the credential can read. |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The scan finished. There are no findings, or `--fail-on-findings` is off. |
| 1 | `--fail-on-findings` is set and there are findings. |
| 2 | Bad flags, an unwritable output file, or at least one provider failed or was incomplete. |

If there are findings and a provider also failed, the exit code is 2. An incomplete scan is not a clean result.

### Using it in CI

- Name the providers with `--providers`. A provider without credentials makes the run exit 2.
- Use `--fail-on-findings` to fail the job on findings, and a larger `--timeout` for big organizations.
- Prefer keyless credentials: OIDC to an AWS role, workload identity federation for GCP, a federated credential for an Azure app.
- Give the identity only the permissions listed in the cloud sections. The AWS role in each account should trust the scanner's own role, not the whole account.
- The output names accounts, projects, resources and open ports. Write it to a file with `--output` and keep it as a protected artifact.

## Output

The task's example is not valid JSON as printed, so this uses the clearly intended shape. This is the output of `fwscan --mock`. The tool prints each rule over several lines. Here each rule is on one line to keep it short.

```json
{
  "aws": {
    "security_groups": [
      {
        "id": "sg-12345678",
        "name": "open-sg",
        "region": "us-east-1",
        "insecure_rules": [
          { "protocol": "tcp", "port": "8080", "source": "0.0.0.0/0" },
          { "protocol": "udp", "port": "123", "source": "0.0.0.0/0" }
        ]
      }
    ]
  },
  "gcp": {
    "firewall_rules": [
      {
        "name": "allow-all",
        "network": "default",
        "project": "example-project",
        "insecure_rules": [
          { "protocol": "icmp", "port": "all", "source": "0.0.0.0/0" }
        ]
      }
    ]
  },
  "azure": {
    "nsgs": [
      {
        "id": "/subscriptions/xxxx/resourceGroups/my-rg/providers/Microsoft.Network/networkSecurityGroups/my-nsg",
        "name": "open-nsg",
        "location": "westeurope",
        "insecure_rules": [
          { "protocol": "*", "port": "*", "source": "0.0.0.0/0", "rule_id": "allow-any" }
        ]
      }
    ]
  },
  "errors": []
}
```

Notes on the fields:

- `port` is always a string: `"8080"`, `"1000-2000"`, `"all"` (AWS and GCP) or `"*"` (Azure).
- Only resources with at least one reported rule are listed.
- Extra fields, not in the task's example: `region` and `account` (AWS), `project` (GCP), `location` (Azure), `rule_id` (the Azure rule name, or the priority of a GCP policy rule), `type` (GCP policy rules only: `network_firewall_policy` or `hierarchical_firewall_policy`) and the top-level `errors`.
- For a GCP policy rule, `network` lists the networks the policy is attached to, or the folder or organization for a hierarchical policy.
- `errors` is always present. It lists each provider, region, account, project or subscription that failed, and what was found before the failure is kept.
- A provider you did not select is left out. A selected provider with no findings has an empty list.
- The output is sorted, so two runs can be compared with a diff.

## How it was tested

All live runs were on 2026-10-14 against real test environments. Each run's findings were compared with an expected set built from the cloud's own CLI output.

**Unit tests** (`make fwscan-test`, with the race detector):

- Detection: tcp, udp, icmp, `-1`, port ranges, several CIDRs where one is open, IPv6, disabled, egress and deny rules, policy rules, and Azure `*`, `Any` and `Internet`.
- Adapters with fake clients: pagination, filtering, sorting, partial failures, errors on a later page, organizations, subscriptions and scope discovery. The real GCP clients also run against local test servers for page tokens, a 403, a slow server and a timeout.
- The mock output is checked against a golden file (`cmd/fwscan/testdata/mock.golden.json`).
- Exit codes, the timeout, and one failing provider not hiding the others, using fake scanners.

**Live runs**

| Cloud | Environment | Runs |
| --- | --- | --- |
| AWS | One account that is the management account of an AWS Organization, with 18 test security groups in two regions | Scans with one region, two regions and `all`, with `--include-ipv6`, and with `--aws-scope` `auto`, `org` and `account`. Run with the account's credentials, and as a role that holds only the two EC2 permissions (checked with the IAM policy simulator). |
| GCP | A test organization with two projects and one folder: 22 test VPC rules next to the default ones, a network policy, an organization policy and a folder policy | Scans by project list, folder, organization, and by discovery with no flag. Run as the project owner, and as a service account whose custom role holds `compute.firewalls.list`, `compute.firewallPolicies.list` and `cloudasset.assets.searchAllResources`. |
| Azure | A free subscription with 4 NSGs in two regions and 20 rules | Scans with `--azure-subscription` and `--azure-all-subscriptions`. Run through the Azure CLI login, and as a service principal whose custom role holds only `Microsoft.Network/networkSecurityGroups/read`. |

This is a take-home sample. It has not been hardened or load tested.
