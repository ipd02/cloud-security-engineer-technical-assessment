# Part 3: multi-cloud firewall scanner

## What it is

`fwscan` is a read-only command line tool written in Go. It checks the network firewall rules of AWS, GCP and Azure and reports every rule that lets the whole internet in.

### What it does

- Logs in to each cloud with the credentials you already have (the SDKs' default credential chains).
- Finds what those credentials can see: organizations, accounts, projects, subscriptions and regions.
- Reads the firewall rules: AWS security groups, GCP firewall rules and firewall policies, Azure network security groups (NSGs).
- Reports every inbound allow rule whose source is `0.0.0.0/0`, whatever its protocol or port.
- Never changes anything. It only lists and describes.

### What you get

- A JSON report in the shape of the task's example, with one list per cloud and an `errors` list.
- Exit codes you can use in a pipeline: 0 clean, 1 findings, 2 incomplete.
- A mock mode that runs without any credentials.

### What the task asks, and where it is covered

| Task requirement | Covered by |
| --- | --- |
| Authenticate with AWS, GCP and Azure | Default credential chains. See [Run it](#run-it) and each cloud section. |
| Fetch all firewall and security group rules | Pagination, all regions, and discovery of accounts, projects and subscriptions. See [Default scope](#default-scope). |
| Detect `0.0.0.0/0` inbound for any protocol and port | See [What counts as insecure](#what-counts-as-insecure). |
| Output the findings as JSON | See [Output](#output). |
| AWS: Go SDK, list EC2 security groups | [AWS](#aws): `ec2.DescribeSecurityGroups` with the SDK for Go v2. |
| GCP: Go SDK, list firewall rules, `sourceRanges` | [GCP](#gcp): the Compute `FirewallsClient`. |
| Azure: Go SDK, list NSGs, "Any" source | [Azure](#azure): the `armnetwork` NSG client. |

## How it works

### The flow

1. **Authenticate.** Each provider builds its client from the default credential chain of its SDK. The tool takes no credentials as flags.
2. **Discover the scope.** With no scope flag, each cloud scans everything its credentials can see. Flags narrow it.
3. **Fetch the rules.** The cloud clients sit behind small interfaces and follow every page of results.
4. **Detect.** Pure functions in `internal/detect` decide whether a rule is open, with no SDK types and no network.
5. **Report.** The findings are sorted and written as JSON. A failure in one provider is recorded in `errors` and does not hide the others.

### What counts as insecure

"Any protocol and any port" means every inbound allow rule whose source is the whole internet is reported, whatever its protocol or port. The task's own example lists `tcp/8080` and `udp/123`.

For all three clouds a finding needs these things:

- The rule is inbound (ingress).
- The rule allows traffic. Deny rules are ignored.
- The rule is enabled.
- The source is the literal `0.0.0.0/0`. Several ranges that together cover the internet, such as `0.0.0.0/1` and `128.0.0.0/1`, are not reported. This follows the task, which names `0.0.0.0/0`.
- A rule with several protocol and port entries produces one finding per entry.
- IPv6 `::/0` is not part of the task. It is reported only with `--include-ipv6`, and shows as `::/0` in the `source` field.

Each cloud adds its own details, described below.

### Design choices

- **Detection is pure.** `internal/detect` takes plain values and returns findings. The cloud adapters convert SDK types into those values.
- **Everything is replaceable in tests.** Each adapter talks to a small interface, so tests use fake clients. `--mock` runs the real adapters against fake clients that return SDK types, so it exercises the same code as a real scan.
- **Partial results are kept.** A provider, region, account, project or subscription that fails is listed in `errors`, and what was found before the failure stays in the output. An incomplete scan exits 2, so it is never mistaken for a clean one.
- **Providers run concurrently** with `errgroup`. Inside a provider, AWS regions, AWS accounts and Azure subscriptions are scanned in parallel, at most 8 at once. GCP projects are scanned one after another. The context carries the `--timeout`.
- **Rule priority is not evaluated.** The tool reports rules that are open. It does not work out whether a higher-priority deny rule blocks the traffic, so it can over-report. Each cloud section says where this applies.

### Layout

```
cmd/fwscan/            flags, concurrency, exit codes
internal/model/        report types (JSON shape)
internal/detect/       pure functions: is this rule open to the world
internal/scan/aws/     EC2 adapter behind a small interface, paginator, multi-region, organization accounts
internal/scan/gcp/     compute and Cloud Asset clients behind small interfaces (VPC rules, policies, org scope)
internal/scan/azure/   armnetwork SecurityGroupsClient pager behind an interface
internal/report/       JSON writer
internal/mock/         fixture clients for --mock (they return SDK types, so the real adapters run)
```

Go 1.26.0 is the minimum, set by the SDK dependencies. All versions are in `go.mod`.

## Default scope

With no scope flag, each cloud scans everything its credentials can see:

| Cloud | Default | Flags that narrow it |
| --- | --- | --- |
| AWS | The organization when the caller can list its accounts, else the caller's account. All enabled regions. | `--aws-scope`, `--aws-regions` |
| GCP | Every organization the caller can see, or, when there is none, every project the caller can see. | `--gcp-org`, `--gcp-folder`, `--gcp-project` |
| Azure | Every enabled subscription the credential can read. | `--azure-subscription` |

## AWS

**What it reads.** EC2 `DescribeSecurityGroups` with the SDK for Go v2 paginator, and `DescribeRegions` for `--aws-regions all`. For organizations it also uses Organizations `ListAccounts` and STS `AssumeRole`.

**Authentication.** The default AWS credential chain: environment, shared config, SSO or `aws login`, and roles. Without a configured region the tool falls back to `us-east-1` for credential handling.

**Scope.**

- `--aws-scope auto` (the default) scans the organization when the caller can list its accounts, and the caller's own account otherwise. `org` requires the organization. `account` scans only the caller's account.
- The caller's own account is scanned with the caller's credentials. Every other active account is reached by assuming the role named by `--aws-role-name` (default `fwscan-reader`). The role must exist in each account and trust the caller.
- Suspended and closing accounts are skipped. A role that cannot be assumed in one account is listed in `errors`, and the other accounts still report.
- Regions default to `all`, which means every enabled region.
- Findings carry the account id and the region.

**What counts.** Each `IpPermissions[].IpRanges[].CidrIp` equal to `0.0.0.0/0`. Protocol `-1` is reported as protocol `all`, port `all`. Numeric protocols 1, 6, 17 and 58 are shown as `icmp`, `tcp`, `udp` and `icmpv6`. A tcp or udp range of 0-65535 is shown as `all`. For ICMP the numbers are type and code, and `-1` is `all`. With `--include-ipv6`, `Ipv6Ranges` equal to `::/0` count too. Only ingress rules are read. The default egress rule every group has is never reported.

**Things to know.**

- It does not check whether a group is attached to anything.
- Prefix lists and referenced security groups are not expanded.
- It reads security groups only, not network ACLs or AWS Network Firewall.
- Only the `aws` partition is supported.
- Temporary credentials issued by the global STS endpoint are rejected in opt-in regions. With `--aws-regions all` such a region fails with `AuthFailure`, the other regions still report, and the exit code is 2. Use a regional STS endpoint (`AWS_STS_REGIONAL_ENDPOINTS=regional`) or long-lived role credentials.
- The tool warns on stderr when it runs as the AWS root user.

**Permissions.**

| Case | Needed | Notes |
| --- | --- | --- |
| One account | `ec2:DescribeSecurityGroups`, plus `ec2:DescribeRegions` for `--aws-regions all` | Allow only these two actions on `*`. The Describe actions do not support resource-level scoping. |
| Organization | The caller needs `organizations:ListAccounts` and `sts:AssumeRole` on the role in each other account. The role in each account holds the two EC2 actions. | The role must trust the caller. The root user cannot assume roles. Without `organizations:ListAccounts`, `--aws-scope auto` scans the caller's account only. |

## GCP

**What it reads.**

- VPC firewall rules: the Compute `FirewallsClient`.
- Network firewall policies: the Compute `NetworkFirewallPoliciesClient` (global and regional, from the aggregated list).
- Hierarchical firewall policies of organizations and folders: the Compute `FirewallPoliciesClient`.
- For organization and folder scope, Cloud Asset Inventory `SearchAllResources`. To find organizations and projects, Resource Manager search.

**Authentication.** Application Default Credentials. With user credentials, organization and folder scans need a quota project: pass `--gcp-quota-project`, or run `gcloud auth application-default set-quota-project`. The Cloud Asset API must be enabled in that project.

**Scope.**

- With no scope flag, every organization the caller can see is scanned. When there is none, every project the caller can see is scanned.
- `--gcp-org` and `--gcp-folder` exclude each other. They read VPC firewall rules from the Cloud Asset Inventory index and cover every project below. A GCP project can be combined with either, and a project inside a scanned scope is reported once.
- `--gcp-project` takes a comma separated list and reads the Compute API directly, in real time. Projects are scanned one after another.
- A project whose Compute API is off is skipped without an error.
- `--gcp-policies` (on by default) adds network and hierarchical policies. Turn it off to need fewer permissions.
- Findings carry the project. Policy findings also carry a `type`.

**What counts.**

- VPC firewall rules: direction `INGRESS` (an empty direction counts as ingress), not `disabled`, `allowed` entries present, `sourceRanges` contains `0.0.0.0/0`. An `allowed` entry with no `ports` means all ports. Each port or range in `ports` is one finding. Deny rules and egress rules are ignored.
- Policy rules (network and hierarchical policies): direction `INGRESS`, not disabled, action `allow`, `srcIpRanges` contains `0.0.0.0/0`. Each `layer4Configs` entry is read like an `allowed` entry. The finding has a `type` and the rule priority as `rule_id`.

**Things to know.**

- It does not evaluate rule priority or the order between VPC rules and policies. A rule shadowed by a higher-priority deny is still reported.
- It ignores target tags and target service accounts, and does not check whether any instance uses a rule.
- Only `sourceRanges` and `srcIpRanges` are read. A rule that has only source tags or source service accounts is not reported. A rule with both a source range of `0.0.0.0/0` and source tags is reported, because GCP treats them as alternatives.
- Policies: `allow` is the only action reported. `goto_next` and `deny` are not, and neither is an allow that goes through a security profile group. Source address groups, FQDNs, region codes and secure tags in a policy rule are not read. A policy that is not attached to anything is still reported.
- Hierarchical policies are read for the organization or folder and its subfolders. A folder you pass with `--gcp-folder` is not checked for policies of its parents.
- The Cloud Asset index lags behind real changes. In a test, a rule created seconds earlier was missing from the first run and present about 30 seconds later. `--gcp-project` has no such delay.

**Permissions.**

| Case | Needed | Notes |
| --- | --- | --- |
| Project scope, `--gcp-policies=false` | `compute.firewalls.list` on each project | A custom role with this one permission is the tightest option. `roles/compute.networkViewer` also works and is broader. `roles/compute.securityAdmin` is too broad. |
| Project scope, default | add `compute.firewallPolicies.list` on each project | Network firewall policies. Not in `roles/compute.networkViewer`. |
| No scope flag | `resourcemanager.organizations.get` to find organizations, and `resourcemanager.projects.get` to find projects | Without them nothing is found and the tool asks for a scope flag. |
| Organization or folder scope | `cloudasset.assets.searchAllResources` on the scope, and `compute.firewallPolicies.list` on the organization, on each folder and on each project | The caller needs `serviceusage.services.use` on the quota project. `roles/cloudasset.viewer` includes the first permission and is broad. Use a custom role. |

## Azure

**What it reads.** The `armnetwork` `SecurityGroupsClient` pager over all NSGs of a subscription, and the `armsubscriptions` client to list subscriptions.

**Authentication.** `DefaultAzureCredential`: environment variables for a service principal, workload identity, managed identity, and the Azure CLI login.

**Scope.**

- With no subscription named, every enabled subscription the credential can read is scanned. This is the Azure tenant scope.
- `--azure-subscription` takes a comma separated list. `--azure-all-subscriptions` adds all readable subscriptions to the ones you name.
- Subscriptions are scanned in parallel, at most 8 at once. A failing subscription is listed in `errors` and the others still report.
- NSGs in every region of a subscription are listed together.
- Management groups are not walked.

**What counts.** Direction `Inbound`, access `Allow`, custom `securityRules` only. The source is `*`, `Any`, `Internet` or `0.0.0.0/0`, in `sourceAddressPrefix` or in any entry of `sourceAddressPrefixes` (case-insensitive). Ports come from `destinationPortRange` and each entry of `destinationPortRanges`. The source is reported as written, so a rule with `*` shows `"source": "*"`. Azure's built-in default rules are skipped.

**Things to know.**

- `Internet` is a service tag for public address space, not literally `0.0.0.0/0`. It is treated as open to the internet on purpose, as the task intends.
- Rule priority is not evaluated, so a higher-priority deny rule that would block the traffic is not considered. It does not model the association of an NSG with subnets or NICs either. Both can cause over-reporting.
- It reads NSGs only, not Azure Firewall, application security groups or Virtual Network Manager security admin rules.
- Azure refuses a rule whose source prefixes overlap, so `0.0.0.0/0` cannot share a list with other CIDRs.

**Permissions.**

| Case | Needed | Notes |
| --- | --- | --- |
| Any | `Microsoft.Network/networkSecurityGroups/read` on each subscription | Built-in `Reader` on the subscription covers this. A custom role with that one action is tighter. `Network Contributor` is too broad. |
| All subscriptions | no extra permission | `--azure-all-subscriptions` lists the subscriptions where the identity holds a role. |

## Run it

No credentials are needed for the mock run:

```sh
make fwscan-mock                         # from the repo root
# or
cd 03-firewall-scanner && go run ./cmd/fwscan --mock
```

Build, test and lint from the repo root:

```sh
make fwscan-build     # builds 03-firewall-scanner/bin/fwscan, version from git via -ldflags
make fwscan-test      # go test -race ./...
make fwscan-lint      # golangci-lint with the root .golangci.yml
```

Real scans use the default credential chain of each cloud:

```sh
fwscan                                                  # everything the credentials can see, in all three clouds
fwscan --providers aws --aws-regions eu-west-1,eu-north-1 --aws-scope account
fwscan --providers gcp --gcp-org 123456789012
fwscan --providers gcp --gcp-project my-project
fwscan --providers azure --azure-subscription 00000000-0000-0000-0000-000000000000
fwscan --fail-on-findings --output report.json --gcp-project my-project --azure-subscription <id>
```

### Flags

General:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--providers` | `aws,gcp,azure` | Providers to scan, comma separated. |
| `--mock` | off | Use built-in fixtures. No credentials, no network. |
| `--output` | `-` | Output file, or `-` for stdout. A new file is created with mode 0600. An existing file is overwritten and keeps its mode. |
| `--fail-on-findings` | off | Exit 1 when at least one insecure rule is found. |
| `--timeout` | `60s` | Overall scan timeout. |
| `--include-ipv6` | off | Also report `::/0` sources (an extension). |
| `--version` | | Print the version. |

AWS:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--aws-regions` | `all` | Comma separated regions, or `all` (every enabled region, read with `DescribeRegions`). |
| `--aws-scope` | `auto` | `auto`, `org` or `account`, as described in the AWS section. |
| `--aws-role-name` | `fwscan-reader` | Role assumed in the other accounts of an organization. |

GCP:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--gcp-org` | none | Organization number. Scans every project under it through Cloud Asset Inventory. |
| `--gcp-folder` | none | Folder number. Same as `--gcp-org` for one folder and its subfolders. |
| `--gcp-project` | none | Project ids, comma separated. Reads the Compute API directly. |
| `--gcp-quota-project` | none | Project that is billed for the API calls. User credentials need it for `--gcp-org` and `--gcp-folder`. |
| `--gcp-policies` | on | Also read network and hierarchical firewall policies. |

Azure:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--azure-subscription` | none | Subscription ids, comma separated. |
| `--azure-all-subscriptions` | on when no subscription is named | Also scan every enabled subscription the credential can read. |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scan finished. No findings, or `--fail-on-findings` is off. |
| 1 | `--fail-on-findings` is set and findings exist. |
| 2 | Operational error: bad flags, unwritable output, or at least one provider failed or was incomplete. |

If findings exist and a provider also failed, the exit code is 2. An incomplete scan is not a clean result, so 2 wins.

### Running in CI

- Name the providers with `--providers`. A provider without credentials makes the run exit 2.
- Use `--fail-on-findings` to gate on findings, and a larger `--timeout` for big organizations. A scan that is cut short exits 2.
- Prefer keyless credentials: OIDC to an AWS role, workload identity federation for GCP, a federated credential for an Azure app. The default credential chains accept them.
- Give the identity only the permissions in the cloud sections. The AWS role in each account should trust the scanner's own role, not the whole account.
- The output names accounts, projects, resources and open ports. Write it to a file (`--output`) and keep it as a protected artifact.

## Output

The JSON follows the example in the task. The example is not valid JSON as printed, so this uses the clearly intended shape. Differences and additions:

- `port` is always a string: `"8080"`, `"1000-2000"`, `"all"` (AWS, GCP) or `"*"` (Azure).
- Only resources with at least one insecure rule are listed.
- Extra fields, all additive: `region` (AWS), `account` (AWS), `project` (GCP), `location` (Azure), `rule_id` (Azure rule name, or the priority of a GCP policy rule), `type` (GCP, only for policy rules: `network_firewall_policy` or `hierarchical_firewall_policy`), and a top-level `errors` list.
- For a GCP policy rule, `network` lists the networks the policy is attached to, or the folder or organization for a hierarchical policy. `project` is empty for a hierarchical policy.
- `errors` is always present. A provider that fails does not hide the other providers. Partial results from a provider that failed halfway are kept, and the error is listed.
- A provider that was not selected is omitted. A selected provider with no findings has an empty list.
- Output is sorted (region, id, name, then protocol, port, source), so runs can be diffed.

Example (`fwscan --mock`, trimmed to one provider):

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
  "errors": []
}
```

## Verified how

Every claim in this README about live behaviour comes from runs on 2026-10-14 against real test environments. Each run compared the findings with an expected set built from the cloud's own CLI output.

| Provider | Unit tests | Live runs |
| --- | --- | --- |
| AWS | A fake EC2 client: pagination over three pages, filtering, sorting, multi-region, `all` regions, partial failure, error on a later page, IPv6 flag. A fake Organizations client: account pages, suspended accounts, the caller's own account, scope fallback, partial failure. | One account that is the management account of an AWS Organization, with 18 test security groups in two regions. Scans with `--aws-regions` (one, two and `all`), `--include-ipv6`, `--aws-scope auto`, `org` and `account`. Run with the account's credentials and as a role that holds only `ec2:DescribeSecurityGroups` and `ec2:DescribeRegions` (checked with the IAM policy simulator). |
| GCP | Fake listers, a fake asset searcher and a fake discoverer for the scope logic. The real SDK clients against local `httptest` servers for page tokens, an HTTP 403, a slow server and a timeout, and for the Cloud Asset, network policy and hierarchical policy requests. | A test organization with two projects and one folder: 22 test VPC firewall rules next to the default ones, a network firewall policy, an organization policy and a folder policy. Scans by project list, folder, organization and by discovery with no flag. Run as the project owner and as a service account whose custom role holds `compute.firewalls.list`, `compute.firewallPolicies.list` and `cloudasset.assets.searchAllResources`. |
| Azure | The SDK's own fake server (`armnetwork/fake`): two pages, address prefix lists, port range lists, error on the second page. A fake subscription list: paging, disabled subscriptions, de-duplication, partial failure. | A free subscription with 4 NSGs in two regions and 20 rules, run through the Azure CLI login and as a service principal whose custom role holds only `Microsoft.Network/networkSecurityGroups/read`. Scans with `--azure-subscription` and `--azure-all-subscriptions`. |

- The detection logic has table-driven tests for tcp, udp, icmp, `-1`, port ranges, multiple CIDRs where one is open, IPv6, disabled GCP rules, egress rules, deny rules, policy rules, and Azure `*`, `Any` and `Internet`.
- The JSON output has a golden-file test (`cmd/fwscan/testdata/mock.golden.json`).
- The exit codes, the timeout and the isolation of one failing provider from the others are covered by tests that inject fake scanners.

This is a take-home sample. It has not been hardened or load tested.
