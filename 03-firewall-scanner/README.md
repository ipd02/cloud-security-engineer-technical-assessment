# Part 3: multi-cloud firewall scanner

`fwscan` is a read-only Go CLI. It lists AWS security groups, GCP VPC firewall rules and Azure network security groups (NSGs). It reports every inbound allow rule that is open to `0.0.0.0/0`, for any protocol and any port, and prints JSON.

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

| Flag | Default | Meaning |
| --- | --- | --- |
| `--providers` | `aws,gcp,azure` | Providers to scan, comma separated. |
| `--mock` | off | Use built-in fixtures. No credentials, no network. |
| `--output` | `-` | Output file, or `-` for stdout. A new file is created with mode 0600. An existing file is overwritten and keeps its mode. |
| `--fail-on-findings` | off | Exit 1 when at least one insecure rule is found. |
| `--timeout` | `60s` | Overall scan timeout. |
| `--include-ipv6` | off | Also report `::/0` sources (an extension, see below). |
| `--aws-regions` | `all` | Comma separated regions, or `all` (every enabled region, read with `DescribeRegions`). |
| `--aws-scope` | `auto` | `auto` scans the organization when the caller can list its accounts, and the caller's own account otherwise. `org` requires the organization. `account` scans only the caller's account. |
| `--aws-role-name` | `fwscan-reader` | Role assumed in the other accounts of an organization. It must exist in each of them. The caller's own account is scanned with the caller's credentials. |
| `--gcp-org` | none | GCP organization number. Scans every project under it through Cloud Asset Inventory. |
| `--gcp-folder` | none | GCP folder number. Same as `--gcp-org` for one folder and its subfolders. |
| `--gcp-project` | none | GCP project ids, comma separated. Reads the Compute API directly, in real time. |
| `--gcp-quota-project` | none | GCP project that is billed for the API calls. User credentials need it for `--gcp-org` and `--gcp-folder`, and the Cloud Asset API must be enabled there. The caller needs `serviceusage.services.use` on it. |
| `--gcp-policies` | on | Also read GCP network and hierarchical firewall policies. Turn it off to need fewer permissions. |
| `--azure-subscription` | none | Azure subscription ids, comma separated. |
| `--azure-all-subscriptions` | on when no subscription is named | Also scan every enabled subscription the credential can read. This is the Azure tenant scope. |

## Default scope

With no scope flag, each cloud scans everything its credentials can see:

| Cloud | Default | Flags that narrow it |
| --- | --- | --- |
| AWS | The organization when the caller can list its accounts, else the caller's account. All enabled regions. | `--aws-scope`, `--aws-regions` |
| GCP | Every organization the caller can see, or, when there is none, every project the caller can see. | `--gcp-org`, `--gcp-folder`, `--gcp-project` |
| Azure | Every enabled subscription the credential can read. | `--azure-subscription` |

`--gcp-org` and `--gcp-folder` exclude each other. A GCP project can be combined with either, and a project inside a scanned scope is reported once. `--azure-all-subscriptions` adds all readable subscriptions to the ones named with `--azure-subscription`. With user credentials GCP organization scans need `--gcp-quota-project` (or `gcloud auth application-default set-quota-project`).
| `--version` | | Print the version. |

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Scan finished. No findings, or `--fail-on-findings` is off. |
| 1 | `--fail-on-findings` is set and findings exist. |
| 2 | Operational error: bad flags, unwritable output, or at least one provider failed or was incomplete. |

If findings exist and a provider also failed, the exit code is 2. An incomplete scan is not a clean result, so 2 wins.

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

## How rules are interpreted

"Any protocol and any port" means every inbound allow rule whose source is the whole internet is reported, whatever its protocol or port. The task's own example lists `tcp/8080` and `udp/123`.

| Cloud | What counts |
| --- | --- |
| AWS | Each `IpPermissions[].IpRanges[].CidrIp` equal to `0.0.0.0/0`. Protocol `-1` is reported as protocol `all`, port `all`. Numeric protocols 1, 6, 17 and 58 are shown as `icmp`, `tcp`, `udp`, `icmpv6`. A tcp or udp range of 0-65535 is shown as `all`. For ICMP the numbers are type and code (`-1` is `all`). |
| GCP | VPC firewall rules: direction `INGRESS` (an empty direction counts as ingress), not `disabled`, `allowed` entries present, `sourceRanges` contains `0.0.0.0/0`. An `allowed` entry with no `ports` means all ports. Each port or range in `ports` is one finding. Deny rules and egress rules are ignored. Policy rules (network and hierarchical firewall policies): direction `INGRESS`, not disabled, action `allow`, `srcIpRanges` contains `0.0.0.0/0`. Each `layer4Configs` entry is read like an `allowed` entry. The finding has a `type` and the priority as `rule_id`. |
| Azure | Direction `Inbound`, access `Allow`, custom `securityRules` only. The source is `*`, `Any`, `Internet` or `0.0.0.0/0`, in `sourceAddressPrefix` or in any entry of `sourceAddressPrefixes` (case-insensitive). Ports come from `destinationPortRange` and each entry of `destinationPortRanges`. The source is reported as written, so a rule with `*` shows `"source": "*"`. Azure's built-in default rules are skipped. |

Things to know:

- IPv6 `::/0` is not part of the task. It is reported only with `--include-ipv6`, and is labelled in the output by its source value `::/0`.
- Azure `Internet` is a service tag for public address space, not literally `0.0.0.0/0`. It is treated as open to the internet on purpose, as the task intends.
- Azure effective allow is out of scope. The scanner does not look at rule priority, so a higher-priority deny rule that would block the traffic is not considered. It may over-report. It does not model NSG association with subnets or NICs either.
- "Open" means the literal `0.0.0.0/0` (and `::/0` with the flag). Several ranges that together cover the internet, such as `0.0.0.0/1` and `128.0.0.0/1`, are not reported. This follows the task, which names `0.0.0.0/0`.
- GCP: it does not evaluate rule priority or the order between VPC rules and policies, and it ignores target tags and service accounts. It does not check whether any instance uses a rule. A rule shadowed by a higher-priority deny is still reported. Only `sourceRanges` and `srcIpRanges` are read. A rule that has only source tags or source service accounts is not reported. A rule with both a source range of `0.0.0.0/0` and source tags is reported, because GCP treats them as alternatives.
- GCP policies: `allow` is the only action reported. `goto_next` and `deny` are not, and neither is an allow that goes through a security profile group. Source address groups, FQDNs, region codes and secure tags in a policy rule are not read. A policy that is not attached to anything is still reported.
- GCP scope: `--gcp-org` and `--gcp-folder` read the Cloud Asset Inventory index. It lags behind real changes. In a test, a rule created seconds earlier was missing from the first run and present about 30 seconds later. `--gcp-project` reads the Compute API directly. Projects are scanned one after another, and a project whose Compute API is off is skipped without an error.
- GCP: regional network firewall policies come from the project-wide list. Hierarchical policies are read for the organization or folder and its subfolders. A folder you pass with `--gcp-folder` is not checked for policies of its parents.
- AWS: temporary credentials issued by the global STS endpoint are rejected in opt-in regions. With `--aws-regions all` that region fails with `AuthFailure`, the other regions still report, and the exit code is 2. Use a regional STS endpoint (`AWS_STS_REGIONAL_ENDPOINTS=regional`) or long-lived role credentials.
- AWS: in an organization it scans the active accounts, and accounts that are suspended or closing are skipped. A role that cannot be assumed in one account is reported in `errors`, and the other accounts still report. Only the `aws` partition is supported. It reads security groups only, not network ACLs or AWS Network Firewall.
- Azure: it scans the subscriptions you name, or every enabled subscription the credential can read. Management groups are not walked. It reads NSGs only, not Azure Firewall, application security groups or Virtual Network Manager security admin rules.
- AWS: it does not check whether the group is attached to anything. Only IPv4 and (optionally) IPv6 ranges are checked. Prefix lists and referenced security groups are not expanded.
- Several protocol and port entries in one rule produce several findings, one each.

## Least privilege for the scanner

The tool never changes anything. Give it a read-only identity.

| Cloud | Permission needed | Notes |
| --- | --- | --- |
| AWS | `ec2:DescribeSecurityGroups`, plus `ec2:DescribeRegions` for `--aws-regions all` | Allow only these two actions on `*` (the Describe actions do not support resource-level scoping). |
| AWS, organization scan | The caller needs `organizations:ListAccounts` and `sts:AssumeRole` on the role in each other account. The role in each account holds the two EC2 actions above. | The role must trust the caller. Without `organizations:ListAccounts`, `--aws-scope auto` scans the caller's account only. |
| GCP, project scope, `--gcp-policies=false` | `compute.firewalls.list` on each project | A custom role with this one permission is the tightest option. `roles/compute.networkViewer` also works and is broader. `roles/compute.securityAdmin` is too broad. |
| GCP, project scope, default | add `compute.firewallPolicies.list` on each project | Network firewall policies. Not in `roles/compute.networkViewer`. |
| GCP, no scope flag | `resourcemanager.organizations.get` to find organizations, and `resourcemanager.projects.get` to find projects | Without them nothing is found and the tool asks for a scope flag. |
| GCP, org or folder scope | `cloudasset.assets.searchAllResources` on the scope, `compute.firewallPolicies.list` on the organization, on each folder and on each project | The Cloud Asset API must be enabled in the project the credentials bill against. `roles/cloudasset.viewer` includes the first one and is broad. Use a custom role. |
| Azure | `Microsoft.Network/networkSecurityGroups/read` on each subscription | Built-in `Reader` on the subscription covers this. A custom role with that one action is tighter. `Network Contributor` is too broad. `--azure-all-subscriptions` lists the subscriptions where the identity holds a role, so it needs no extra permission. |

## Layout

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

Providers run concurrently with `errgroup`. The context carries the `--timeout`. A provider error is recorded in `errors` and never cancels the other providers. AWS regions are scanned in parallel, at most 8 at once.

Go 1.26.0 is the minimum, set by the SDK dependencies in `go.mod`. SDK versions (from `go.mod`): `aws-sdk-go-v2` v1.47.3, `service/ec2` v1.338.4, `config` v1.33.9; `cloud.google.com/go/compute` v1.72.0; `azidentity` v1.14.1, `azcore` v1.23.3, `armnetwork/v7` v7.2.0; `golang.org/x/sync` v0.24.0.

## Verified how

| Provider | Unit tests with fakes | Live run against a real account |
| --- | --- | --- |
| AWS | Yes. Fake EC2 client: pagination over three pages, filtering, sorting, multi-region, `all` regions, partial failure, error on a later page, IPv6 flag. | Not run. |
| GCP | Yes. Fake listers and a fake asset searcher for the scope logic. The real SDK clients against local `httptest` servers for page tokens, an HTTP 403, a slow server and a timeout, and for the Cloud Asset, network policy and hierarchical policy requests. | Not run. |
| Azure | Yes. The SDK's own fake server (`armnetwork/fake`): two pages, address prefix lists, port range lists, error on the second page. | Not run. |

- The detection logic has table-driven tests for tcp, udp, icmp, `-1`, port ranges, multiple CIDRs where one is open, IPv6, disabled GCP rules, egress rules, deny rules, and Azure `*`, `Any` and `Internet`.
- The JSON output has a golden-file test (`cmd/fwscan/testdata/mock.golden.json`).
- Credential loading (`aws.New`, `azidentity`, GCP Application Default Credentials) was not exercised against a real identity. The Azure scanner in particular has never talked to Azure.
- <!-- UPDATE: author may add a dated GCP live run here (date, scope, read-only identity) -->

This is a take-home sample. It has not been hardened or load tested.
