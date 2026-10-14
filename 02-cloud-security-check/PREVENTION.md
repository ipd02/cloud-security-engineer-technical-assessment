# Prevention: stopping these misconfigurations from being introduced

The two inputs share five root causes:

1. A wildcard admin identity (`Action: *` on `Resource: *`).
2. A long-lived IAM user instead of a role.
3. A public-capable, unencrypted, unlogged bucket.
4. A container that runs as root on an end-of-life base image.
5. Secrets baked into the image.

The controls below follow the life of a change: development, pull request, deployment, runtime. Each phase has two kinds of control. Checks find a problem and report it. Policies make the problem impossible or refuse the change. Policies are stronger, because a person cannot skip them. Checks are cheaper and give earlier feedback. Use both.

## What this repository implements

| Phase | Implemented here | Described only |
| --- | --- | --- |
| Development | Pre-commit config, `.dockerignore`, `.gitignore` | Editor and IDE plugins |
| Pull request | `make cloud-check-lint`, `cloud-check-scan` and `cloud-check-test` (`tests/assert-originals-fail.sh`), run by the `cloud-check` and `cloud-check-image` jobs in `.github/workflows/ci.yml`. Signed commits. Both jobs passed on their first GitHub run. The repository's gitleaks job failed on that run, because of a scaffold bug fixed in another branch. | Conftest or `cfn-guard`, CODEOWNERS, branch protection and required status checks |
| Deployment | Two example policy files in `policies/`. Access Analyzer `validate-policy` accepts both (it rejected an invalid action in the first SCP, now fixed). Neither was attached, because the sandbox account is not in an organization. | Everything else in this phase. A permission boundary and a TLS-only bucket policy were tested in the sandbox, as described in the Part 2 README. |
| Runtime | `scripts/find_risky_iam_users.py`, with unit tests and a run on real exports from a sandbox account. Hardened image run with the recommended flags (see README). AWS Config rules and CloudTrail lookups run once in the sandbox. | Config rules as a standing control, GuardDuty, CloudTrail alerts, Falco or EDR |

## Which phase stops which problem

| Problem | Development | Pull request | Deployment | Runtime |
| --- | --- | --- | --- | --- |
| Wildcard admin policy | Hook warning | Policy as code fails the PR | CloudFormation Hook rejects the stack. Permission boundary caps the role. SCP blocks `AdministratorAccess`. | Access Analyzer and Config flag it. The script lists it. |
| IAM user and access keys | Hook warning | Policy as code fails the PR | SCP denies `iam:CreateUser` and `iam:CreateAccessKey` | Credential report, key age and unused-key checks |
| Public or unencrypted bucket | cfn-lint, checkov locally | checkov and `trivy config` fail the PR | Account-level Block Public Access. RCP forces TLS. Hook rejects the stack. | Config rules, Security Hub controls |
| Root container, old base image | hadolint locally | hadolint, `trivy config`, `trivy image` fail the PR | Admission control rejects root and unsigned images | Read-only filesystem, dropped capabilities, runtime sensor |
| Secrets in the image | gitleaks pre-commit, `.dockerignore` | gitleaks on full history | Registry scan on push | Rotate any leaked value, secret manager at run time |

## 1. Development (developer machine)

Local checks give feedback in seconds. A developer can skip them, so each one is repeated in the next phase.

| Primitive | Catches |
| --- | --- |
| `pre-commit` with `gitleaks` | Hardcoded secrets such as the `ENV` values, before they enter history |
| `hadolint` hook | Root user, missing `--no-install-recommends`, shell-form `CMD`, secrets in `ENV` |
| `cfn-lint` hook | Invalid or deprecated CloudFormation |
| `tflint` and `terraform fmt` hooks | The same for Terraform (Part 1) |
| `detect-private-key`, `check-added-large-files` | Keys and stray artifacts |
| `.dockerignore` and `.gitignore` | `.env`, keys and `.git` copied into an image |

## 2. Pull request (review and merge)

Checks here are required, so a failing change cannot merge.

| Primitive | Catches |
| --- | --- |
| Required status checks: cfn-lint, hadolint, `checkov`, `trivy config`, `trivy image`, gitleaks | The same issues, enforced and not skippable |
| Policy as code: Open Policy Agent with Conftest, or AWS CloudFormation Guard (`cfn-guard`) | Custom rules such as "no IAM statement with `Action: *`", "every bucket has a public access block", "image must not run as root" |
| `CODEOWNERS` on `**/iam*`, `cloudformation/`, `Dockerfile*`, `.github/workflows/` plus required reviews | A second person reads every security-sensitive change |
| Signed commits and protected branches | Attribution, and no direct push to the main branch |
| IAM Access Analyzer `validate-policy` and `check-no-new-access` in CI | New access that a change would grant |
| A regression test such as `tests/assert-originals-fail.sh` | A scanner or rule that stops catching a known bad input |

A `cfn-guard` rule for this template would look like this:

```
rule no_wildcard_iam_actions {
  Resources.*[ Type in ["AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::ManagedPolicy"] ]
    .Properties.*.PolicyDocument.Statement[ Effect == "Allow" ] {
      Action != "*"
    }
}
```

It is shown as an example of the primitive. It was not run here, because `cfn-guard` is not installed.

## 3. Deployment (pipeline and cloud gate)

Two things happen here. The pipeline decides who may deploy and what it deploys. Then the cloud accepts or refuses the change, whatever the pipeline did.

### 3a. Pipeline

| Primitive | Catches |
| --- | --- |
| Workflow `permissions: {}` at the top, `contents: read` per job | A compromised step cannot write to the repository |
| OIDC federation: the pipeline assumes an IAM role (`aws-actions/configure-aws-credentials` with `role-to-assume`) or a GCP workload identity pool | No stored long-lived cloud keys, which removes the "IAM user" pattern from CI |
| Separate build and deploy identities, and trust policy conditions on repository, branch and environment (`token.actions.githubusercontent.com:sub`) | A pull request build cannot deploy |
| Protected deployment environments with required reviewers | A human approves production changes |
| Actions pinned to a full commit SHA | Tag hijack of a third-party action |
| Dependabot or Renovate for actions, base images and packages | Stale base images and tools |
| Base images pinned by digest | Silent base image changes |
| Sign images with Sigstore Cosign (keyless, OIDC identity) and attach provenance (SLSA attestation, SBOM from `trivy` or `syft`) | Images that did not come from the pipeline |
| Private registry with immutable tags and scanning on push (ECR, Artifact Registry) | Tag overwrite and unscanned images |

### 3b. Cloud gate (policies)

These controls live in the cloud. They apply to every caller, including a person with admin rights in a member account.

| Primitive | What it refuses | Limit |
| --- | --- | --- |
| AWS Organizations Service Control Policy. Example: `policies/scp-deny-iam-users-and-admin.json` | `iam:CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `PutUserPolicy` and `AttachUserPolicy` outside a break-glass role. Attaching `AdministratorAccess`. Weakening S3 Block Public Access. | An SCP cannot read inside a policy document, so it cannot ban `Action: *` in a new policy. It does not apply to the management account. |
| AWS Resource Control Policy. Example: `policies/rcp-s3-tls-only.json` | S3 requests over plain HTTP, whatever the bucket policy says | Supported services are limited. Check the AWS list before relying on one. |
| IAM permission boundaries on roles that teams can create | A role that grants more than the boundary allows, including a wildcard admin role | Must be required on every role-creation path, with a condition on `iam:CreateRole` and `iam:PutRolePermissionsBoundary`. |
| S3 account-level Block Public Access (`aws s3control put-public-access-block`) | Public buckets regardless of bucket settings | S3 only. |
| CloudFormation Hooks (a Guard or Lambda hook) | A stack with `Action: *`, an IAM user, or a bucket without a public access block, before it is created. This is the only control in this table that reads template content. | Covers CloudFormation deploys only. |
| AWS Organizations declarative policies | Settings enforced by the service itself. They began with EC2, VPC and EBS. Check the AWS list for S3 support. | Small set of services and attributes. |
| GCP Organization Policy constraints, for example `iam.disableServiceAccountKeyCreation` and `storage.publicAccessPrevention` | The GCP equivalent of the same classes of mistake | GCP only. |
| Admission control in the cluster: Kyverno, OPA Gatekeeper or the Sigstore policy-controller. Pod Security Admission at the `restricted` level. | Unsigned images, root users, privileged pods, `latest` tags, pods without dropped capabilities or seccomp | Applies to Kubernetes only. |
| Separate accounts or projects for dev, staging and production, with their own roles | A mistake in one environment does not reach another | Needs the account structure to exist first. |

The two policy files in `policies/` are examples of the primitive. Access Analyzer `validate-policy` accepts both. They were not attached to an organisation. Test any SCP on a single sandbox account before attaching it higher, because a wrong deny can lock out administrators. Validate it first: that check found an action name that does not exist in the first version of the SCP.

## 4. Runtime (after deploy)

Something still gets through: a drifted setting, an old key, a new CVE in a pinned base. Runtime controls limit the damage and find what the earlier phases missed.

### Hardening of the running workload

Run containers with a read-only root filesystem, all capabilities dropped, `no-new-privileges` and the default seccomp profile. Add an AppArmor or SELinux profile where the host supports it. In Kubernetes, enforce this through the `securityContext` and Pod Security Admission. `README.md` shows the flags and a manifest. They were tested with Docker only.

### Drift and exposure detection

| Primitive | Purpose |
| --- | --- |
| AWS Config rules and conformance packs, with auto-remediation through SSM Automation. For the IAM user in this task use `IAM_NO_INLINE_POLICY_CHECK` and `IAM_USER_NO_POLICIES_CHECK`: the admin-access rules cover customer-managed policies only. | Drift from the baseline after deploy |
| Security Hub CSPM (AWS Foundational Security Best Practices, CIS) | Aggregated findings across accounts |
| IAM Access Analyzer: external access and unused access findings on a schedule | Exposure, and stale users and permissions |
| `scripts/find_risky_iam_users.py` on the credential report and account authorization details | Wildcard admin, admin attachments, console users without MFA, old and unused keys, ranked by severity. It reads exports offline. |
| Scheduled image rescans (`trivy image`) and rebuilds on a new base digest | New CVEs in images that are already deployed |

### Detection and response

| Primitive | Purpose |
| --- | --- |
| CloudTrail organisation trail in a dedicated log archive account, with log file validation and S3 Object Lock | Immutable audit record |
| GCP Cloud Audit Logs with a locked log bucket sink | Same on GCP |
| EventBridge rules or CloudWatch metric filters on `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`, `DeleteTrail`, `StopLogging` | Alert on privilege changes within minutes |
| GuardDuty (credential and anomaly findings) | Compromise detection |
| A runtime sensor such as Falco rules (shell in a container, write below `/etc`, unexpected outbound connection) or an EDR agent on the nodes | Attacks inside a running container or host |
| Runbook: disable the key (`aws iam update-access-key --status Inactive`), attach a deny-all policy, review CloudTrail, rotate | A tested response when a key leaks |

This repository does not implement runtime detection or response.
