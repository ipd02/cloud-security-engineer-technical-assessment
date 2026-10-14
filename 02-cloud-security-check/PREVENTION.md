# Preventing these problems

The two files share five root problems:

1. A user that can do anything (`Action: *` on `Resource: *`).
2. A user with long-lived keys instead of a role.
3. A bucket with no protection built in.
4. A container that runs as root on an old base image.
5. Secrets stored inside the image.

The controls follow the life of a change in four phases: development, pull request, deployment and runtime. There are two kinds of control. A **check** looks at a change and reports a problem. A **policy** makes the problem impossible, or refuses the change, and nobody can skip it. Checks are cheaper and give earlier feedback. Policies are stronger. Use both.

## What this repository contains

| Phase | In this repository |
| --- | --- |
| Development | A pre-commit configuration, `.dockerignore` and `.gitignore` |
| Pull request | The `cloud-check` and `cloud-check-image` CI jobs, which run the scanners on every pull request. The test script `tests/assert-originals-fail.sh`. Signed commits. |
| Deployment | Two example AWS policies in `policies/`, checked with IAM Access Analyzer |
| Runtime | The finder script `scripts/find_risky_iam_users.py`, and the run flags for the hardened container |

The other controls in this document are recommendations.

## Which phase stops which problem

| Problem | Development | Pull request | Deployment | Runtime |
| --- | --- | --- | --- | --- |
| User that can do anything | A hook warns | A policy-as-code check fails the pull request | A CloudFormation Hook rejects the stack. A permission boundary caps the role. A service control policy blocks `AdministratorAccess`. | Access Analyzer and AWS Config report it. The finder script lists it. |
| User with long-lived keys | A hook warns | A policy-as-code check fails the pull request | A service control policy denies creating users and keys | The credential report shows old and unused keys |
| Bucket with no protection | `cfn-lint` and `checkov` locally | `checkov` and `trivy config` fail the pull request | Account-level Block Public Access. A policy that forces HTTPS. A CloudFormation Hook. | AWS Config rules and Security Hub controls |
| Root container on an old image | `hadolint` locally | `hadolint`, `trivy config` and `trivy image` fail the pull request | Cluster admission control refuses root and unsigned images | Read-only filesystem, no extra capabilities, a runtime sensor |
| Secrets in the image | `gitleaks` before commit, `.dockerignore` | `gitleaks` on the full history | The registry scans on push | Change any leaked value. Use a secret manager. |

## 1. Development (the developer's machine)

These checks give an answer in seconds. A developer can skip them, so the pull request repeats every one.

| Control | What it stops |
| --- | --- |
| `pre-commit` with `gitleaks` | Passwords and keys, such as the `ENV` values, before they enter the history |
| `hadolint` hook | Root user, shell-form `CMD`, missing `--no-install-recommends` |
| `cfn-lint` hook | Invalid CloudFormation |
| `tflint` and `terraform fmt` hooks | The same for Terraform (Part 1) |
| `detect-private-key` and `check-added-large-files` | Private keys and stray files |
| `.dockerignore` and `.gitignore` | `.env` files, keys and `.git` ending up in an image |

## 2. Pull request (review and merge)

These checks are required, so a failing change cannot be merged.

| Control | What it stops |
| --- | --- |
| Required checks: `cfn-lint`, `hadolint`, `checkov`, `trivy config`, `trivy image`, `gitleaks` | The same problems as in development, enforced |
| Policy as code, with Open Policy Agent (Conftest) or AWS CloudFormation Guard | Your own rules, such as "no IAM statement with `Action: *`", "every bucket has a public access block", "no container runs as root" |
| `CODEOWNERS` on IAM files, templates, Dockerfiles and workflows, with required reviews | A second person reads every security-sensitive change |
| Signed commits and protected branches | Unknown authors and direct pushes to the main branch |
| IAM Access Analyzer `validate-policy` and `check-no-new-access` in CI | A change that gives new access |
| A test like `tests/assert-originals-fail.sh` | A scanner that quietly stops catching a known bad file |

## 3. Deployment (pipeline and cloud)

Two things happen here. The pipeline decides who may deploy and what. Then the cloud accepts or refuses the change, whatever the pipeline did.

### 3a. The pipeline

| Control | What it stops |
| --- | --- |
| Workflow `permissions: {}` at the top and `contents: read` per job | A compromised step writing to the repository |
| OIDC sign-in: the pipeline assumes an IAM role (`role-to-assume`) or a GCP workload identity pool | Stored cloud keys, so the "user with keys" pattern disappears from CI |
| Separate build and deploy identities, with trust conditions on repository, branch and environment | A pull request build that can deploy |
| Protected environments with required reviewers | An unreviewed change to production |
| Actions pinned to a full commit SHA | A tampered third-party action |
| Dependabot or Renovate for actions, base images and packages | Old base images and tools |
| Base images pinned by digest | A base image that changes without notice |
| Signed images (Sigstore Cosign) with an SBOM and build provenance | Images that did not come from the pipeline |
| A private registry with immutable tags and scanning on push | Overwritten tags and unscanned images |

### 3b. The cloud (policies)

These controls live in the cloud and apply to everyone, including an administrator of a member account.

| Control | What it refuses | Good to know |
| --- | --- | --- |
| AWS service control policy (SCP). Example: `policies/scp-deny-iam-users-and-admin.json` | Creating IAM users and access keys, attaching `AdministratorAccess`, and weakening S3 Block Public Access, except for a break-glass role | An SCP cannot read inside a policy, so it cannot ban `Action: *` in a new policy. It does not apply to the management account of an organization. |
| AWS resource control policy (RCP). Example: `policies/rcp-s3-tls-only.json` | S3 requests that do not use HTTPS, whatever the bucket policy says | It covers a short list of AWS services, including S3. |
| Permission boundaries on roles that teams create | A role that can do more than the boundary allows, even with `AdministratorAccess` attached | Require the boundary whenever a role is created, with a condition on `iam:CreateRole`. |
| S3 account-level Block Public Access (`aws s3control put-public-access-block`) | Public buckets, whatever the bucket settings say | S3 only. |
| CloudFormation Hooks (a Guard or Lambda hook) | A stack with `Action: *`, an IAM user, or a bucket with no public access block, before it is created. It is the only control in this table that reads the template. | CloudFormation deployments only. |
| GCP Organization Policy, for example `iam.disableServiceAccountKeyCreation` and `storage.publicAccessPrevention` | The same kinds of mistake on GCP | GCP only. |
| Admission control in the cluster (Kyverno, OPA Gatekeeper, Sigstore policy-controller) and Pod Security Admission at the `restricted` level | Unsigned images, root users, privileged pods, `latest` tags | Kubernetes only. |
| Separate accounts or projects for development, staging and production | A mistake in one environment reaching another | |

Try any SCP on one test account before attaching it higher up, because a wrong deny can lock out administrators. Check it with `aws accessanalyzer validate-policy --policy-type SERVICE_CONTROL_POLICY` first. That check found an action that does not exist in the first version of the example SCP.

## 4. Runtime (after deployment)

Some problems still get through: a setting that drifts, an old key, a new vulnerability in a pinned base image. Runtime controls limit the damage and find what the earlier phases missed.

### The running workload

Run containers with a read-only filesystem, no extra capabilities, `no-new-privileges` and the default seccomp profile. Add an AppArmor or SELinux profile where the host supports it. In Kubernetes, set the same options in the `securityContext` and enforce them with Pod Security Admission. The README (issue 2 of the Dockerfile section) shows the Docker flags and the Kubernetes settings.

### Finding drift and exposure

| Control | What it does |
| --- | --- |
| AWS Config rules and conformance packs, with automatic fixes through SSM Automation. For the user in this task, use `IAM_NO_INLINE_POLICY_CHECK` and `IAM_USER_NO_POLICIES_CHECK`. The admin-access rules look at customer-managed policies only. | Reports settings that drift from the baseline |
| Security Hub (AWS Foundational Security Best Practices and CIS) | Collects findings from many accounts |
| IAM Access Analyzer on a schedule | Reports outside access and unused users, roles and permissions |
| `scripts/find_risky_iam_users.py` on the credential report and account authorization details | Lists users and roles that can do anything, console users without MFA, old or unused keys and root account keys, worst first. It reads policies as written. |
| Scheduled `trivy image` scans, and rebuilds on a new base digest | New vulnerabilities in images that are already running |

### Detection and response

| Control | What it does |
| --- | --- |
| A CloudTrail organization trail in a separate log account, with log file validation and S3 Object Lock | A record of events that nobody can change |
| GCP Cloud Audit Logs with a locked log bucket | The same on GCP |
| EventBridge rules or CloudWatch metric filters on `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`, `DeleteTrail` and `StopLogging` | Alerts within minutes when privileges change |
| GuardDuty | Alerts on stolen credentials and unusual behavior |
| A runtime sensor such as Falco, or an EDR agent on the nodes | Alerts on a shell in a container, writes below `/etc` and unexpected connections |
| A runbook: set the key inactive (`aws iam update-access-key --status Inactive`), attach a deny-all policy, review CloudTrail, replace the key | A set of steps ready for when a key leaks |
